"""Safety gate: dry-run, allow-list, kill switch, rate limit, failure breaker.

Every real switch has to pass :meth:`SafetyGate.check_roam`.  The defaults are
conservative: dry-run is on, and active mode refuses to act unless the current
SSID is explicitly allow-listed.

The kill switch is a file (``%LOCALAPPDATA%\\RoamPredict\\KILL`` by default).
``roampredict kill`` creates it, and a running RoamPredict sees it on the next
tick (four times a second) and stops acting.  It also trips itself after
``max_consecutive_failures`` failed switches or a suspected login prompt.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path

from roampredict.platform.base import LinkStatus
from roampredict.validate import normalize_bssid, validate_profile_name, validate_ssid

__all__ = ["SafetyConfig", "KillSwitch", "RoamRateLimiter", "GateDecision", "SafetyGate"]


@dataclass(frozen=True)
class SafetyConfig:
    dry_run: bool = True
    allowed_ssids: tuple[str, ...] = ()
    allowed_profiles: tuple[str, ...] = ()  # empty = any profile Windows uses for an allowed SSID
    deny_bssids: tuple[str, ...] = ()
    min_roam_interval_s: float = 20.0
    max_roams_per_window: int = 6
    rate_window_s: float = 600.0
    max_consecutive_failures: int = 2

    def __post_init__(self) -> None:
        object.__setattr__(self, "allowed_ssids", tuple(validate_ssid(s) for s in self.allowed_ssids))
        object.__setattr__(
            self, "allowed_profiles", tuple(validate_profile_name(p) for p in self.allowed_profiles)
        )
        object.__setattr__(self, "deny_bssids", tuple(normalize_bssid(b) for b in self.deny_bssids))
        if self.min_roam_interval_s < 0 or self.rate_window_s <= 0:
            raise ValueError("min_roam_interval_s must be >= 0 and rate_window_s > 0")
        if self.max_roams_per_window < 1 or self.max_consecutive_failures < 1:
            raise ValueError("max_roams_per_window and max_consecutive_failures must be >= 1")


class KillSwitch:
    """File-based kill switch.  With ``path=None`` it only lives in memory."""

    def __init__(self, path: Path | None) -> None:
        self.path = path
        self._memory_reason: str | None = None

    def active(self) -> bool:
        if self._memory_reason is not None:
            return True
        return self.path is not None and self.path.exists()

    def reason(self) -> str | None:
        if self._memory_reason is not None:
            return self._memory_reason
        if self.path is not None and self.path.exists():
            try:
                return self.path.read_text(encoding="utf-8", errors="replace").strip() or "kill file present"
            except OSError:
                return "kill file present"
        return None

    def trip(self, reason: str) -> None:
        self._memory_reason = reason
        if self.path is not None:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                stamp = time.strftime("%Y-%m-%d %H:%M:%S")
                self.path.write_text(f"{stamp} {reason}\n", encoding="utf-8")
            except OSError:
                pass  # the in-memory flag still stops this process

    def clear(self) -> None:
        self._memory_reason = None
        if self.path is not None:
            try:
                self.path.unlink()
            except FileNotFoundError:
                pass


class RoamRateLimiter:
    def __init__(self, min_interval_s: float, max_per_window: int, window_s: float) -> None:
        self.min_interval_s = min_interval_s
        self.max_per_window = max_per_window
        self.window_s = window_s
        self._times: deque[float] = deque()

    def check(self, now: float) -> tuple[bool, str]:
        while self._times and now - self._times[0] > self.window_s:
            self._times.popleft()
        if self._times and now - self._times[-1] < self.min_interval_s:
            wait = self.min_interval_s - (now - self._times[-1])
            return False, f"rate limit: last switch {now - self._times[-1]:.0f} s ago (wait {wait:.0f} s)"
        if len(self._times) >= self.max_per_window:
            return False, f"rate limit: {len(self._times)} switches in the last {self.window_s:.0f} s"
        return True, "ok"

    def record(self, now: float) -> None:
        self._times.append(now)


@dataclass(frozen=True)
class GateDecision:
    allowed: bool
    reason: str


class SafetyGate:
    def __init__(
        self,
        config: SafetyConfig,
        kill_switch: KillSwitch,
        rate_limiter: RoamRateLimiter | None = None,
    ) -> None:
        self.config = config
        self.kill_switch = kill_switch
        self.rate_limiter = rate_limiter or RoamRateLimiter(
            config.min_roam_interval_s, config.max_roams_per_window, config.rate_window_s
        )
        self.consecutive_failures = 0
        self.deny = frozenset(config.deny_bssids)

    def link_allowed(self, link: LinkStatus) -> GateDecision:
        cfg = self.config
        if not link.connected or not link.ssid or not link.profile_name:
            return GateDecision(False, "not connected through a saved profile")
        if not cfg.allowed_ssids:
            return GateDecision(False, "no SSIDs are allow-listed (set safety.allowed_ssids)")
        if link.ssid not in cfg.allowed_ssids:
            return GateDecision(False, f"SSID {link.ssid!r} is not allow-listed")
        if cfg.allowed_profiles and link.profile_name not in cfg.allowed_profiles:
            return GateDecision(False, f"profile {link.profile_name!r} is not allow-listed")
        return GateDecision(True, "ok")

    def check_roam(self, link: LinkStatus, now: float) -> GateDecision:
        if self.config.dry_run:
            return GateDecision(False, "dry-run")
        if self.kill_switch.active():
            return GateDecision(False, f"kill switch active ({self.kill_switch.reason()})")
        decision = self.link_allowed(link)
        if not decision.allowed:
            return decision
        ok, why = self.rate_limiter.check(now)
        return GateDecision(ok, why)

    def record_attempt(self, now: float) -> None:
        self.rate_limiter.record(now)

    def record_result(self, success: bool, reason: str, *, login_prompt_suspected: bool = False) -> None:
        if login_prompt_suspected:
            self.kill_switch.trip(f"stopped: 802.1X did not complete, a login prompt may be waiting ({reason})")
            return
        if success:
            self.consecutive_failures = 0
            return
        self.consecutive_failures += 1
        if self.consecutive_failures >= self.config.max_consecutive_failures:
            self.kill_switch.trip(f"stopped after {self.consecutive_failures} failed switches (last: {reason})")
