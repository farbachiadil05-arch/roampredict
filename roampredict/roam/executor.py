"""Safe switch: verify -> connect -> check -> fix the IP layer -> measure.

Nothing is disconnected unless a better AP was verified first:

1. Refresh the BSS list: re-read Windows' list, and if the candidate was not
   heard within ``fresh_scan_max_age_s``, ask Windows for a scan and wait for it
   (Windows requires drivers to finish a scan within 4 s).
2. Verify the candidate: present in the refreshed list, heard recently, the
   link did not change meanwhile, and at least ``min_gain_db`` stronger than the
   current AP.  The current level is the HIGHER of the smoothed estimate and a
   fresh reading, so a momentary dip can never make a candidate look better.
3. ``WlanConnect`` with the saved profile NAME and the candidate as the only
   desired BSSID.  This is a request: the driver may still choose differently,
   and Windows most likely drops the old link first (the connect result records
   whether it did).
4. If the connection failed:
   * 802.1X stalled or failed (a login prompt may be waiting): stop, report and
     leave everything to Windows.  The engine then trips the kill switch.
   * any other failure: give Windows ``fallback_wait_s`` to reconnect on its own,
     then ask for a plain profile connection (no BSSID restriction) - we are
     already disconnected at that point, so this cannot drop anything.
5. Check which BSSID we actually ended up on.
6. IP layer: same subnet and gateway -> flush the ARP cache (needs admin);
   changed -> renew DHCP (needs admin) and time it; then ping the gateway.
7. Reset RoamPredict's own sockets (other programs are not touched).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from roampredict.platform.base import (
    BssEntry,
    CommandResult,
    ConnectResult,
    L3Snapshot,
    LinkStatus,
    NetworkOps,
    PingResult,
    WlanAdapter,
    WlanError,
)
from roampredict.telemetry import Telemetry
from roampredict.topology.predictor import ScoreBreakdown
from roampredict.topology.store import SwitchRecord

__all__ = ["ExecutorConfig", "Verification", "RoamOutcome", "RoamExecutor", "is_auth_reason"]

# Windows reason codes 0x40000-0x4FFFF are security (MSMSEC) failures and
# 0x50000-0x5FFFF are 802.1X (OneX) failures.  Either means "authentication
# trouble", which is where a login prompt would come from.
_AUTH_REASON_MIN = 0x40000
_AUTH_REASON_MAX = 0x5FFFF


def is_auth_reason(code: int | None) -> bool:
    return code is not None and _AUTH_REASON_MIN <= code <= _AUTH_REASON_MAX


@dataclass(frozen=True)
class ExecutorConfig:
    min_gain_db: float = 8.0
    fresh_scan_max_age_s: float = 3.0
    scan_timeout_s: float = 4.5
    connect_timeout_s: float = 12.0
    auth_stall_s: float = 6.0
    fallback_wait_s: float = 5.0
    l3_wait_s: float = 4.0
    ping_timeout_ms: int = 500
    poll_interval_s: float = 0.2
    arp_flush: bool = True
    dhcp_renew: bool = True

    def __post_init__(self) -> None:
        for name in (
            "fresh_scan_max_age_s",
            "scan_timeout_s",
            "connect_timeout_s",
            "auth_stall_s",
            "fallback_wait_s",
            "l3_wait_s",
            "poll_interval_s",
        ):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be > 0")
        if self.min_gain_db < 0 or self.ping_timeout_ms <= 0:
            raise ValueError("min_gain_db must be >= 0 and ping_timeout_ms > 0")
        if self.auth_stall_s >= self.connect_timeout_s:
            raise ValueError("auth_stall_s must be shorter than connect_timeout_s")


@dataclass(frozen=True)
class Verification:
    ok: bool
    reason: str
    candidate: BssEntry | None = None
    current_rssi_dbm: float | None = None
    gain_db: float | None = None
    scanned: bool = False  # a new scan was requested for this check
    scan_ms: float = 0.0
    entries: tuple[BssEntry, ...] = ()  # the refreshed BSS list

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "reason": self.reason,
            "candidate_dbm": None if self.candidate is None else round(self.candidate.rssi_dbm, 1),
            "candidate_age_s": None if self.candidate is None or self.candidate.age_s is None else round(self.candidate.age_s, 1),
            "current_dbm": None if self.current_rssi_dbm is None else round(self.current_rssi_dbm, 1),
            "gain_db": None if self.gain_db is None else round(self.gain_db, 1),
            "scanned": self.scanned,
            "scan_ms": round(self.scan_ms),
        }


@dataclass
class RoamOutcome:
    success: bool
    stage: str  # where it ended: "connect", "bssid", "l3" or "done"
    reason: str
    requested_bssid: str
    from_bssid: str | None
    candidate_class: str
    final_bssid: str | None = None
    connect: ConnectResult | None = None
    verification: Verification | None = None
    l3_before: L3Snapshot | None = None
    l3_after: L3Snapshot | None = None
    gateway_changed: bool | None = None
    gateway_rtt_ms: float | None = None
    l3_ms: float | None = None
    arp: CommandResult | None = None
    dhcp: CommandResult | None = None
    fallback: str = "none"
    login_prompt_suspected: bool = False
    sockets_reset: int = 0
    extra: dict[str, Any] = field(default_factory=dict)

    def detail(self) -> dict[str, Any]:
        c = self.connect
        return {
            "stage": self.stage,
            "fallback": self.fallback,
            "login_prompt_suspected": self.login_prompt_suspected,
            "disconnect_seen": None if c is None else c.disconnect_seen,
            "auth_stalled": None if c is None else c.auth_stalled,
            "reason_code": None if c is None else c.reason_code,
            "events": [] if c is None else [list(e) for e in c.events],
            "arp": None if self.arp is None else {"ok": self.arp.ok, "skipped": self.arp.skipped, "detail": self.arp.detail},
            "dhcp": None
            if self.dhcp is None
            else {"ok": self.dhcp.ok, "skipped": self.dhcp.skipped, "ms": round(self.dhcp.duration_ms), "detail": self.dhcp.detail},
            "gateway_rtt_ms": self.gateway_rtt_ms,
            "verify": None if self.verification is None else self.verification.as_dict(),
            "sockets_reset": self.sockets_reset,
            **self.extra,
        }

    def to_switch_record(self, at: float) -> SwitchRecord:
        c = self.connect
        dhcp_ms = None if self.dhcp is None or self.dhcp.skipped else self.dhcp.duration_ms
        return SwitchRecord(
            at=at,
            initiator="roampredict",
            success=self.success,
            from_bssid=self.from_bssid,
            to_bssid=self.final_bssid,
            requested_bssid=self.requested_bssid,
            candidate_class=self.candidate_class,
            honored=None if c is None else c.honored,
            total_ms=None if c is None else c.total_ms,
            assoc_ms=None if c is None else c.assoc_ms,
            auth_ms=None if c is None else c.auth_ms,
            l3_ms=self.l3_ms,
            dhcp_ms=dhcp_ms,
            gateway_changed=self.gateway_changed,
            reason=self.reason,
            detail=self.detail(),
        )


class RoamExecutor:
    def __init__(
        self,
        adapter: WlanAdapter,
        net: NetworkOps,
        config: ExecutorConfig,
        telemetry: Telemetry,
        *,
        reset_sockets: Callable[[], int] | None = None,
    ) -> None:
        self.adapter = adapter
        self.net = net
        self.config = config
        self.telemetry = telemetry
        self.reset_sockets = reset_sockets
        self._last_scan_done: float | None = None
        self._gateway_pingable: bool | None = None  # learned before the first switch
        self._guid = adapter.interface().guid

    def note_scan_complete(self, t: float) -> None:
        if self._last_scan_done is None or t > self._last_scan_done:
            self._last_scan_done = t

    # -- step 1 + 2 -------------------------------------------------------------------

    def _fresh(self, entry: BssEntry | None) -> bool:
        """Heard within ``fresh_scan_max_age_s`` (or, if Windows gives no age, a
        scan completed within that time)."""
        if entry is None:
            return False
        max_age = self.config.fresh_scan_max_age_s
        if entry.age_s is not None:
            return entry.age_s <= max_age
        return self._last_scan_done is not None and self.adapter.now() - self._last_scan_done <= max_age

    def scan_and_wait(self, ssid: str | None) -> bool:
        try:
            self.adapter.request_scan(ssid)
        except WlanError as exc:
            self.telemetry.emit("warning", f"scan request refused: {exc}")
            return False
        if self.adapter.wait_for_scan(self.config.scan_timeout_s):
            self.note_scan_complete(self.adapter.now())
            return True
        return False

    def verify(self, *, link: LinkStatus, bssid: str, current_estimate_dbm: float) -> Verification:
        """Refresh the BSS list and check the candidate against fresh data.

        "Refresh" means re-reading Windows' BSS list; if the candidate was not
        heard within ``fresh_scan_max_age_s``, a new scan is requested and
        awaited first.
        """
        cfg = self.config
        start = self.adapter.now()

        def find(items: list[BssEntry]) -> BssEntry | None:
            return next((e for e in items if e.bssid == bssid and e.ssid == link.ssid), None)

        entries = self.adapter.bss_list()
        cand = find(entries)
        scanned = False
        if not self._fresh(cand):
            scanned = self.scan_and_wait(link.ssid)
            entries = self.adapter.bss_list()
            cand = find(entries)
        scan_ms = (self.adapter.now() - start) * 1000.0
        common = {"scanned": scanned, "scan_ms": scan_ms, "entries": tuple(entries)}
        if cand is None:
            return Verification(False, "candidate not visible in the refreshed BSS list", **common)
        if not self._fresh(cand):
            age = "unknown" if cand.age_s is None else f"{cand.age_s:.1f} s"
            return Verification(False, f"no fresh data for the candidate (last heard: {age})", cand, **common)
        now_link = self.adapter.link_status()
        if not now_link.connected or now_link.bssid != link.bssid:
            return Verification(False, "link changed while verifying (Windows roamed or disconnected)", cand, **common)
        current = current_estimate_dbm
        if now_link.rssi_dbm is not None:
            current = max(current, now_link.rssi_dbm)
        gain = cand.rssi_dbm - current
        if gain < cfg.min_gain_db:
            return Verification(
                False, f"candidate only {gain:+.1f} dB vs current (needs +{cfg.min_gain_db:.0f})", cand, current, gain, **common
            )
        return Verification(True, "verified", cand, current, gain, **common)

    # -- steps 3-7 ---------------------------------------------------------------------

    def switch(self, *, link: LinkStatus, candidate: ScoreBreakdown, verification: Verification) -> RoamOutcome:
        cfg = self.config
        if not (link.profile_name and link.ssid and link.bssid):
            raise ValueError("switch() needs a connected link with SSID, BSSID and profile name")
        target = candidate.bssid
        out = RoamOutcome(
            success=False,
            stage="connect",
            reason="",
            requested_bssid=target,
            from_bssid=link.bssid,
            candidate_class=candidate.candidate_class,
            verification=verification,
        )
        out.l3_before = self._snapshot()
        if self._gateway_pingable is None and out.l3_before is not None and out.l3_before.gateway:
            # Learn once, while the old link still works, whether ping can be used
            # to check the gateway after a switch.
            self._gateway_pingable = self.net.ping(out.l3_before.gateway, cfg.ping_timeout_ms).ok
        result = self.adapter.connect_bssid(
            link.profile_name,
            link.ssid,
            target,
            timeout_s=cfg.connect_timeout_s,
            auth_stall_s=cfg.auth_stall_s,
        )
        out.connect = result

        if not result.connected:
            if result.auth_stalled or is_auth_reason(result.reason_code):
                out.login_prompt_suspected = True
                out.fallback = "left_to_windows"
                out.reason = (
                    f"802.1X did not complete ({result.failure_reason or 'no reason given'}); "
                    "stopped and left it to Windows - a login prompt may appear"
                )
                return out
            out.reason = f"connection failed: {result.failure_reason or 'unknown reason'}"
            if self._wait_connected(cfg.fallback_wait_s):
                out.fallback = "windows_autoconnect"
            else:
                try:
                    self.adapter.connect_profile(link.profile_name)
                    out.fallback = "plain_profile_connect"
                except WlanError as exc:
                    out.fallback = f"plain_profile_connect_failed ({exc})"
            now_link = self.adapter.link_status()
            out.final_bssid = now_link.bssid if now_link.connected else None
            return out

        out.final_bssid = result.final_bssid
        if result.final_bssid != target:
            out.stage = "bssid"
            out.reason = f"Windows/driver connected to {result.final_bssid} instead of {target}"
            self._check_l3(out)
            return out

        post = self.adapter.link_status()
        if post.connected and post.rssi_dbm is not None:
            # Compare what the scan promised with what we got (old scan data can mislead).
            out.extra["post_rssi_dbm"] = post.rssi_dbm
            if verification.candidate is not None:
                out.extra["expected_rssi_dbm"] = verification.candidate.rssi_dbm
        out.stage = "l3"
        l3_ok = self._check_l3(out)
        if self.reset_sockets is not None:
            try:
                out.sockets_reset = self.reset_sockets()
            except Exception as exc:  # noqa: BLE001 - must never break the switch
                self.telemetry.emit("warning", f"socket reset failed: {exc}")
        if not l3_ok:
            out.reason = out.reason or "no reply from the gateway after the switch"
            return out
        out.stage = "done"
        out.success = True
        out.reason = "switched"
        return out

    # -- helpers -------------------------------------------------------------------------

    def _snapshot(self) -> L3Snapshot | None:
        try:
            return self.net.snapshot(self._guid)
        except Exception as exc:  # noqa: BLE001 - IP info is best effort
            self.telemetry.emit("warning", f"could not read IP configuration: {exc}")
            return None

    def _wait_connected(self, timeout_s: float) -> bool:
        deadline = self.adapter.now() + timeout_s
        while True:
            if self.adapter.link_status().connected:
                return True
            if self.adapter.now() >= deadline:
                return False
            self.adapter.sleep(self.config.poll_interval_s)

    def _wait_usable_snapshot(self, budget_s: float) -> L3Snapshot | None:
        deadline = self.adapter.now() + budget_s
        snap = self._snapshot()
        while (snap is None or not snap.usable) and self.adapter.now() < deadline:
            self.adapter.sleep(self.config.poll_interval_s)
            snap = self._snapshot()
        return snap

    def _ping_until(self, host: str, budget_s: float) -> PingResult:
        deadline = self.adapter.now() + budget_s
        while True:
            result = self.net.ping(host, self.config.ping_timeout_ms)
            if result.ok or self.adapter.now() >= deadline:
                return result
            self.adapter.sleep(self.config.poll_interval_s)

    def _check_l3(self, out: RoamOutcome) -> bool:
        cfg = self.config
        t0 = self.adapter.now()
        before = out.l3_before
        after = self._wait_usable_snapshot(cfg.l3_wait_s)
        out.l3_after = after
        if after is not None and after.usable and before is not None and before.usable:
            out.gateway_changed = not before.same_network(after)

        if after is not None and after.usable and out.gateway_changed is False:
            if cfg.arp_flush:
                out.arp = self.net.flush_arp(after)
        elif after is not None and cfg.dhcp_renew and (not after.usable or out.gateway_changed):
            # Subnet/gateway changed, or still no usable address.  (If the old
            # state is unknown we do neither; the gateway ping below decides.)
            out.dhcp = self.net.renew_dhcp(after)
            after = self._snapshot() or after
            out.l3_after = after
            if before is not None and before.usable and after.usable:
                out.gateway_changed = not before.same_network(after)

        gateway = after.gateway if after is not None and after.gateway else None
        if gateway is None:
            out.reason = "no gateway after the switch"
            out.l3_ms = (self.adapter.now() - t0) * 1000.0
            return False
        if self._gateway_pingable is False:
            # The gateway ignored ping before the switch too (many campuses block
            # ICMP), so a missing reply proves nothing: check the address instead.
            out.extra["gateway_check"] = "skipped: the gateway does not answer ping on this network"
            out.l3_ms = (self.adapter.now() - t0) * 1000.0
            if after is None or not after.usable:
                out.reason = "no usable IP address after the switch"
                return False
            return True
        ping = self._ping_until(gateway, cfg.l3_wait_s)
        if not ping.ok and out.dhcp is None and cfg.dhcp_renew and after is not None:
            out.dhcp = self.net.renew_dhcp(after)
            refreshed = self._snapshot()
            if refreshed is not None and refreshed.gateway:
                out.l3_after = refreshed
                gateway = refreshed.gateway
            ping = self._ping_until(gateway, cfg.l3_wait_s)
        out.gateway_rtt_ms = ping.rtt_ms
        out.l3_ms = (self.adapter.now() - t0) * 1000.0
        if not ping.ok:
            out.reason = f"no reply from gateway {gateway}: {ping.error or 'timeout'}"
        return ping.ok
