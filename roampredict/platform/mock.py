"""Fake Wi-Fi adapter and IP stack.

:class:`MockWlanAdapter` implements the same interface as the Windows adapter
on top of any object that follows the small :class:`MockRadio` protocol.  Two
radios exist:

* ``simulator.strategies.SimDriver`` - the full simulated building, including
  Windows' own "sticky" roaming, used by ``roampredict simulate``.
* :class:`ScriptedRadio` (below) - a tiny deterministic radio for unit tests.

Time is virtual: :meth:`MockWlanAdapter.sleep` advances the radio's clock
instead of sleeping, so a two-minute walk simulates in milliseconds.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Protocol

from roampredict.platform.base import (
    BssEntry,
    CommandResult,
    ConnectResult,
    InterfaceInfo,
    L3Snapshot,
    LinkStatus,
    NetworkOps,
    PingResult,
    RoamCapabilities,
    WlanAdapter,
    WlanEvent,
    WlanEventKind,
    freq_to_channel,
)
from roampredict.validate import normalize_bssid, validate_profile_name

__all__ = [
    "MockRadio",
    "MockWlanAdapter",
    "MockNetworkOps",
    "ScriptedAp",
    "ScriptedRadio",
    "DEFAULT_L3",
]

MOCK_GUID = "{00000000-0000-4000-8000-00000000A11C}"

DEFAULT_L3 = L3Snapshot(
    if_index=7,
    friendly_name="Wi-Fi",
    ipv4="10.20.30.40",
    prefix_len=22,
    gateway="10.20.28.1",
    dhcp_server="10.20.0.10",
)


class MockRadio(Protocol):
    def now(self) -> float: ...

    def advance(self, seconds: float) -> None: ...

    def link(self) -> LinkStatus: ...

    def cached_bss(self) -> list[BssEntry]: ...

    def start_scan(self, ssid: str | None) -> None: ...

    def wait_scan(self, timeout_s: float) -> bool: ...

    def connect(self, profile: str, ssid: str, bssid: str, timeout_s: float, auth_stall_s: float) -> ConnectResult: ...

    def connect_any(self, profile: str) -> None: ...

    def profiles(self) -> list[str]: ...

    def drain_events(self) -> list[WlanEvent]: ...


class MockWlanAdapter(WlanAdapter):
    def __init__(self, radio: MockRadio, interface: InterfaceInfo | None = None) -> None:
        self.radio = radio
        self._interface = interface or InterfaceInfo(guid=MOCK_GUID, description="Simulated Wi-Fi adapter", state="connected")
        self.connect_calls: list[tuple[str, str]] = []
        self.profile_connects: list[str] = []
        self.scan_requests = 0
        self.closed = False

    def now(self) -> float:
        return self.radio.now()

    def sleep(self, seconds: float) -> None:
        if seconds > 0:
            self.radio.advance(seconds)

    def interface(self) -> InterfaceInfo:
        return self._interface

    def link_status(self) -> LinkStatus:
        return self.radio.link()

    def bss_list(self) -> list[BssEntry]:
        return self.radio.cached_bss()

    def request_scan(self, ssid: str | None = None) -> None:
        self.scan_requests += 1
        self.radio.start_scan(ssid)

    def wait_for_scan(self, timeout_s: float) -> bool:
        return self.radio.wait_scan(timeout_s)

    def connect_bssid(
        self,
        profile: str,
        ssid: str,
        bssid: str,
        *,
        timeout_s: float,
        auth_stall_s: float,
    ) -> ConnectResult:
        profile = validate_profile_name(profile)
        bssid = normalize_bssid(bssid)
        self.connect_calls.append((profile, bssid))
        return self.radio.connect(profile, ssid, bssid, timeout_s, auth_stall_s)

    def connect_profile(self, profile: str) -> None:
        profile = validate_profile_name(profile)
        self.profile_connects.append(profile)
        self.radio.connect_any(profile)

    def profile_names(self) -> list[str]:
        return self.radio.profiles()

    def poll_events(self) -> list[WlanEvent]:
        return self.radio.drain_events()

    def close(self) -> None:
        self.closed = True


class MockNetworkOps(NetworkOps):
    """Scriptable IP stack.

    ``snapshots`` are returned in order (the last one repeats); after
    :meth:`renew_dhcp`, ``after_renew`` is returned instead.  ``ping_ok`` can be
    a bool, a list of bools consumed in order (last repeats) or a callable.
    """

    def __init__(
        self,
        *,
        admin: bool = True,
        snapshots: Sequence[L3Snapshot] | None = None,
        after_renew: L3Snapshot | None = None,
        ping_ok: bool | Sequence[bool] | Callable[[], bool] = True,
        rtt_ms: float = 3.0,
    ) -> None:
        self.admin = admin
        self._snapshots = list(snapshots) if snapshots else [DEFAULT_L3]
        self._after_renew = after_renew
        self._renewed = False
        self._ping_ok = ping_ok
        self._ping_index = 0
        self._snap_index = 0
        self.rtt_ms = rtt_ms
        self.calls: list[str] = []

    def snapshot(self, interface_guid: str) -> L3Snapshot:
        self.calls.append("snapshot")
        if self._renewed and self._after_renew is not None:
            return self._after_renew
        snap = self._snapshots[min(self._snap_index, len(self._snapshots) - 1)]
        self._snap_index += 1
        return snap

    def ping(self, host: str, timeout_ms: int) -> PingResult:
        self.calls.append(f"ping {host}")
        if callable(self._ping_ok):
            ok = bool(self._ping_ok())
        elif isinstance(self._ping_ok, bool):
            ok = self._ping_ok
        else:
            seq = list(self._ping_ok)
            ok = seq[min(self._ping_index, len(seq) - 1)]
            self._ping_index += 1
        return PingResult(ok=ok, rtt_ms=self.rtt_ms if ok else None, error=None if ok else "timed out")

    def flush_arp(self, snapshot: L3Snapshot) -> CommandResult:
        self.calls.append("flush_arp")
        if not self.admin:
            return CommandResult(ok=False, skipped=True, duration_ms=0.0, detail="needs admin")
        return CommandResult(ok=True, skipped=False, duration_ms=5.0, detail="flushed")

    def renew_dhcp(self, snapshot: L3Snapshot) -> CommandResult:
        self.calls.append("renew_dhcp")
        if not self.admin:
            return CommandResult(ok=False, skipped=True, duration_ms=0.0, detail="needs admin")
        self._renewed = True
        return CommandResult(ok=True, skipped=False, duration_ms=420.0, detail="renewed")

    def is_admin(self) -> bool:
        return self.admin


@dataclass
class ScriptedAp:
    bssid: str
    rssi: float | Callable[[float], float]
    ssid: str = "testnet"
    freq_mhz: int = 5180
    capabilities: RoamCapabilities = field(default_factory=RoamCapabilities)

    def rssi_at(self, t: float) -> float:
        return float(self.rssi(t)) if callable(self.rssi) else float(self.rssi)


class ScriptedRadio:
    """Deterministic radio for unit tests.

    ``connect_mode``:
      ``"ok"``          connects to the requested BSSID
      ``"other_bssid"`` connects, but to the strongest *other* AP (driver's choice)
      ``"fail"``        association fails (non-security reason code)
      ``"auth_fail"``   802.1X fails (reason code in the 802.1X range)
      ``"stall"``       stuck in "authenticating" (like a pending login prompt)
    """

    AUTH_FAIL_REASON = 0x50005  # ONEX_EAP_FAILURE_RECEIVED
    ASSOC_FAIL_REASON = 0x38001  # a generic MSM (association) failure

    def __init__(
        self,
        aps: Sequence[ScriptedAp],
        *,
        connected_to: str | None,
        profile: str = "testnet",
        ssid: str = "testnet",
        scan_duration_s: float = 1.0,
        scan_completes: bool = True,
        connect_mode: str = "ok",
        connect_duration_s: float = 0.3,
        auth_ms: float = 100.0,
        autoconnect_after_s: float | None = None,
        start_time: float = 0.0,
        initial_cache_age_s: float = 0.5,
    ) -> None:
        if connect_mode not in ("ok", "other_bssid", "fail", "auth_fail", "stall"):
            raise ValueError(f"unknown connect_mode {connect_mode!r}")
        self.t = start_time
        self.aps = {normalize_bssid(a.bssid): a for a in aps}
        self.current = normalize_bssid(connected_to) if connected_to else None
        self.profile = profile
        self.ssid = ssid
        self.scan_duration_s = scan_duration_s
        self.scan_completes = scan_completes
        self.connect_mode = connect_mode
        self.connect_duration_s = connect_duration_s
        self.auth_ms = auth_ms
        self.autoconnect_after_s = autoconnect_after_s
        self.hidden: set[str] = set()
        self._events: list[WlanEvent] = []
        self._scan_done_at: float | None = None
        self._disconnected_at: float | None = None if self.current else start_time
        self._cache: dict[str, tuple[float, float]] = {
            b: (ap.rssi_at(start_time), start_time - initial_cache_age_s) for b, ap in self.aps.items()
        }

    # -- clock ---------------------------------------------------------------------

    def now(self) -> float:
        return self.t

    def _next_timed(self) -> tuple[float, str] | None:
        pending = []
        if self._scan_done_at is not None:
            pending.append((self._scan_done_at, "scan"))
        if self.current is None and self.autoconnect_after_s is not None and self._disconnected_at is not None:
            pending.append((self._disconnected_at + self.autoconnect_after_s, "autoconnect"))
        return min(pending) if pending else None

    def advance(self, seconds: float) -> None:
        end = self.t + max(0.0, seconds)
        while True:
            nxt = self._next_timed()
            if nxt is None or nxt[0] > end:
                break
            self.t = max(self.t, nxt[0])
            if nxt[1] == "scan":
                self._complete_scan()
            else:
                self._associate(self._strongest(), "autoconnect")
        self.t = end

    # -- queries -------------------------------------------------------------------

    def link(self) -> LinkStatus:
        if self.current is None:
            return LinkStatus(connected=False)
        ap = self.aps[self.current]
        rssi = ap.rssi_at(self.t)
        channel, _ = freq_to_channel(ap.freq_mhz)
        return LinkStatus(
            connected=True,
            ssid=ap.ssid,
            bssid=self.current,
            profile_name=self.profile,
            rssi_dbm=rssi,
            signal_quality=int(max(0, min(100, 2 * (rssi + 100)))),
            channel=channel,
            auth="WPA2-Enterprise",
            onex=True,
        )

    def cached_bss(self) -> list[BssEntry]:
        out = []
        for bssid, (rssi, heard_at) in self._cache.items():
            ap = self.aps[bssid]
            if bssid == self.current and bssid not in self.hidden:
                rssi, heard_at = ap.rssi_at(self.t), self.t
            channel, band = freq_to_channel(ap.freq_mhz)
            out.append(
                BssEntry(
                    bssid=bssid,
                    ssid=ap.ssid,
                    rssi_dbm=rssi,
                    freq_mhz=ap.freq_mhz,
                    channel=channel,
                    band=band,
                    age_s=max(0.0, self.t - heard_at),
                    capabilities=ap.capabilities,
                )
            )
        return out

    def profiles(self) -> list[str]:
        return [self.profile]

    def drain_events(self) -> list[WlanEvent]:
        events, self._events = self._events, []
        return events

    # -- scans -----------------------------------------------------------------------

    def start_scan(self, ssid: str | None) -> None:
        if self.scan_completes and self._scan_done_at is None:
            self._scan_done_at = self.t + self.scan_duration_s

    def wait_scan(self, timeout_s: float) -> bool:
        if self._scan_done_at is None or self._scan_done_at - self.t > timeout_s:
            self.advance(timeout_s)
            return False
        self.advance(self._scan_done_at - self.t)
        return True

    def _complete_scan(self) -> None:
        for bssid, ap in self.aps.items():
            if bssid not in self.hidden:
                self._cache[bssid] = (ap.rssi_at(self.t), self.t)
        self._scan_done_at = None
        self._emit(WlanEventKind.SCAN_COMPLETE)

    # -- connections ---------------------------------------------------------------------

    def _emit(self, kind: WlanEventKind, bssid: str | None = None, reason_code: int | None = None) -> None:
        self._events.append(WlanEvent(t=self.t, kind=kind, bssid=bssid, profile=self.profile, reason_code=reason_code))

    def _strongest(self, exclude: str | None = None) -> str:
        choices = [b for b in self.aps if b != exclude and b not in self.hidden]
        return max(choices, key=lambda b: self.aps[b].rssi_at(self.t))

    def _associate(self, bssid: str, how: str) -> None:
        self._emit(WlanEventKind.ASSOCIATING, bssid)
        self._emit(WlanEventKind.ASSOCIATED, bssid)
        self._emit(WlanEventKind.CONNECTED, bssid)
        self._emit(WlanEventKind.CONNECTION_COMPLETE, bssid, 0)
        self.current = bssid
        self._disconnected_at = None

    def connect(self, profile: str, ssid: str, bssid: str, timeout_s: float, auth_stall_s: float) -> ConnectResult:
        t0 = self.t
        old = self.current
        if old is not None:
            self._emit(WlanEventKind.DISCONNECTING, old)
            self._emit(WlanEventKind.DISCONNECTED, old)
            self.current = None
            self._disconnected_at = t0
        self._emit(WlanEventKind.CONNECTION_START)
        mode = self.connect_mode
        if mode in ("ok", "other_bssid"):
            target = bssid if mode == "ok" else self._strongest(exclude=bssid)
            self._emit(WlanEventKind.ASSOCIATING, target)
            assoc_s = max(0.0, self.connect_duration_s - self.auth_ms / 1000.0)
            self.advance(assoc_s)
            self._emit(WlanEventKind.ASSOCIATED, target)
            self._emit(WlanEventKind.AUTHENTICATING, target)
            self.advance(self.auth_ms / 1000.0)
            self._emit(WlanEventKind.CONNECTED, target)
            self._emit(WlanEventKind.CONNECTION_COMPLETE, target, 0)
            self.current = target
            self._disconnected_at = None
            return ConnectResult(
                requested_bssid=bssid,
                connected=True,
                final_bssid=target,
                total_ms=(self.t - t0) * 1000.0,
                assoc_ms=assoc_s * 1000.0,
                auth_ms=self.auth_ms,
                disconnect_seen=old is not None,
            )
        if mode == "stall":
            self._emit(WlanEventKind.ASSOCIATING, bssid)
            self._emit(WlanEventKind.ASSOCIATED, bssid)
            self._emit(WlanEventKind.AUTHENTICATING, bssid)
            self.advance(auth_stall_s)
            return ConnectResult(
                requested_bssid=bssid,
                connected=False,
                final_bssid=None,
                total_ms=(self.t - t0) * 1000.0,
                disconnect_seen=old is not None,
                auth_stalled=True,
                failure_reason=f"802.1X did not finish within {auth_stall_s:.0f} s",
            )
        code = self.AUTH_FAIL_REASON if mode == "auth_fail" else self.ASSOC_FAIL_REASON
        self.advance(self.connect_duration_s)
        self._emit(WlanEventKind.CONNECTION_FAILED, bssid, code)
        return ConnectResult(
            requested_bssid=bssid,
            connected=False,
            final_bssid=None,
            total_ms=(self.t - t0) * 1000.0,
            disconnect_seen=old is not None,
            failure_reason="simulated 802.1X failure" if mode == "auth_fail" else "simulated association failure",
            reason_code=code,
        )

    def connect_any(self, profile: str) -> None:
        self.advance(self.connect_duration_s)
        self._associate(self._strongest(), "profile")
