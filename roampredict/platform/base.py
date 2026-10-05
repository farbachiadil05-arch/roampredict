"""Platform abstraction: what the engine needs from Wi-Fi and from the IP stack.

Two implementations exist:

* ``windows_wlan.WindowsWlanAdapter`` / ``net.l3.WindowsNetworkOps`` - the real
  thing (wlanapi.dll and iphlpapi.dll through ctypes).
* ``mock.MockWlanAdapter`` / ``mock.MockNetworkOps`` - driven by the simulator
  or by scripted test radios.

All times returned by :meth:`WlanAdapter.now` are monotonic seconds (virtual in
the simulator); wall-clock times are only used for the SQLite store.
"""

from __future__ import annotations

import abc
import ipaddress
from dataclasses import dataclass, field
from enum import Enum

__all__ = [
    "Band",
    "freq_to_channel",
    "RoamCapabilities",
    "InterfaceInfo",
    "LinkStatus",
    "BssEntry",
    "WlanEventKind",
    "WlanEvent",
    "ConnectResult",
    "WlanError",
    "WlanPermissionError",
    "WlanUnavailableError",
    "WlanAdapter",
    "L3Snapshot",
    "PingResult",
    "CommandResult",
    "NetworkOps",
]


class Band(str, Enum):
    GHZ_2_4 = "2.4GHz"
    GHZ_5 = "5GHz"
    GHZ_6 = "6GHz"
    UNKNOWN = "unknown"


def freq_to_channel(freq_mhz: int | None) -> tuple[int | None, Band]:
    """Map a centre frequency (MHz) to ``(channel, band)``."""
    if freq_mhz is None:
        return None, Band.UNKNOWN
    f = int(freq_mhz)
    if f == 2484:
        return 14, Band.GHZ_2_4
    if 2412 <= f <= 2472 and (f - 2407) % 5 == 0:
        return (f - 2407) // 5, Band.GHZ_2_4
    if f == 5935:
        return 2, Band.GHZ_6
    if 5925 <= f <= 7125 and (f - 5950) % 5 == 0:
        return (f - 5950) // 5, Band.GHZ_6
    if 5150 <= f < 5925 and (f - 5000) % 5 == 0:
        return (f - 5000) // 5, Band.GHZ_5
    return None, Band.UNKNOWN


@dataclass(frozen=True)
class RoamCapabilities:
    """Fast-roaming features an AP *advertises* (parsed from its beacon IEs).

    ``None`` means "unknown" (no IE data, or a malformed element).  Whether
    Windows actually uses a feature is decided inside Windows and the driver.
    """

    ft: bool | None = None  # 802.11r: FT AKM in RSN and/or Mobility Domain element
    ft_over_ds: bool | None = None
    mobility_domain: str | None = None  # MDID as 4 hex digits
    rrm_neighbor_report: bool | None = None  # 802.11k
    bss_transition: bool | None = None  # 802.11v BSS Transition Management
    rsn_preauth: bool | None = None  # 802.11i RSN pre-authentication
    akm_suites: tuple[int, ...] = ()
    enterprise: bool | None = None  # an 802.1X AKM is offered
    mfp_capable: bool | None = None
    mfp_required: bool | None = None
    bss_load_stations: int | None = None
    bss_load_utilization: float | None = None  # 0..1

    def flags(self) -> str:
        def mark(value: bool | None) -> str:
            return "?" if value is None else ("yes" if value else "no")

        return (
            f"11r={mark(self.ft)} 11k={mark(self.rrm_neighbor_report)} "
            f"11v={mark(self.bss_transition)} preauth={mark(self.rsn_preauth)}"
        )


@dataclass(frozen=True)
class InterfaceInfo:
    guid: str  # "{XXXXXXXX-XXXX-...}"
    description: str
    state: str


@dataclass(frozen=True)
class LinkStatus:
    connected: bool
    ssid: str | None = None
    bssid: str | None = None
    profile_name: str | None = None
    rssi_dbm: float | None = None
    signal_quality: int | None = None  # 0..100 as reported by Windows
    rssi_source: str = "rssi"  # "rssi" (driver dBm) or "quality" (estimated from %)
    channel: int | None = None
    auth: str | None = None
    cipher: str | None = None
    onex: bool | None = None  # 802.1X in use
    rx_rate_mbps: float | None = None
    tx_rate_mbps: float | None = None


@dataclass(frozen=True)
class BssEntry:
    bssid: str
    ssid: str
    rssi_dbm: float
    freq_mhz: int | None = None
    channel: int | None = None
    band: Band = Band.UNKNOWN
    link_quality: int | None = None
    age_s: float | None = None  # seconds since the AP was last heard (None = unknown)
    capabilities: RoamCapabilities = field(default_factory=RoamCapabilities)


class WlanEventKind(str, Enum):
    SCAN_COMPLETE = "scan_complete"
    SCAN_FAILED = "scan_failed"
    CONNECTION_START = "connection_start"
    CONNECTION_COMPLETE = "connection_complete"
    CONNECTION_FAILED = "connection_failed"
    DISCONNECTING = "disconnecting"
    DISCONNECTED = "disconnected"
    ASSOCIATING = "associating"
    ASSOCIATED = "associated"
    AUTHENTICATING = "authenticating"
    CONNECTED = "connected"
    ROAMING_START = "roaming_start"
    ROAMING_END = "roaming_end"
    SIGNAL_CHANGE = "signal_change"
    RADIO_STATE = "radio_state"
    ONEX_ACTIVITY = "onex_activity"  # 802.1X notification (payload deliberately NOT parsed)
    OTHER = "other"


@dataclass(frozen=True)
class WlanEvent:
    t: float  # monotonic seconds
    kind: WlanEventKind
    bssid: str | None = None
    profile: str | None = None
    reason_code: int | None = None
    detail: str | None = None


@dataclass(frozen=True)
class ConnectResult:
    requested_bssid: str
    connected: bool  # connected to *something* when the wait ended
    final_bssid: str | None
    total_ms: float
    assoc_ms: float | None = None  # associating -> associated
    auth_ms: float | None = None  # authenticating -> connected (802.1X/4-way handshake)
    disconnect_seen: bool = False  # Windows dropped the old link first
    auth_stalled: bool = False  # stuck in 802.1X: a login prompt may be waiting
    failure_reason: str | None = None
    reason_code: int | None = None
    events: tuple[tuple[float, str], ...] = ()  # (ms since request, event name)

    @property
    def honored(self) -> bool:
        return self.connected and self.final_bssid == self.requested_bssid


class WlanError(RuntimeError):
    def __init__(self, message: str, code: int | None = None) -> None:
        super().__init__(message)
        self.code = code


class WlanPermissionError(WlanError):
    """Windows refused access (e.g. Location permission missing on Windows 11 24H2+)."""


class WlanUnavailableError(WlanError):
    """No usable Wi-Fi API/adapter (not Windows, service stopped, no adapter...)."""


class WlanAdapter(abc.ABC):
    """Everything RoamPredict needs from the Wi-Fi stack."""

    @abc.abstractmethod
    def now(self) -> float:
        """Monotonic seconds."""

    @abc.abstractmethod
    def sleep(self, seconds: float) -> None: ...

    @abc.abstractmethod
    def interface(self) -> InterfaceInfo: ...

    @abc.abstractmethod
    def link_status(self) -> LinkStatus: ...

    @abc.abstractmethod
    def bss_list(self) -> list[BssEntry]:
        """The BSS list Windows already has (cheap, no radio time)."""

    @abc.abstractmethod
    def request_scan(self, ssid: str | None = None) -> None:
        """Ask for a new scan (all channels; Windows has no per-channel scan)."""

    @abc.abstractmethod
    def wait_for_scan(self, timeout_s: float) -> bool:
        """Block until the requested scan completes; False on timeout/failure."""

    @abc.abstractmethod
    def connect_bssid(
        self,
        profile: str,
        ssid: str,
        bssid: str,
        *,
        timeout_s: float,
        auth_stall_s: float,
    ) -> ConnectResult:
        """Ask Windows to connect with ``profile`` preferring ``bssid``. A request, not an order."""

    @abc.abstractmethod
    def connect_profile(self, profile: str) -> None:
        """Plain connect with the profile, letting Windows pick the AP (fallback)."""

    @abc.abstractmethod
    def profile_names(self) -> list[str]: ...

    @abc.abstractmethod
    def poll_events(self) -> list[WlanEvent]:
        """Notifications received since the last call."""

    def reason_text(self, code: int | None) -> str:
        """Readable text for a WLAN reason code (Windows overrides this with its own wording)."""
        return "no reason given" if code is None else f"reason 0x{code:x}"

    def close(self) -> None:  # noqa: B027 - optional hook
        """Release OS resources."""

    def __enter__(self) -> WlanAdapter:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


@dataclass(frozen=True)
class L3Snapshot:
    if_index: int | None
    friendly_name: str | None
    ipv4: str | None
    prefix_len: int | None
    gateway: str | None
    dhcp_server: str | None = None

    @property
    def subnet(self) -> ipaddress.IPv4Network | None:
        if not self.ipv4 or self.prefix_len is None:
            return None
        try:
            return ipaddress.IPv4Network(f"{self.ipv4}/{self.prefix_len}", strict=False)
        except ValueError:
            return None

    @property
    def usable(self) -> bool:
        """Has a real (non link-local) address and a gateway."""
        if not self.ipv4 or not self.gateway:
            return False
        try:
            return not ipaddress.IPv4Address(self.ipv4).is_link_local
        except ValueError:
            return False

    def same_network(self, other: L3Snapshot | None) -> bool:
        return (
            other is not None
            and self.usable
            and other.usable
            and self.gateway == other.gateway
            and self.subnet == other.subnet
        )


@dataclass(frozen=True)
class PingResult:
    ok: bool
    rtt_ms: float | None
    error: str | None = None


@dataclass(frozen=True)
class CommandResult:
    ok: bool
    skipped: bool
    duration_ms: float
    detail: str


class NetworkOps(abc.ABC):
    """IP-level helpers used after a switch."""

    @abc.abstractmethod
    def snapshot(self, interface_guid: str) -> L3Snapshot: ...

    @abc.abstractmethod
    def ping(self, host: str, timeout_ms: int) -> PingResult: ...

    @abc.abstractmethod
    def flush_arp(self, snapshot: L3Snapshot) -> CommandResult: ...

    @abc.abstractmethod
    def renew_dhcp(self, snapshot: L3Snapshot) -> CommandResult: ...

    @abc.abstractmethod
    def is_admin(self) -> bool: ...
