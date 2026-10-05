"""Windows Native Wifi adapter (wlanapi.dll through ctypes).

API calls used (all documented, all available since Windows Vista):

* ``WlanOpenHandle`` / ``WlanCloseHandle``
* ``WlanEnumInterfaces``                  - find the Wi-Fi adapter
* ``WlanQueryInterface``                  - current connection (SSID, BSSID,
  profile name, security) and ``wlan_intf_opcode_rssi`` (dBm)
* ``WlanGetNetworkBssList``               - nearby BSSIDs with RSSI, frequency
  and raw information elements (for 802.11r/k/v detection)
* ``WlanScan``                            - ask for a scan (always all channels)
* ``WlanConnect``                         - connect with a saved profile NAME and
  a desired BSSID.  A request: the driver may still pick another AP.
* ``WlanRegisterNotification``            - scan/connect/roam events
* ``WlanGetProfileList``                  - profile NAMES only
* ``WlanReasonCodeToString``              - human text for failure codes

Never used, on purpose: ``WlanGetProfile`` (profile XML), the plaintext-key
flag, ``WlanDisconnect``, and the payload of 802.1X (OneX) notifications, which
can contain the user name.

Notes that matter on real hardware:

* Windows 11 24H2 and newer require Location permission for BSSID/scan data;
  without it these calls fail with "access denied" (``WlanPermissionError``).
* ``wlan_intf_opcode_rssi`` is optional for drivers.  If it fails, RSSI is
  estimated from Windows' signal quality: dBm = quality / 2 - 100.
* The notification callback runs on a Windows thread pool thread.  It only
  copies data into a queue and never calls back into wlanapi.
"""

from __future__ import annotations

import ctypes
import sys
import threading
import time
from collections import deque
from ctypes import POINTER, byref, sizeof

from roampredict.platform import win32_structs as w
from roampredict.platform.base import (
    BssEntry,
    ConnectResult,
    InterfaceInfo,
    LinkStatus,
    WlanAdapter,
    WlanError,
    WlanEvent,
    WlanEventKind,
    WlanPermissionError,
    WlanUnavailableError,
    freq_to_channel,
)
from roampredict.platform.info_elements import parse_capabilities
from roampredict.validate import (
    ValidationError,
    bssid_from_bytes,
    bssid_to_bytes,
    normalize_bssid,
    ssid_from_bytes,
    validate_profile_name,
)

__all__ = ["WindowsWlanAdapter", "parse_bss_list", "decode_notification", "list_interfaces", "LOCATION_HINT", "PROTOTYPES"]

LOCATION_HINT = (
    "Windows refused access to Wi-Fi scan/BSSID data. On Windows 11 24H2 and newer this needs Location: "
    "Settings > Privacy & security > Location > turn on 'Location services' and "
    "'Let desktop apps access your location'."
)

_ACM_KINDS = {
    w.ACM_CONNECTION_START: WlanEventKind.CONNECTION_START,
    w.ACM_CONNECTION_COMPLETE: WlanEventKind.CONNECTION_COMPLETE,
    w.ACM_CONNECTION_ATTEMPT_FAIL: WlanEventKind.CONNECTION_FAILED,
    w.ACM_DISCONNECTING: WlanEventKind.DISCONNECTING,
    w.ACM_DISCONNECTED: WlanEventKind.DISCONNECTED,
}
_MSM_KINDS = {
    w.MSM_ASSOCIATING: WlanEventKind.ASSOCIATING,
    w.MSM_ASSOCIATED: WlanEventKind.ASSOCIATED,
    w.MSM_AUTHENTICATING: WlanEventKind.AUTHENTICATING,
    w.MSM_CONNECTED: WlanEventKind.CONNECTED,
    w.MSM_ROAMING_START: WlanEventKind.ROAMING_START,
    w.MSM_ROAMING_END: WlanEventKind.ROAMING_END,
    w.MSM_DISCONNECTED: WlanEventKind.DISCONNECTED,
}


# -- pure helpers (tested on any OS with synthetic buffers) ------------------------------------


def parse_bss_list(address: int, now_filetime: int | None = None) -> list[BssEntry]:
    """Parse a ``WLAN_BSS_LIST`` in memory.  Entries or IE blobs that point
    outside the list's declared size are skipped, not read."""
    header = w.WLAN_BSS_LIST.from_address(address)
    total = int(header.dwTotalSize)
    first = address + w.WLAN_BSS_LIST.wlanBssEntries.offset
    entry_size = sizeof(w.WLAN_BSS_ENTRY)
    room = max(0, (total - w.WLAN_BSS_LIST.wlanBssEntries.offset) // entry_size)
    count = min(int(header.dwNumberOfItems), room)
    out: list[BssEntry] = []
    for i in range(count):
        addr = first + i * entry_size
        e = w.WLAN_BSS_ENTRY.from_address(addr)
        try:
            bssid = bssid_from_bytes(bytes(e.dot11Bssid))
        except ValidationError:
            continue
        ies = b""
        size = int(e.ulIeSize)
        if size and addr + int(e.ulIeOffset) + size <= address + total:
            ies = ctypes.string_at(addr + int(e.ulIeOffset), size)
        freq = int(e.ulChCenterFrequency) // 1000 if e.ulChCenterFrequency else None
        channel, band = freq_to_channel(freq)
        age = None
        if now_filetime and e.ullHostTimestamp:
            delta = (now_filetime - int(e.ullHostTimestamp)) / 1e7
            if -5.0 <= delta <= 86400.0:  # only trust plausible timestamps
                age = max(0.0, delta)
        out.append(
            BssEntry(
                bssid=bssid,
                ssid=ssid_from_bytes(w.dot11_ssid_bytes(e.dot11Ssid)),
                rssi_dbm=float(e.lRssi),
                freq_mhz=freq,
                channel=channel,
                band=band,
                link_quality=int(e.uLinkQuality),
                age_s=age,
                capabilities=parse_capabilities(ies),
            )
        )
    return out


def _bssid_or_none(raw: bytes) -> str | None:
    try:
        return bssid_from_bytes(raw)
    except ValidationError:
        return None


def decode_notification(data: w.WLAN_NOTIFICATION_DATA, t: float) -> WlanEvent | None:
    """Copy what we need out of a notification (its memory is freed after the
    callback returns).  802.1X (OneX) payloads are never read."""
    src = int(data.NotificationSource)
    code = int(data.NotificationCode)
    size = int(data.dwDataSize)
    ptr = data.pData
    if src == w.WLAN_NOTIFICATION_SOURCE_ACM:
        if code == w.ACM_SCAN_COMPLETE:
            return WlanEvent(t, WlanEventKind.SCAN_COMPLETE)
        if code == w.ACM_SCAN_FAIL:
            reason = w.DWORD.from_address(ptr).value if ptr and size >= 4 else None
            return WlanEvent(t, WlanEventKind.SCAN_FAILED, reason_code=reason)
        kind = _ACM_KINDS.get(code)
        if kind is None:
            return None
        profile = reason = None
        if ptr and size >= sizeof(w.WLAN_CONNECTION_NOTIFICATION_DATA):
            info = w.WLAN_CONNECTION_NOTIFICATION_DATA.from_address(ptr)
            profile = w.wchars_to_str(info.strProfileName) or None
            reason = int(info.wlanReasonCode)
        if kind is WlanEventKind.CONNECTION_COMPLETE and reason:
            kind = WlanEventKind.CONNECTION_FAILED
        return WlanEvent(t, kind, profile=profile, reason_code=reason)
    if src == w.WLAN_NOTIFICATION_SOURCE_MSM:
        if code == w.MSM_SIGNAL_QUALITY_CHANGE:
            quality = w.ULONG.from_address(ptr).value if ptr and size >= 4 else None
            return WlanEvent(t, WlanEventKind.SIGNAL_CHANGE, detail=None if quality is None else str(quality))
        if code == w.MSM_RADIO_STATE_CHANGE:
            return WlanEvent(t, WlanEventKind.RADIO_STATE)
        kind = _MSM_KINDS.get(code)
        if kind is None:
            return WlanEvent(t, WlanEventKind.OTHER, detail=f"msm {code}") if code == w.MSM_DISASSOCIATING else None
        bssid = profile = reason = None
        if ptr and size >= sizeof(w.WLAN_MSM_NOTIFICATION_DATA):
            info = w.WLAN_MSM_NOTIFICATION_DATA.from_address(ptr)
            bssid = _bssid_or_none(bytes(info.dot11MacAddr))
            profile = w.wchars_to_str(info.strProfileName) or None
            reason = int(info.wlanReasonCode)
        return WlanEvent(t, kind, bssid=bssid, profile=profile, reason_code=reason)
    if src == w.WLAN_NOTIFICATION_SOURCE_ONEX:
        return WlanEvent(t, WlanEventKind.ONEX_ACTIVITY)
    return None


# -- the DLL ---------------------------------------------------------------------------------------


# name -> (argtypes, restype).  Shared by the real DLL and the test double.
PROTOTYPES: dict[str, tuple[list, object]] = {  # type: ignore[type-arg]
    "WlanOpenHandle": ([w.DWORD, w.PVOID, POINTER(w.DWORD), POINTER(w.HANDLE)], w.DWORD),
    "WlanCloseHandle": ([w.HANDLE, w.PVOID], w.DWORD),
    "WlanEnumInterfaces": ([w.HANDLE, w.PVOID, POINTER(POINTER(w.WLAN_INTERFACE_INFO_LIST))], w.DWORD),
    "WlanQueryInterface": (
        [w.HANDLE, POINTER(w.GUID), w.DWORD, w.PVOID, POINTER(w.DWORD), POINTER(w.PVOID), POINTER(w.DWORD)],
        w.DWORD,
    ),
    "WlanGetNetworkBssList": (
        [w.HANDLE, POINTER(w.GUID), POINTER(w.DOT11_SSID), w.DWORD, w.BOOL, w.PVOID, POINTER(POINTER(w.WLAN_BSS_LIST))],
        w.DWORD,
    ),
    "WlanScan": ([w.HANDLE, POINTER(w.GUID), POINTER(w.DOT11_SSID), w.PVOID, w.PVOID], w.DWORD),
    "WlanConnect": ([w.HANDLE, POINTER(w.GUID), POINTER(w.WLAN_CONNECTION_PARAMETERS), w.PVOID], w.DWORD),
    "WlanRegisterNotification": (
        [w.HANDLE, w.DWORD, w.BOOL, w.WLAN_NOTIFICATION_CALLBACK, w.PVOID, w.PVOID, POINTER(w.DWORD)],
        w.DWORD,
    ),
    "WlanGetProfileList": ([w.HANDLE, POINTER(w.GUID), w.PVOID, POINTER(POINTER(w.WLAN_PROFILE_INFO_LIST))], w.DWORD),
    "WlanFreeMemory": ([w.PVOID], None),
    "WlanReasonCodeToString": ([w.DWORD, w.DWORD, ctypes.c_wchar_p, w.PVOID], w.DWORD),
}


class _WlanApi:
    """wlanapi.dll with explicit prototypes (wrong argument types fail loudly).

    ``dll`` is only passed by the tests (a stand-in built from the same
    prototypes); normally the real wlanapi.dll is loaded.
    """

    def __init__(self, dll: object | None = None) -> None:
        if dll is None:
            dll = ctypes.WinDLL("wlanapi.dll", use_last_error=True)  # type: ignore[attr-defined]
        for name, (argtypes, restype) in PROTOTYPES.items():
            func = getattr(dll, name)
            func.argtypes = argtypes
            func.restype = restype
            setattr(self, name, func)


def _error_text(code: int) -> str:
    # FormatError takes a C long, but NDIS/WLAN codes such as 0x80342003 are
    # above 0x7FFFFFFF (a campus walk crashed here): pass the same 32 bits signed.
    signed = code - (1 << 32) if code >= (1 << 31) else code
    try:
        return ctypes.FormatError(signed).strip()  # type: ignore[attr-defined]
    except (AttributeError, ValueError, OverflowError):
        return "unknown error"


def _code(rc: int) -> str:
    return f"code {rc}" if rc <= 0xFFFF else f"code 0x{rc:08X}"


def _raise_for(rc: int, what: str) -> None:
    if rc == w.ERROR_SUCCESS:
        return
    if rc == w.ERROR_ACCESS_DENIED:
        raise WlanPermissionError(f"{what}: access denied. {LOCATION_HINT}", rc)
    if rc == w.ERROR_SERVICE_NOT_ACTIVE:
        raise WlanUnavailableError(f"{what}: the WLAN AutoConfig service is not running (Start-Service WlanSvc)", rc)
    if rc == w.ERROR_NDIS_DOT11_POWER_STATE_INVALID:
        raise WlanUnavailableError(f"{what}: the Wi-Fi radio is switched off", rc)
    raise WlanError(f"{what} failed: {_error_text(rc)} ({_code(rc)})", rc)


def _open(api: _WlanApi) -> tuple[w.HANDLE, int]:
    handle = w.HANDLE()
    negotiated = w.DWORD()
    _raise_for(api.WlanOpenHandle(w.WLAN_CLIENT_VERSION_VISTA, None, byref(negotiated), byref(handle)), "WlanOpenHandle")
    return handle, int(negotiated.value)


def _enum(api: _WlanApi, handle: w.HANDLE) -> list[InterfaceInfo]:
    plist = POINTER(w.WLAN_INTERFACE_INFO_LIST)()
    _raise_for(api.WlanEnumInterfaces(handle, None, byref(plist)), "WlanEnumInterfaces")
    try:
        n = int(plist.contents.dwNumberOfItems)
        base = ctypes.addressof(plist.contents) + w.WLAN_INTERFACE_INFO_LIST.InterfaceInfo.offset
        out = []
        for i in range(n):
            info = w.WLAN_INTERFACE_INFO.from_address(base + i * sizeof(w.WLAN_INTERFACE_INFO))
            out.append(
                InterfaceInfo(
                    guid=w.guid_to_str(info.InterfaceGuid),
                    description=w.wchars_to_str(info.strInterfaceDescription),
                    state=w.INTERFACE_STATES.get(int(info.isState), str(int(info.isState))),
                )
            )
        return out
    finally:
        api.WlanFreeMemory(plist)


def list_interfaces(api: _WlanApi | None = None) -> list[InterfaceInfo]:
    """All Wi-Fi interfaces (for ``doctor``)."""
    if api is None:
        if sys.platform != "win32":
            raise WlanUnavailableError("wlanapi.dll only exists on Windows")
        api = _WlanApi()
    handle, _ = _open(api)
    try:
        return _enum(api, handle)
    finally:
        api.WlanCloseHandle(handle, None)


# -- the adapter -----------------------------------------------------------------------------------


class WindowsWlanAdapter(WlanAdapter):
    def __init__(self, interface: str | None = None, *, api: _WlanApi | None = None) -> None:
        if api is None:
            if sys.platform != "win32":
                raise WlanUnavailableError("the Windows Wi-Fi adapter only works on Windows (try: roampredict simulate)")
            try:
                api = _WlanApi()
            except OSError as exc:
                raise WlanUnavailableError(f"cannot load wlanapi.dll: {exc}") from exc
        self._api = api
        self._handle, self.negotiated_version = _open(self._api)
        self._closed = False
        self._registered = False
        self._cond = threading.Condition()
        self._recent: deque[tuple[int, WlanEvent]] = deque(maxlen=1024)
        self._pending: deque[WlanEvent] = deque(maxlen=4096)
        self._seq = 0
        self._scan_done = threading.Event()
        self._scan_ok = False
        self._rssi_supported = True
        self._channel_cache: tuple[str | None, int | None] = (None, None)
        self._callback = w.WLAN_NOTIFICATION_CALLBACK(self._on_notification)  # keep a reference!
        try:
            self._iface = self._pick_interface(interface)
            self._guid = w.guid_from_str(self._iface.guid)
            self._guid_bytes = bytes(self._guid)
            previous = w.DWORD()
            sources = w.WLAN_NOTIFICATION_SOURCE_ACM | w.WLAN_NOTIFICATION_SOURCE_MSM | w.WLAN_NOTIFICATION_SOURCE_ONEX
            _raise_for(
                self._api.WlanRegisterNotification(self._handle, sources, True, self._callback, None, None, byref(previous)),
                "WlanRegisterNotification",
            )
            self._registered = True
        except Exception:
            self.close()
            raise

    # -- basics --------------------------------------------------------------------------

    def now(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        if seconds > 0:
            time.sleep(seconds)

    def interface(self) -> InterfaceInfo:
        return self._iface

    def _pick_interface(self, match: str | None) -> InterfaceInfo:
        interfaces = _enum(self._api, self._handle)
        if not interfaces:
            raise WlanUnavailableError("no Wi-Fi adapter found")
        if match:
            key = match.strip().strip("{}").lower()
            for info in interfaces:
                if info.guid.strip("{}").lower() == key or key in info.description.lower():
                    return info
            raise WlanUnavailableError(f"no Wi-Fi adapter matches {match!r}")
        connected = [i for i in interfaces if i.state == "connected"]
        return (connected or interfaces)[0]

    # -- notifications ----------------------------------------------------------------------

    def _on_notification(self, pdata: object, _context: object) -> None:
        try:
            if not pdata:
                return
            data = pdata.contents  # type: ignore[attr-defined]
            if bytes(data.InterfaceGuid) != self._guid_bytes:
                return
            event = decode_notification(data, time.monotonic())
            if event is None:
                return
            with self._cond:
                self._seq += 1
                self._recent.append((self._seq, event))
                self._pending.append(event)
                self._cond.notify_all()
            if event.kind in (WlanEventKind.SCAN_COMPLETE, WlanEventKind.SCAN_FAILED):
                self._scan_ok = event.kind is WlanEventKind.SCAN_COMPLETE
                self._scan_done.set()
        except Exception:  # noqa: BLE001 - never let an exception reach Windows
            pass

    def poll_events(self) -> list[WlanEvent]:
        with self._cond:
            events = list(self._pending)
            self._pending.clear()
        return events

    # -- queries ---------------------------------------------------------------------------

    def _query(self, opcode: int) -> tuple[int, bytes]:
        size = w.DWORD()
        data = w.PVOID()
        kind = w.DWORD()
        rc = self._api.WlanQueryInterface(self._handle, byref(self._guid), opcode, None, byref(size), byref(data), byref(kind))
        if rc != w.ERROR_SUCCESS:
            return rc, b""
        if not data.value:
            return w.ERROR_NOT_FOUND, b""
        try:
            return rc, ctypes.string_at(data.value, size.value)
        finally:
            self._api.WlanFreeMemory(data)

    def link_status(self) -> LinkStatus:
        rc, raw = self._query(w.wlan_intf_opcode_current_connection)
        if rc == w.ERROR_INVALID_STATE:
            return LinkStatus(connected=False)
        _raise_for(rc, "WlanQueryInterface(current_connection)")
        if len(raw) < sizeof(w.WLAN_CONNECTION_ATTRIBUTES):
            raise WlanError("WlanQueryInterface returned a short connection record")
        attrs = w.WLAN_CONNECTION_ATTRIBUTES.from_buffer_copy(raw)
        if int(attrs.isState) != w.WLAN_INTERFACE_STATE_CONNECTED:
            return LinkStatus(connected=False)
        assoc = attrs.wlanAssociationAttributes
        bssid = _bssid_or_none(bytes(assoc.dot11Bssid))
        if bssid is None:
            raise WlanPermissionError(f"connected, but Windows hid the BSSID. {LOCATION_HINT}")
        quality = int(assoc.wlanSignalQuality)
        rssi = self._query_rssi()
        source = "rssi"
        if rssi is None:
            rssi = quality / 2.0 - 100.0
            source = "quality"
        sec = attrs.wlanSecurityAttributes
        return LinkStatus(
            connected=True,
            ssid=ssid_from_bytes(w.dot11_ssid_bytes(assoc.dot11Ssid)),
            bssid=bssid,
            profile_name=w.wchars_to_str(attrs.strProfileName) or None,
            rssi_dbm=float(rssi),
            signal_quality=quality,
            rssi_source=source,
            channel=self._channel(bssid),
            auth=w.AUTH_ALGORITHMS.get(int(sec.dot11AuthAlgorithm), f"0x{int(sec.dot11AuthAlgorithm):x}"),
            cipher=w.CIPHER_ALGORITHMS.get(int(sec.dot11CipherAlgorithm), f"0x{int(sec.dot11CipherAlgorithm):x}"),
            onex=bool(sec.bOneXEnabled),
            rx_rate_mbps=int(assoc.ulRxRate) / 1000.0,
            tx_rate_mbps=int(assoc.ulTxRate) / 1000.0,
        )

    def _query_rssi(self) -> int | None:
        if not self._rssi_supported:
            return None
        rc, raw = self._query(w.wlan_intf_opcode_rssi)
        if rc in (w.ERROR_NOT_SUPPORTED, w.ERROR_INVALID_PARAMETER):
            self._rssi_supported = False  # this driver does not report dBm
            return None
        if rc != w.ERROR_SUCCESS or len(raw) < 4:
            return None
        value = int.from_bytes(raw[:4], "little", signed=True)
        if not -110 <= value <= -10:
            # Seen on a real Intel AX201 (Windows 10): the opcode "works" but
            # returns e.g. +27.  A real Wi-Fi RSSI is always negative dBm, so
            # stop trusting this driver's value and use signal quality instead.
            self._rssi_supported = False
            return None
        return value

    def _channel(self, bssid: str) -> int | None:
        if self._channel_cache[0] == bssid:
            return self._channel_cache[1]
        rc, raw = self._query(w.wlan_intf_opcode_channel_number)
        channel = int.from_bytes(raw[:4], "little") if rc == w.ERROR_SUCCESS and len(raw) >= 4 else None
        self._channel_cache = (bssid, channel)
        return channel

    def bss_list(self) -> list[BssEntry]:
        plist = POINTER(w.WLAN_BSS_LIST)()
        rc = self._api.WlanGetNetworkBssList(
            self._handle, byref(self._guid), None, w.dot11_BSS_type_any, False, None, byref(plist)
        )
        _raise_for(rc, "WlanGetNetworkBssList")
        try:
            return parse_bss_list(ctypes.addressof(plist.contents), w.filetime_now())
        finally:
            self._api.WlanFreeMemory(plist)

    def profile_names(self) -> list[str]:
        plist = POINTER(w.WLAN_PROFILE_INFO_LIST)()
        _raise_for(self._api.WlanGetProfileList(self._handle, byref(self._guid), None, byref(plist)), "WlanGetProfileList")
        try:
            n = int(plist.contents.dwNumberOfItems)
            base = ctypes.addressof(plist.contents) + w.WLAN_PROFILE_INFO_LIST.ProfileInfo.offset
            return [
                w.wchars_to_str(w.WLAN_PROFILE_INFO.from_address(base + i * sizeof(w.WLAN_PROFILE_INFO)).strProfileName)
                for i in range(n)
            ]
        finally:
            self._api.WlanFreeMemory(plist)

    def reason_text(self, code: int | None) -> str:
        if code is None:
            return "no reason given"
        buf = ctypes.create_unicode_buffer(512)
        if self._api.WlanReasonCodeToString(code, len(buf), buf, None) == w.ERROR_SUCCESS and buf.value:
            return f"{buf.value} (reason 0x{code:x})"
        return f"reason 0x{code:x}"

    # -- scans -----------------------------------------------------------------------------

    def request_scan(self, ssid: str | None = None) -> None:
        self._scan_done.clear()
        self._scan_ok = False
        target = w.make_dot11_ssid(ssid) if ssid else None
        rc = self._api.WlanScan(self._handle, byref(self._guid), byref(target) if target is not None else None, None, None)
        if rc == w.ERROR_BUSY:
            # Windows is already scanning (seen on a real campus): that scan's
            # "complete" notification will wake wait_for_scan() just the same.
            return
        _raise_for(rc, "WlanScan")

    def wait_for_scan(self, timeout_s: float) -> bool:
        return self._scan_done.wait(timeout_s) and self._scan_ok

    # -- connections -----------------------------------------------------------------------

    def _wlan_connect(self, profile: str, bssid: str | None) -> int:
        bssid_list = w.make_bssid_list(bssid_to_bytes(bssid)) if bssid else None
        params = w.WLAN_CONNECTION_PARAMETERS()
        params.wlanConnectionMode = w.wlan_connection_mode_profile
        params.strProfile = profile  # the NAME of a saved profile - credentials stay inside Windows
        params.pDot11Ssid = None  # "use the SSIDs in the profile"
        params.pDesiredBssidList = ctypes.pointer(bssid_list) if bssid_list is not None else None
        params.dot11BssType = w.dot11_BSS_type_infrastructure
        params.dwFlags = 0
        return int(self._api.WlanConnect(self._handle, byref(self._guid), byref(params), None))

    def connect_profile(self, profile: str) -> None:
        _raise_for(self._wlan_connect(validate_profile_name(profile), None), "WlanConnect")

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
        target = normalize_bssid(bssid)
        with self._cond:
            start_seq = self._seq
        t0 = time.monotonic()
        rc = self._wlan_connect(profile, target)
        if rc != w.ERROR_SUCCESS:
            return ConnectResult(
                requested_bssid=target,
                connected=False,
                final_bssid=None,
                total_ms=(time.monotonic() - t0) * 1000.0,
                failure_reason=f"WlanConnect refused the request: {_error_text(rc)} ({_code(rc)})",
            )

        done: WlanEvent | None = None
        stalled = False
        deadline = t0 + timeout_s
        with self._cond:
            while True:
                events = [e for s, e in self._recent if s > start_seq]
                done = next(
                    (
                        e
                        for e in events
                        if e.kind in (WlanEventKind.CONNECTION_COMPLETE, WlanEventKind.CONNECTION_FAILED)
                        and e.profile in (None, profile)
                    ),
                    None,
                )
                if done is not None:
                    break
                now = time.monotonic()
                auth_since = None
                for e in events:
                    if e.kind is WlanEventKind.AUTHENTICATING:
                        auth_since = e.t
                    elif e.kind is WlanEventKind.CONNECTED:
                        auth_since = None
                if auth_since is not None and now - auth_since > auth_stall_s:
                    stalled = True
                    break
                if now >= deadline:
                    break
                self._cond.wait(timeout=min(0.1, deadline - now))
            events = [e for s, e in self._recent if s > start_seq]

        end_t = done.t if done is not None else time.monotonic()
        assoc_ms = _phase_ms(events, WlanEventKind.ASSOCIATING, WlanEventKind.ASSOCIATED)
        auth_ms = _phase_ms(events, WlanEventKind.AUTHENTICATING, WlanEventKind.CONNECTED)
        link = self.link_status() if not stalled else LinkStatus(connected=False)
        connected = link.connected and not (done is not None and done.kind is WlanEventKind.CONNECTION_FAILED)
        reason = None
        code = None
        if stalled:
            reason = f"802.1X did not finish within {auth_stall_s:.0f} s (a login prompt may be waiting)"
        elif done is not None and done.kind is WlanEventKind.CONNECTION_FAILED:
            code = done.reason_code
            reason = self.reason_text(code)
        elif done is None:
            reason = f"no result from Windows within {timeout_s:.0f} s"
        return ConnectResult(
            requested_bssid=target,
            connected=connected,
            final_bssid=link.bssid if connected else None,
            total_ms=(end_t - t0) * 1000.0,
            assoc_ms=assoc_ms,
            auth_ms=auth_ms,
            disconnect_seen=any(e.kind in (WlanEventKind.DISCONNECTING, WlanEventKind.DISCONNECTED) for e in events),
            auth_stalled=stalled,
            failure_reason=reason,
            reason_code=code,
            events=tuple((round((e.t - t0) * 1000.0, 1), e.kind.value) for e in events),
        )

    # -- shutdown ----------------------------------------------------------------------------

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            if self._registered:
                # A NULL callback of the right type: ctypes refuses a bare None here.
                self._api.WlanRegisterNotification(
                    self._handle, w.WLAN_NOTIFICATION_SOURCE_NONE, True, w.WLAN_NOTIFICATION_CALLBACK(), None, None, None
                )
        finally:
            self._api.WlanCloseHandle(self._handle, None)


def _phase_ms(events: list[WlanEvent], start: WlanEventKind, end: WlanEventKind) -> float | None:
    """Duration of the last start -> end pair (e.g. authenticating -> connected)."""
    t_start = None
    result = None
    for e in events:
        if e.kind is start:
            t_start = e.t
        elif e.kind is end and t_start is not None:
            result = (e.t - t_start) * 1000.0
            t_start = None
    return result
