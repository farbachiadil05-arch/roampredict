"""Test doubles for the Windows layer.

``FakeWlanApi`` behaves like wlanapi.dll for one Wi-Fi adapter on an
eduroam-like network.  Every fake function is a real ctypes function pointer
built from the adapter's own PROTOTYPES table, so each call goes through the
same argument conversion as on Windows.  What this cannot prove is that
PROTOTYPES matches the real DLL - that part comes from the SDK documentation.
"""

from __future__ import annotations

import ctypes
import threading
import time
import types
from ctypes import POINTER, sizeof

from roampredict.platform import win32_structs as w
from roampredict.platform.windows_wlan import PROTOTYPES

GUID = "{11111111-2222-3333-4444-555555555555}"
BSS_A = bytes.fromhex("025e000000a1")
BSS_B = bytes.fromhex("025e000000b1")
FT_IES = bytes([0, 7]) + b"eduroam" + bytes([54, 3, 0xA1, 0xB2, 0x00]) + bytes([127, 3, 0, 0, 0x08])


def wchars(text: str, n: int = 256) -> ctypes.Array:  # type: ignore[type-arg]
    raw = text.encode("utf-16-le")
    units = [int.from_bytes(raw[i : i + 2], "little") for i in range(0, len(raw), 2)]
    return (w.WCHAR * n)(*units)


def build_bss_list(entries: list[dict], declared_count: int | None = None, bad_ie_offset: bool = False) -> ctypes.Array:  # type: ignore[type-arg]
    """Lay out a WLAN_BSS_LIST the way wlanapi does: header, entries, then IEs."""
    head = w.WLAN_BSS_LIST.wlanBssEntries.offset
    esize = sizeof(w.WLAN_BSS_ENTRY)
    total = head + len(entries) * esize + sum(len(e["ies"]) for e in entries)
    buf = ctypes.create_string_buffer(total)
    base = ctypes.addressof(buf)
    hdr = w.WLAN_BSS_LIST.from_buffer(buf)
    hdr.dwTotalSize = total
    hdr.dwNumberOfItems = len(entries) if declared_count is None else declared_count
    ie_pos = head + len(entries) * esize
    for i, spec in enumerate(entries):
        off = head + i * esize
        e = w.WLAN_BSS_ENTRY.from_buffer(buf, off)
        e.dot11Ssid = w.make_dot11_ssid(spec["ssid"])
        e.dot11Bssid = (w.UCHAR * 6)(*spec["bssid"])
        e.lRssi = spec["rssi"]
        e.uLinkQuality = 70
        e.ulChCenterFrequency = spec["freq_khz"]
        e.ullHostTimestamp = spec.get("host_ts", 0)
        e.ulIeOffset = 10_000_000 if bad_ie_offset else ie_pos - off
        e.ulIeSize = len(spec["ies"])
        ctypes.memmove(base + ie_pos, spec["ies"], len(spec["ies"]))
        ie_pos += len(spec["ies"])
    return buf


class FakeWlanApi:
    def __init__(self, *, connect_mode: str = "ok", rssi_supported: bool = True, bss_denied: bool = False) -> None:
        self.keep: list[object] = []
        self.callback = None
        self.guid = w.guid_from_str(GUID)
        self.current: bytes | None = BSS_A
        self.connect_mode = connect_mode
        self.rssi_supported = rssi_supported
        self.bss_denied = bss_denied
        self.connect_calls: list[tuple[str, bytes | None]] = []
        self.scan_calls: list[bytes | None] = []
        self.queries: list[int] = []
        self.freed = 0
        self.unregistered = False
        self.closed = False

    def dll(self) -> types.SimpleNamespace:
        ns = types.SimpleNamespace()
        for name, (argtypes, restype) in PROTOTYPES.items():
            setattr(ns, name, ctypes.CFUNCTYPE(restype, *argtypes)(getattr(self, name)))
        return ns

    # -- notifications -----------------------------------------------------------------

    def _fire(self, source: int, code: int, payload: ctypes.Structure | None = None) -> None:
        data = w.WLAN_NOTIFICATION_DATA()
        data.NotificationSource = source
        data.NotificationCode = code
        data.InterfaceGuid = self.guid
        if payload is not None:
            data.dwDataSize = sizeof(payload)
            data.pData = ctypes.addressof(payload)
        if self.callback:
            self.callback(ctypes.pointer(data), None)

    def _acm(self, code: int, reason: int = 0) -> None:
        info = w.WLAN_CONNECTION_NOTIFICATION_DATA()
        info.strProfileName = wchars("eduroam")
        info.wlanReasonCode = reason
        self._fire(w.WLAN_NOTIFICATION_SOURCE_ACM, code, info)

    def _msm(self, code: int, bssid: bytes) -> None:
        info = w.WLAN_MSM_NOTIFICATION_DATA()
        info.strProfileName = wchars("eduroam")
        info.dot11MacAddr = (w.UCHAR * 6)(*bssid)
        self._fire(w.WLAN_NOTIFICATION_SOURCE_MSM, code, info)

    def _connect_sequence(self, bssid: bytes | None) -> None:
        self._acm(w.ACM_DISCONNECTING)
        self._acm(w.ACM_DISCONNECTED)
        self.current = None
        self._acm(w.ACM_CONNECTION_START)
        target = bssid or BSS_B
        time.sleep(0.01)
        self._msm(w.MSM_ASSOCIATING, target)
        time.sleep(0.01)
        self._msm(w.MSM_ASSOCIATED, target)
        self._msm(w.MSM_AUTHENTICATING, target)
        if self.connect_mode == "stall":
            return
        if self.connect_mode == "fail":
            time.sleep(0.01)
            self._acm(w.ACM_CONNECTION_COMPLETE, reason=0x50005)
            return
        time.sleep(0.03)
        self.current = target
        self._msm(w.MSM_CONNECTED, target)
        self._acm(w.ACM_CONNECTION_COMPLETE)

    # -- wlanapi functions (Python side of the ctypes pointers) --------------------------

    def WlanOpenHandle(self, version, reserved, pversion, phandle):  # noqa: N802
        pversion[0] = 2
        phandle[0] = 0x1234
        return 0

    def WlanCloseHandle(self, handle, reserved):  # noqa: N802
        self.closed = True
        return 0

    def WlanEnumInterfaces(self, handle, reserved, pplist):  # noqa: N802
        lst = w.WLAN_INTERFACE_INFO_LIST()
        lst.dwNumberOfItems = 1
        lst.InterfaceInfo[0].InterfaceGuid = self.guid
        lst.InterfaceInfo[0].strInterfaceDescription = wchars("Intel(R) Wi-Fi 6E AX211 160MHz")
        lst.InterfaceInfo[0].isState = 1
        self.keep.append(lst)
        pplist[0] = ctypes.pointer(lst)
        return 0

    def WlanQueryInterface(self, handle, pguid, opcode, reserved, psize, ppdata, pkind):  # noqa: N802
        self.queries.append(opcode)
        if opcode == w.wlan_intf_opcode_current_connection:
            if self.current is None:
                return w.ERROR_INVALID_STATE
            a = w.WLAN_CONNECTION_ATTRIBUTES()
            a.isState = 1
            a.strProfileName = wchars("eduroam")
            a.wlanAssociationAttributes.dot11Ssid = w.make_dot11_ssid("eduroam")
            a.wlanAssociationAttributes.dot11Bssid = (w.UCHAR * 6)(*self.current)
            a.wlanAssociationAttributes.wlanSignalQuality = 74
            a.wlanAssociationAttributes.ulRxRate = 866_700
            a.wlanSecurityAttributes.bSecurityEnabled = 1
            a.wlanSecurityAttributes.bOneXEnabled = 1
            a.wlanSecurityAttributes.dot11AuthAlgorithm = 6
            a.wlanSecurityAttributes.dot11CipherAlgorithm = 4
            obj: ctypes._SimpleCData | ctypes.Structure = a
        elif opcode == w.wlan_intf_opcode_rssi:
            if not self.rssi_supported:
                return w.ERROR_NOT_SUPPORTED
            obj = w.LONG(-63)
        elif opcode == w.wlan_intf_opcode_channel_number:
            obj = w.ULONG(36)
        else:
            return w.ERROR_INVALID_PARAMETER
        self.keep.append(obj)
        psize[0] = sizeof(obj)
        ppdata[0] = ctypes.addressof(obj)
        pkind[0] = 0
        return 0

    def WlanGetNetworkBssList(self, handle, pguid, pssid, bss_type, secure, reserved, pplist):  # noqa: N802
        if self.bss_denied:
            return w.ERROR_ACCESS_DENIED
        buf = build_bss_list(
            [
                {"bssid": BSS_A, "ssid": "eduroam", "rssi": -63, "freq_khz": 5_180_000, "ies": FT_IES},
                {"bssid": BSS_B, "ssid": "eduroam", "rssi": -52, "freq_khz": 5_745_000, "ies": FT_IES},
            ]
        )
        self.keep.append(buf)
        pplist[0] = ctypes.cast(buf, POINTER(w.WLAN_BSS_LIST))
        return 0

    def WlanScan(self, handle, pguid, pssid, pie, reserved):  # noqa: N802
        self.scan_calls.append(w.dot11_ssid_bytes(pssid.contents) if pssid else None)
        threading.Timer(0.02, self._fire, args=(w.WLAN_NOTIFICATION_SOURCE_ACM, w.ACM_SCAN_COMPLETE)).start()
        return 0

    def WlanConnect(self, handle, pguid, pparams, reserved):  # noqa: N802
        params = pparams.contents
        bssid = bytes(params.pDesiredBssidList.contents.BSSIDs[0]) if params.pDesiredBssidList else None
        self.connect_calls.append((params.strProfile, bssid))
        threading.Thread(target=self._connect_sequence, args=(bssid,), daemon=True).start()
        return 0

    def WlanRegisterNotification(self, handle, source, ignore_dup, callback, context, reserved, pprevious):  # noqa: N802
        if source == w.WLAN_NOTIFICATION_SOURCE_NONE:
            self.unregistered = True
            self.callback = None
        else:
            self.callback = callback
        return 0

    def WlanGetProfileList(self, handle, pguid, reserved, pplist):  # noqa: N802
        n = 2
        buf = ctypes.create_string_buffer(w.WLAN_PROFILE_INFO_LIST.ProfileInfo.offset + n * sizeof(w.WLAN_PROFILE_INFO))
        lst = w.WLAN_PROFILE_INFO_LIST.from_buffer(buf)
        lst.dwNumberOfItems = n
        base = ctypes.addressof(buf) + w.WLAN_PROFILE_INFO_LIST.ProfileInfo.offset
        for i, name in enumerate(("eduroam", "Home WiFi")):
            w.WLAN_PROFILE_INFO.from_address(base + i * sizeof(w.WLAN_PROFILE_INFO)).strProfileName = wchars(name)
        self.keep.append(buf)
        pplist[0] = ctypes.cast(buf, POINTER(w.WLAN_PROFILE_INFO_LIST))
        return 0

    def WlanFreeMemory(self, pointer):  # noqa: N802
        self.freed += 1

    def WlanReasonCodeToString(self, code, size, buffer, reserved):  # noqa: N802
        return 1  # a Python callback cannot fill a c_wchar_p buffer: exercise the fallback text
