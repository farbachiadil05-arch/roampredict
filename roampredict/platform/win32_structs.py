"""ctypes definitions for wlanapi.dll and iphlpapi.dll (Windows SDK layouts).

Only fixed-width integer types are used - never ``ctypes.wintypes``, whose
DWORD/ULONG are 8 bytes on 64-bit Linux - and WCHAR is stored as uint16.  That
keeps every structure byte-identical to Windows on any 64-bit OS, so the tests
can check sizes and field offsets on Linux against the published x64 layout
(tests/test_win32_structs.py).  Nothing in this module loads a DLL.
"""

from __future__ import annotations

import ctypes
from ctypes import POINTER, Structure, Union, c_int32, c_uint8, c_uint16, c_uint32, c_uint64, c_void_p, c_wchar_p

BYTE = UCHAR = BOOLEAN = c_uint8
USHORT = WORD = c_uint16
ULONG = DWORD = UINT = c_uint32
LONG = INT = BOOL = c_int32
ULONGLONG = ULONG64 = c_uint64
WCHAR = c_uint16  # one UTF-16 code unit
HANDLE = PVOID = c_void_p

# -- error codes -------------------------------------------------------------------------
ERROR_SUCCESS = 0
ERROR_ACCESS_DENIED = 5
ERROR_INVALID_HANDLE = 6
ERROR_NOT_ENOUGH_MEMORY = 8
ERROR_NOT_SUPPORTED = 50
ERROR_INVALID_PARAMETER = 87
ERROR_BUFFER_OVERFLOW = 111
ERROR_BUSY = 170
ERROR_NO_DATA = 232
ERROR_SERVICE_NOT_ACTIVE = 1062
ERROR_NOT_FOUND = 1168
ERROR_INVALID_STATE = 5023
ERROR_NDIS_DOT11_POWER_STATE_INVALID = 0x80342002  # radio switched off

# -- wlanapi constants ---------------------------------------------------------------------
WLAN_CLIENT_VERSION_VISTA = 2
DOT11_SSID_MAX_LENGTH = 32
DOT11_RATE_SET_MAX_LENGTH = 126
WLAN_MAX_NAME_LENGTH = 256

wlan_intf_opcode_interface_state = 6
wlan_intf_opcode_current_connection = 7
wlan_intf_opcode_channel_number = 8
wlan_intf_opcode_rssi = 0x10000102  # LONG, dBm

dot11_BSS_type_infrastructure = 1
dot11_BSS_type_independent = 2
dot11_BSS_type_any = 3

wlan_connection_mode_profile = 0

NDIS_OBJECT_TYPE_DEFAULT = 0x80
DOT11_BSSID_LIST_REVISION_1 = 1

WLAN_NOTIFICATION_SOURCE_NONE = 0x00
WLAN_NOTIFICATION_SOURCE_ONEX = 0x04
WLAN_NOTIFICATION_SOURCE_ACM = 0x08
WLAN_NOTIFICATION_SOURCE_MSM = 0x10

# WLAN_NOTIFICATION_ACM
ACM_SCAN_COMPLETE = 7
ACM_SCAN_FAIL = 8
ACM_CONNECTION_START = 9
ACM_CONNECTION_COMPLETE = 10
ACM_CONNECTION_ATTEMPT_FAIL = 11
ACM_DISCONNECTING = 20
ACM_DISCONNECTED = 21
# WLAN_NOTIFICATION_MSM
MSM_ASSOCIATING = 1
MSM_ASSOCIATED = 2
MSM_AUTHENTICATING = 3
MSM_CONNECTED = 4
MSM_ROAMING_START = 5
MSM_ROAMING_END = 6
MSM_RADIO_STATE_CHANGE = 7
MSM_SIGNAL_QUALITY_CHANGE = 8
MSM_DISASSOCIATING = 9
MSM_DISCONNECTED = 10

WLAN_INTERFACE_STATE_CONNECTED = 1
INTERFACE_STATES = {
    0: "not ready",
    1: "connected",
    2: "ad hoc network formed",
    3: "disconnecting",
    4: "disconnected",
    5: "associating",
    6: "discovering",
    7: "authenticating",
}
AUTH_ALGORITHMS = {
    1: "Open",
    2: "Shared key",
    3: "WPA-Enterprise",
    4: "WPA-Personal",
    5: "WPA-None",
    6: "WPA2-Enterprise",
    7: "WPA2-Personal",
    8: "WPA3-Enterprise 192-bit",
    9: "WPA3-Personal (SAE)",
    10: "OWE",
    11: "WPA3-Enterprise",
}
CIPHER_ALGORITHMS = {
    0x00: "None",
    0x01: "WEP-40",
    0x02: "TKIP",
    0x04: "CCMP (AES)",
    0x05: "WEP-104",
    0x08: "GCMP",
    0x09: "GCMP-256",
    0x0A: "CCMP-256",
    0x100: "group key",
    0x101: "WEP",
}

# -- iphlpapi constants -----------------------------------------------------------------------
AF_INET = 2
GAA_FLAG_SKIP_ANYCAST = 0x0002
GAA_FLAG_SKIP_MULTICAST = 0x0004
GAA_FLAG_SKIP_DNS_SERVER = 0x0008
GAA_FLAG_INCLUDE_GATEWAYS = 0x0080
IP_ADAPTER_DHCP_ENABLED = 0x0004
IP_SUCCESS = 0
IP_REQ_TIMED_OUT = 11010
MAX_ADAPTER_ADDRESS_LENGTH = 8
MAX_DHCPV6_DUID_LENGTH = 130

# -- wlanapi structures ------------------------------------------------------------------------


class GUID(Structure):
    _fields_ = [("Data1", DWORD), ("Data2", WORD), ("Data3", WORD), ("Data4", BYTE * 8)]


def guid_to_str(g: GUID) -> str:
    d4 = bytes(g.Data4)
    return "{%08X-%04X-%04X-%s-%s}" % (g.Data1, g.Data2, g.Data3, d4[:2].hex().upper(), d4[2:].hex().upper())


def guid_from_str(text: str) -> GUID:
    s = text.strip().strip("{}")
    parts = s.split("-")
    if [len(p) for p in parts] != [8, 4, 4, 4, 12]:
        raise ValueError(f"not a GUID: {text!r}")
    tail = bytes.fromhex(parts[3] + parts[4])
    return GUID(int(parts[0], 16), int(parts[1], 16), int(parts[2], 16), (BYTE * 8)(*tail))


def wchars_to_str(buf: ctypes.Array) -> str:  # type: ignore[type-arg]
    """Decode a fixed WCHAR[] buffer (stored as uint16) up to the first NUL."""
    raw = bytes(buf)
    text = raw.decode("utf-16-le", errors="replace")
    return text.split("\x00", 1)[0]


class WLAN_INTERFACE_INFO(Structure):
    _fields_ = [
        ("InterfaceGuid", GUID),
        ("strInterfaceDescription", WCHAR * WLAN_MAX_NAME_LENGTH),
        ("isState", DWORD),  # WLAN_INTERFACE_STATE
    ]


class WLAN_INTERFACE_INFO_LIST(Structure):
    _fields_ = [("dwNumberOfItems", DWORD), ("dwIndex", DWORD), ("InterfaceInfo", WLAN_INTERFACE_INFO * 1)]


class DOT11_SSID(Structure):
    _fields_ = [("uSSIDLength", ULONG), ("ucSSID", UCHAR * DOT11_SSID_MAX_LENGTH)]


def make_dot11_ssid(ssid: str) -> DOT11_SSID:
    raw = ssid.encode("utf-8")
    if len(raw) > DOT11_SSID_MAX_LENGTH:
        raise ValueError("SSID longer than 32 bytes")
    return DOT11_SSID(len(raw), (UCHAR * DOT11_SSID_MAX_LENGTH)(*raw))


def dot11_ssid_bytes(s: DOT11_SSID) -> bytes:
    return bytes(s.ucSSID[: min(int(s.uSSIDLength), DOT11_SSID_MAX_LENGTH)])


class WLAN_ASSOCIATION_ATTRIBUTES(Structure):
    _fields_ = [
        ("dot11Ssid", DOT11_SSID),
        ("dot11BssType", DWORD),
        ("dot11Bssid", UCHAR * 6),
        ("dot11PhyType", DWORD),
        ("uDot11PhyIndex", ULONG),
        ("wlanSignalQuality", ULONG),  # 0..100
        ("ulRxRate", ULONG),  # kbit/s
        ("ulTxRate", ULONG),
    ]


class WLAN_SECURITY_ATTRIBUTES(Structure):
    _fields_ = [
        ("bSecurityEnabled", BOOL),
        ("bOneXEnabled", BOOL),
        ("dot11AuthAlgorithm", DWORD),
        ("dot11CipherAlgorithm", DWORD),
    ]


class WLAN_CONNECTION_ATTRIBUTES(Structure):
    _fields_ = [
        ("isState", DWORD),
        ("wlanConnectionMode", DWORD),
        ("strProfileName", WCHAR * WLAN_MAX_NAME_LENGTH),
        ("wlanAssociationAttributes", WLAN_ASSOCIATION_ATTRIBUTES),
        ("wlanSecurityAttributes", WLAN_SECURITY_ATTRIBUTES),
    ]


class WLAN_RATE_SET(Structure):
    _fields_ = [("uRateSetLength", ULONG), ("usRateSet", USHORT * DOT11_RATE_SET_MAX_LENGTH)]


class WLAN_BSS_ENTRY(Structure):
    _fields_ = [
        ("dot11Ssid", DOT11_SSID),
        ("uPhyId", ULONG),
        ("dot11Bssid", UCHAR * 6),
        ("dot11BssType", DWORD),
        ("dot11BssPhyType", DWORD),
        ("lRssi", LONG),  # dBm
        ("uLinkQuality", ULONG),  # 0..100
        ("bInRegDomain", BOOLEAN),
        ("usBeaconPeriod", USHORT),
        ("ullTimestamp", ULONGLONG),
        ("ullHostTimestamp", ULONGLONG),  # FILETIME of the last beacon/probe response
        ("usCapabilityInformation", USHORT),
        ("ulChCenterFrequency", ULONG),  # kHz
        ("wlanRateSet", WLAN_RATE_SET),
        ("ulIeOffset", ULONG),  # IE blob, relative to the start of this entry
        ("ulIeSize", ULONG),
    ]


class WLAN_BSS_LIST(Structure):
    _fields_ = [("dwTotalSize", DWORD), ("dwNumberOfItems", DWORD), ("wlanBssEntries", WLAN_BSS_ENTRY * 1)]


class NDIS_OBJECT_HEADER(Structure):
    _fields_ = [("Type", UCHAR), ("Revision", UCHAR), ("Size", USHORT)]


class DOT11_BSSID_LIST(Structure):
    """Variant with room for exactly one BSSID - all RoamPredict ever asks for."""

    _fields_ = [
        ("Header", NDIS_OBJECT_HEADER),
        ("uNumOfEntries", ULONG),
        ("uTotalNumOfEntries", ULONG),
        ("BSSIDs", (UCHAR * 6) * 1),
    ]


def make_bssid_list(bssid: bytes) -> DOT11_BSSID_LIST:
    if len(bssid) != 6:
        raise ValueError("BSSID must be 6 bytes")
    lst = DOT11_BSSID_LIST()
    lst.Header.Type = NDIS_OBJECT_TYPE_DEFAULT
    lst.Header.Revision = DOT11_BSSID_LIST_REVISION_1
    lst.Header.Size = ctypes.sizeof(DOT11_BSSID_LIST)
    lst.uNumOfEntries = 1
    lst.uTotalNumOfEntries = 1
    lst.BSSIDs[0] = (UCHAR * 6)(*bssid)
    return lst


class WLAN_CONNECTION_PARAMETERS(Structure):
    _fields_ = [
        ("wlanConnectionMode", DWORD),
        ("strProfile", c_wchar_p),  # the saved profile NAME (never profile XML)
        ("pDot11Ssid", POINTER(DOT11_SSID)),
        ("pDesiredBssidList", POINTER(DOT11_BSSID_LIST)),
        ("dot11BssType", DWORD),
        ("dwFlags", DWORD),
    ]


class WLAN_NOTIFICATION_DATA(Structure):
    _fields_ = [
        ("NotificationSource", DWORD),
        ("NotificationCode", DWORD),
        ("InterfaceGuid", GUID),
        ("dwDataSize", DWORD),
        ("pData", PVOID),
    ]


class WLAN_MSM_NOTIFICATION_DATA(Structure):
    _fields_ = [
        ("wlanConnectionMode", DWORD),
        ("strProfileName", WCHAR * WLAN_MAX_NAME_LENGTH),
        ("dot11Ssid", DOT11_SSID),
        ("dot11BssType", DWORD),
        ("dot11MacAddr", UCHAR * 6),  # the peer, i.e. the BSSID
        ("bSecurityEnabled", BOOL),
        ("bFirstPeer", BOOL),
        ("bLastPeer", BOOL),
        ("wlanReasonCode", DWORD),
    ]


class WLAN_CONNECTION_NOTIFICATION_DATA(Structure):
    """Fixed part only.  The real structure ends with ``strProfileXml``, which
    RoamPredict deliberately never reads."""

    _fields_ = [
        ("wlanConnectionMode", DWORD),
        ("strProfileName", WCHAR * WLAN_MAX_NAME_LENGTH),
        ("dot11Ssid", DOT11_SSID),
        ("dot11BssType", DWORD),
        ("bSecurityEnabled", BOOL),
        ("wlanReasonCode", DWORD),
        ("dwFlags", DWORD),
    ]


class WLAN_PROFILE_INFO(Structure):
    _fields_ = [("strProfileName", WCHAR * WLAN_MAX_NAME_LENGTH), ("dwFlags", DWORD)]


class WLAN_PROFILE_INFO_LIST(Structure):
    _fields_ = [("dwNumberOfItems", DWORD), ("dwIndex", DWORD), ("ProfileInfo", WLAN_PROFILE_INFO * 1)]


# stdcall on 32-bit Windows; on 64-bit there is a single calling convention.
_CALLBACK_FACTORY = getattr(ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE)
WLAN_NOTIFICATION_CALLBACK = _CALLBACK_FACTORY(None, POINTER(WLAN_NOTIFICATION_DATA), PVOID)

# -- iphlpapi structures -------------------------------------------------------------------------


class SOCKET_ADDRESS(Structure):
    _fields_ = [("lpSockaddr", PVOID), ("iSockaddrLength", INT)]


class SOCKADDR_IN(Structure):
    _fields_ = [("sin_family", USHORT), ("sin_port", USHORT), ("sin_addr", UCHAR * 4), ("sin_zero", UCHAR * 8)]


class _LengthFlags(Structure):
    _fields_ = [("Length", ULONG), ("Flags", DWORD)]


class _LengthFlagsUnion(Union):
    _anonymous_ = ("s",)
    _fields_ = [("Alignment", ULONGLONG), ("s", _LengthFlags)]


class IP_ADAPTER_UNICAST_ADDRESS_LH(Structure):
    _anonymous_ = ("u",)
    _fields_ = [
        ("u", _LengthFlagsUnion),
        ("Next", PVOID),
        ("Address", SOCKET_ADDRESS),
        ("PrefixOrigin", DWORD),
        ("SuffixOrigin", DWORD),
        ("DadState", DWORD),
        ("ValidLifetime", ULONG),
        ("PreferredLifetime", ULONG),
        ("LeaseLifetime", ULONG),
        ("OnLinkPrefixLength", c_uint8),
    ]


class IP_ADAPTER_GATEWAY_ADDRESS_LH(Structure):
    _anonymous_ = ("u",)
    _fields_ = [("u", _LengthFlagsUnion), ("Next", PVOID), ("Address", SOCKET_ADDRESS)]


class _LengthIfIndex(Structure):
    _fields_ = [("Length", ULONG), ("IfIndex", ULONG)]


class _LengthIfIndexUnion(Union):
    _anonymous_ = ("s",)
    _fields_ = [("Alignment", ULONGLONG), ("s", _LengthIfIndex)]


class IP_ADAPTER_ADDRESSES_LH(Structure):
    _anonymous_ = ("u",)
    _fields_ = [
        ("u", _LengthIfIndexUnion),
        ("Next", PVOID),
        ("AdapterName", PVOID),  # char* "{GUID}"
        ("FirstUnicastAddress", PVOID),
        ("FirstAnycastAddress", PVOID),
        ("FirstMulticastAddress", PVOID),
        ("FirstDnsServerAddress", PVOID),
        ("DnsSuffix", PVOID),
        ("Description", PVOID),
        ("FriendlyName", PVOID),  # wchar_t*, e.g. "Wi-Fi"
        ("PhysicalAddress", BYTE * MAX_ADAPTER_ADDRESS_LENGTH),
        ("PhysicalAddressLength", ULONG),
        ("Flags", ULONG),
        ("Mtu", ULONG),
        ("IfType", ULONG),
        ("OperStatus", DWORD),
        ("Ipv6IfIndex", ULONG),
        ("ZoneIndices", ULONG * 16),
        ("FirstPrefix", PVOID),
        ("TransmitLinkSpeed", ULONG64),
        ("ReceiveLinkSpeed", ULONG64),
        ("FirstWinsServerAddress", PVOID),
        ("FirstGatewayAddress", PVOID),
        ("Ipv4Metric", ULONG),
        ("Ipv6Metric", ULONG),
        ("Luid", ULONG64),
        ("Dhcpv4Server", SOCKET_ADDRESS),
        ("CompartmentId", c_uint32),
        ("NetworkGuid", GUID),
        ("ConnectionType", DWORD),
        ("TunnelType", DWORD),
        ("Dhcpv6Server", SOCKET_ADDRESS),
        ("Dhcpv6ClientDuid", BYTE * MAX_DHCPV6_DUID_LENGTH),
        ("Dhcpv6ClientDuidLength", ULONG),
        ("Dhcpv6Iaid", ULONG),
        ("FirstDnsSuffix", PVOID),
    ]


class IP_OPTION_INFORMATION(Structure):
    _fields_ = [("Ttl", UCHAR), ("Tos", UCHAR), ("Flags", UCHAR), ("OptionsSize", UCHAR), ("OptionsData", PVOID)]


class ICMP_ECHO_REPLY(Structure):
    _fields_ = [
        ("Address", ULONG),
        ("Status", ULONG),
        ("RoundTripTime", ULONG),  # milliseconds
        ("DataSize", USHORT),
        ("Reserved", USHORT),
        ("Data", PVOID),
        ("Options", IP_OPTION_INFORMATION),
    ]


def filetime_now() -> int:
    """Current time as a Windows FILETIME (100 ns units since 1601-01-01 UTC)."""
    import time

    return int((time.time() + 11_644_473_600) * 10_000_000)

