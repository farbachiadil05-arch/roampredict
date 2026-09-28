"""The ctypes layer, tested without Windows.

1. Sizes and field offsets must equal the Windows x64 SDK layout - a wrong
   offset would silently read garbage (or crash) on a real laptop.
2. Parsers are fed synthetic buffers built exactly like Windows builds them.
"""

import ctypes

import pytest

from wlan_fakes import FT_IES, build_bss_list, wchars

from roampredict.net.l3 import parse_adapter_addresses
from roampredict.platform import win32_structs as w
from roampredict.platform.base import Band, WlanEventKind
from roampredict.platform.windows_wlan import decode_notification, parse_bss_list

x64 = pytest.mark.skipif(ctypes.sizeof(ctypes.c_void_p) != 8, reason="layout table is for 64-bit")

LAYOUT = [
    (w.GUID, 16, {}),
    (w.WLAN_INTERFACE_INFO, 532, {"strInterfaceDescription": 16, "isState": 528}),
    (w.WLAN_INTERFACE_INFO_LIST, None, {"InterfaceInfo": 8}),
    (w.DOT11_SSID, 36, {}),
    (w.WLAN_ASSOCIATION_ATTRIBUTES, 68, {"dot11Bssid": 40, "dot11PhyType": 48, "wlanSignalQuality": 56}),
    (w.WLAN_SECURITY_ATTRIBUTES, 16, {}),
    (w.WLAN_CONNECTION_ATTRIBUTES, 604, {"strProfileName": 8, "wlanAssociationAttributes": 520, "wlanSecurityAttributes": 588}),
    (
        w.WLAN_BSS_ENTRY,
        360,
        {
            "dot11Bssid": 40,
            "lRssi": 56,
            "bInRegDomain": 64,
            "usBeaconPeriod": 66,
            "ullTimestamp": 72,
            "ullHostTimestamp": 80,
            "ulChCenterFrequency": 92,
            "wlanRateSet": 96,
            "ulIeOffset": 352,
            "ulIeSize": 356,
        },
    ),
    (w.WLAN_BSS_LIST, None, {"wlanBssEntries": 8}),
    (w.DOT11_BSSID_LIST, 20, {"uNumOfEntries": 4, "BSSIDs": 12}),
    (w.WLAN_CONNECTION_PARAMETERS, 40, {"strProfile": 8, "pDot11Ssid": 16, "pDesiredBssidList": 24, "dot11BssType": 32, "dwFlags": 36}),
    (w.WLAN_NOTIFICATION_DATA, 40, {"InterfaceGuid": 8, "dwDataSize": 24, "pData": 32}),
    (w.WLAN_MSM_NOTIFICATION_DATA, 580, {"dot11Ssid": 516, "dot11MacAddr": 556, "bSecurityEnabled": 564, "wlanReasonCode": 576}),
    (w.WLAN_CONNECTION_NOTIFICATION_DATA, 568, {"wlanReasonCode": 560, "dwFlags": 564}),
    (w.WLAN_PROFILE_INFO, 516, {}),
    (w.WLAN_PROFILE_INFO_LIST, None, {"ProfileInfo": 8}),
    (w.SOCKET_ADDRESS, 16, {}),
    (w.IP_ADAPTER_UNICAST_ADDRESS_LH, 64, {"Next": 8, "Address": 16, "OnLinkPrefixLength": 56}),
    (w.IP_ADAPTER_GATEWAY_ADDRESS_LH, 32, {"Address": 16}),
    (
        w.IP_ADAPTER_ADDRESSES_LH,
        448,
        {
            "IfIndex": 4,
            "AdapterName": 16,
            "FirstUnicastAddress": 24,
            "FriendlyName": 72,
            "Flags": 92,
            "FirstGatewayAddress": 208,
            "Dhcpv4Server": 232,
            "FirstDnsSuffix": 440,
        },
    ),
    (w.ICMP_ECHO_REPLY, 40, {"RoundTripTime": 8, "Data": 16, "Options": 24}),
]


@x64
@pytest.mark.parametrize("cls, size, offsets", LAYOUT, ids=[c.__name__ for c, _, _ in LAYOUT])
def test_layout_matches_windows_x64(cls, size, offsets):
    if size is not None:
        assert ctypes.sizeof(cls) == size
    for field, offset in offsets.items():
        assert getattr(cls, field).offset == offset, field


def test_guid_round_trip():
    text = "{4D36E972-E325-11CE-BFC1-08002BE10318}"
    g = w.guid_from_str(text)
    assert w.guid_to_str(g) == text
    assert w.guid_to_str(w.guid_from_str(text.lower().strip("{}"))) == text
    with pytest.raises(ValueError):
        w.guid_from_str("not-a-guid")


def test_bssid_list_header():
    lst = w.make_bssid_list(bytes.fromhex("025e000000a1"))
    assert lst.Header.Type == 0x80 and lst.Header.Revision == 1 and lst.Header.Size == ctypes.sizeof(lst)
    assert lst.uNumOfEntries == lst.uTotalNumOfEntries == 1
    assert bytes(lst.BSSIDs[0]) == bytes.fromhex("025e000000a1")
    with pytest.raises(ValueError):
        w.make_bssid_list(b"\x01\x02")


def test_connection_parameters_hold_only_a_profile_name():
    params = w.WLAN_CONNECTION_PARAMETERS()
    params.strProfile = "eduroam"
    lst = w.make_bssid_list(bytes.fromhex("025e000000a1"))
    params.pDesiredBssidList = ctypes.pointer(lst)
    assert params.strProfile == "eduroam"
    assert bytes(params.pDesiredBssidList.contents.BSSIDs[0]) == bytes.fromhex("025e000000a1")


def test_parse_bss_list():
    now = w.filetime_now()
    buf = build_bss_list(
        [
            {"bssid": bytes.fromhex("025e000000a1"), "ssid": "eduroam", "rssi": -61, "freq_khz": 5_180_000, "ies": FT_IES, "host_ts": now - 20_000_000},
            {"bssid": bytes.fromhex("025e000000b1"), "ssid": "eduroam", "rssi": -70, "freq_khz": 2_437_000, "ies": b""},
            {"bssid": b"\xff" * 6, "ssid": "broadcast?", "rssi": -50, "freq_khz": 5_200_000, "ies": b""},
        ]
    )
    entries = parse_bss_list(ctypes.addressof(buf), now)
    assert [e.bssid for e in entries] == ["02:5e:00:00:00:a1", "02:5e:00:00:00:b1"]  # broadcast skipped
    a, b = entries
    assert a.ssid == "eduroam" and a.rssi_dbm == -61 and a.freq_mhz == 5180
    assert (a.channel, a.band) == (36, Band.GHZ_5)
    assert a.age_s == pytest.approx(2.0, abs=0.01)
    assert a.capabilities.ft is True and a.capabilities.bss_transition is True
    assert (b.channel, b.band) == (6, Band.GHZ_2_4)
    assert b.age_s is None and b.capabilities.ft is None  # no IEs, no timestamp: unknown


def test_parse_bss_list_distrusts_bad_sizes():
    spec = {"bssid": bytes.fromhex("025e000000a1"), "ssid": "x", "rssi": -60, "freq_khz": 5_180_000, "ies": FT_IES}
    buf = build_bss_list([spec], declared_count=1000)  # count far larger than the buffer
    assert len(parse_bss_list(ctypes.addressof(buf))) == 1
    buf = build_bss_list([spec], bad_ie_offset=True)  # IE pointer outside the list
    assert parse_bss_list(ctypes.addressof(buf))[0].capabilities.ft is None


def notification(source, code, payload=None):
    data = w.WLAN_NOTIFICATION_DATA()
    data.NotificationSource = source
    data.NotificationCode = code
    if payload is not None:
        data.dwDataSize = ctypes.sizeof(payload)
        data.pData = ctypes.addressof(payload)
    return data


def test_decode_msm_roaming_notification():
    msm = w.WLAN_MSM_NOTIFICATION_DATA()
    msm.strProfileName = wchars("eduroam")
    msm.dot11MacAddr = (w.UCHAR * 6)(*bytes.fromhex("025e000000b2"))
    ev = decode_notification(notification(w.WLAN_NOTIFICATION_SOURCE_MSM, w.MSM_ROAMING_END, msm), 12.5)
    assert ev.kind is WlanEventKind.ROAMING_END and ev.t == 12.5
    assert ev.bssid == "02:5e:00:00:00:b2" and ev.profile == "eduroam"


def test_decode_acm_notifications():
    conn = w.WLAN_CONNECTION_NOTIFICATION_DATA()
    conn.strProfileName = wchars("eduroam")
    ok = decode_notification(notification(w.WLAN_NOTIFICATION_SOURCE_ACM, w.ACM_CONNECTION_COMPLETE, conn), 1.0)
    assert ok.kind is WlanEventKind.CONNECTION_COMPLETE and ok.profile == "eduroam"
    conn.wlanReasonCode = 0x50005
    failed = decode_notification(notification(w.WLAN_NOTIFICATION_SOURCE_ACM, w.ACM_CONNECTION_COMPLETE, conn), 1.0)
    assert failed.kind is WlanEventKind.CONNECTION_FAILED and failed.reason_code == 0x50005
    scan = decode_notification(notification(w.WLAN_NOTIFICATION_SOURCE_ACM, w.ACM_SCAN_COMPLETE), 2.0)
    assert scan.kind is WlanEventKind.SCAN_COMPLETE
    assert decode_notification(notification(w.WLAN_NOTIFICATION_SOURCE_ACM, 999), 2.0) is None


def test_onex_payload_is_never_read():
    data = w.WLAN_NOTIFICATION_DATA()
    data.NotificationSource = w.WLAN_NOTIFICATION_SOURCE_ONEX
    data.NotificationCode = 1
    data.dwDataSize = 4096
    data.pData = 1  # would crash if dereferenced
    ev = decode_notification(data, 3.0)
    assert ev.kind is WlanEventKind.ONEX_ACTIVITY


def test_parse_adapter_addresses():
    keep = []

    def sockaddr(ip):
        sa = w.SOCKADDR_IN(sin_family=w.AF_INET, sin_addr=(w.UCHAR * 4)(*[int(p) for p in ip.split(".")]))
        keep.append(sa)
        return ctypes.addressof(sa)

    def cstring(text):
        s = ctypes.create_string_buffer(text.encode("ascii"))
        keep.append(s)
        return ctypes.addressof(s)

    def wstring(text):
        raw = text.encode("utf-16-le") + b"\x00\x00"
        s = ctypes.create_string_buffer(raw, len(raw))
        keep.append(s)
        return ctypes.addressof(s)

    guid = "{11111111-2222-3333-4444-555555555555}"
    link_local = w.IP_ADAPTER_UNICAST_ADDRESS_LH()
    link_local.Address.lpSockaddr = sockaddr("169.254.9.9")
    link_local.OnLinkPrefixLength = 16
    real = w.IP_ADAPTER_UNICAST_ADDRESS_LH()
    real.Address.lpSockaddr = sockaddr("10.20.30.40")
    real.OnLinkPrefixLength = 22
    link_local.Next = ctypes.addressof(real)
    gw = w.IP_ADAPTER_GATEWAY_ADDRESS_LH()
    gw.Address.lpSockaddr = sockaddr("10.20.28.1")
    wifi = w.IP_ADAPTER_ADDRESSES_LH()
    wifi.IfIndex = 17
    wifi.AdapterName = cstring(guid.lower())
    wifi.FriendlyName = wstring("Wi-Fi")
    wifi.FirstUnicastAddress = ctypes.addressof(link_local)
    wifi.FirstGatewayAddress = ctypes.addressof(gw)
    wifi.Flags = w.IP_ADAPTER_DHCP_ENABLED
    wifi.Dhcpv4Server.lpSockaddr = sockaddr("10.20.0.10")
    ethernet = w.IP_ADAPTER_ADDRESSES_LH()
    ethernet.IfIndex = 3
    ethernet.AdapterName = cstring("{99999999-0000-0000-0000-000000000000}")
    ethernet.Next = ctypes.addressof(wifi)
    keep += [link_local, real, gw, wifi, ethernet]

    snap = parse_adapter_addresses(ctypes.addressof(ethernet), guid)
    assert snap is not None
    assert (snap.if_index, snap.friendly_name, snap.ipv4, snap.prefix_len) == (17, "Wi-Fi", "10.20.30.40", 22)
    assert snap.gateway == "10.20.28.1" and snap.dhcp_server == "10.20.0.10" and snap.usable
    assert parse_adapter_addresses(ctypes.addressof(ethernet), "{00000000-0000-0000-0000-000000000000}") is None
