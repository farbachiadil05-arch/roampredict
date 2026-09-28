"""802.11r/k/v detection from raw information elements (untrusted input)."""

import random

from roampredict.platform.info_elements import FT_AKMS, iter_elements, parse_capabilities, parse_rsn


def ie(eid, body):
    return bytes([eid, len(body)]) + body


def rsn(akms, caps=0x0000, pairwise=(4,), group=4):
    body = (1).to_bytes(2, "little") + b"\x00\x0f\xac" + bytes([group])
    body += len(pairwise).to_bytes(2, "little") + b"".join(b"\x00\x0f\xac" + bytes([p]) for p in pairwise)
    body += len(akms).to_bytes(2, "little") + b"".join(b"\x00\x0f\xac" + bytes([a]) for a in akms)
    body += caps.to_bytes(2, "little")
    return ie(48, body)


SSID = ie(0, b"eduroam")
MDE = ie(54, bytes.fromhex("a1b2") + b"\x01")  # MDID a1b2, FT over DS
RM = ie(70, bytes([0x02, 0, 0, 0, 0]))  # neighbor report
EXT_BTM = ie(127, bytes([0x00, 0x00, 0x08]))  # bit 19
BSS_LOAD = ie(11, (12).to_bytes(2, "little") + bytes([128]) + (0).to_bytes(2, "little"))


def test_enterprise_network_with_11r_11k_11v():
    caps = parse_capabilities(SSID + rsn([1, 3], caps=0x0081) + MDE + RM + EXT_BTM + BSS_LOAD)
    assert caps.ft is True and caps.ft_over_ds is True and caps.mobility_domain == "a1b2"
    assert caps.rrm_neighbor_report is True
    assert caps.bss_transition is True
    assert caps.rsn_preauth is True  # capabilities bit 0
    assert caps.enterprise is True and caps.akm_suites == (1, 3)
    assert caps.mfp_capable is True and caps.mfp_required is False
    assert caps.bss_load_stations == 12 and abs(caps.bss_load_utilization - 128 / 255) < 1e-9
    assert caps.flags() == "11r=yes 11k=yes 11v=yes preauth=yes"


def test_plain_wpa2_enterprise_without_fast_roaming():
    caps = parse_capabilities(SSID + rsn([1]))
    assert caps.ft is False and caps.rrm_neighbor_report is False and caps.bss_transition is False
    assert caps.rsn_preauth is False and caps.enterprise is True


def test_ft_detected_from_either_signal():
    assert parse_capabilities(SSID + rsn([4])).ft is True  # FT-PSK AKM only
    assert parse_capabilities(SSID + rsn([2]) + MDE).ft is True  # Mobility Domain only
    assert {3, 4, 9, 13} <= FT_AKMS


def test_no_ie_data_means_unknown_not_no():
    caps = parse_capabilities(b"")
    assert caps.ft is None and caps.bss_transition is None and caps.enterprise is None
    assert caps.flags() == "11r=? 11k=? 11v=? preauth=?"


def test_short_extended_capabilities_means_no_btm():
    assert parse_capabilities(SSID + ie(127, b"\x04")).bss_transition is False


def test_vendor_akm_does_not_look_like_a_standard_one():
    body = (1).to_bytes(2, "little") + b"\x00\x0f\xac\x04" + (1).to_bytes(2, "little") + b"\x00\x0f\xac\x04"
    body += (1).to_bytes(2, "little") + b"\x00\x40\x96\x03"  # a Cisco suite with type 3
    info = parse_rsn(body)
    assert info is not None and info.akms[0] != 3


def test_malformed_rsn_gives_unknown():
    bad = ie(48, (1).to_bytes(2, "little") + b"\x00\x0f\xac\x04" + (9).to_bytes(2, "little") + b"\x00")
    caps = parse_capabilities(SSID + bad)
    assert caps.ft is None and caps.enterprise is None and caps.rsn_preauth is None


def test_truncated_element_stops_parsing():
    data = SSID + bytes([48, 200, 1, 0])  # claims 200 bytes, has 2
    assert list(iter_elements(data)) == [(0, b"eduroam")]


def test_random_garbage_never_raises():
    rng = random.Random(1234)
    for _ in range(3000):
        blob = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 80)))
        parse_capabilities(blob)
        parse_capabilities(SSID + blob)
        parse_rsn(blob)
