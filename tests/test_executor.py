"""Safe switch: verification, fallbacks, login-prompt handling, IP layer."""

import pytest

from roampredict.platform.base import L3Snapshot, LinkStatus
from roampredict.platform.mock import DEFAULT_L3, MockNetworkOps, MockWlanAdapter, ScriptedAp, ScriptedRadio
from roampredict.roam.executor import ExecutorConfig, RoamExecutor, is_auth_reason
from roampredict.telemetry import Telemetry
from roampredict.topology.predictor import ScoreBreakdown

CUR = "02:00:00:00:00:01"
CAND = "02:00:00:00:00:02"
OTHER = "02:00:00:00:00:03"


def candidate(bssid=CAND, cls="recent"):
    return ScoreBreakdown(
        bssid=bssid,
        ssid="testnet",
        rssi_dbm=-60,
        gain_db=14,
        learned_p=0.5,
        learned_term=0.1,
        rssi_norm=0.6,
        rssi_term=0.2,
        seen_age_s=1.0,
        seen_term=0.1,
        assoc_age_s=100.0,
        assoc_term=0.1,
        candidate_class=cls,
        total=0.5,
        eligible=True,
    )


def setup(cand_rssi=-60.0, cur_rssi=-74.0, net=None, sockets=None, **radio_kw):
    aps = [ScriptedAp(CUR, cur_rssi), ScriptedAp(CAND, cand_rssi), ScriptedAp(OTHER, -58.0)]
    radio = ScriptedRadio(aps, connected_to=CUR, **radio_kw)
    adapter = MockWlanAdapter(radio)
    net = net or MockNetworkOps()
    tel = Telemetry(console=False, keep_in_memory=True)
    ex = RoamExecutor(adapter, net, ExecutorConfig(), tel, reset_sockets=sockets)
    return radio, adapter, net, ex


def link(adapter):
    return adapter.link_status()


def test_verify_uses_fresh_cache_without_scanning():
    radio, adapter, _, ex = setup(initial_cache_age_s=1.0)
    v = ex.verify(link=link(adapter), bssid=CAND, current_estimate_dbm=-75.0)
    assert v.ok and not v.scanned and adapter.scan_requests == 0
    assert v.current_rssi_dbm == -74.0  # the higher of estimate (-75) and live reading (-74)
    assert v.gain_db == pytest.approx(14.0)


def test_verify_scans_when_the_candidate_entry_is_stale():
    radio, adapter, _, ex = setup(initial_cache_age_s=10.0)
    v = ex.verify(link=link(adapter), bssid=CAND, current_estimate_dbm=-74.0)
    assert v.ok and v.scanned and adapter.scan_requests == 1
    assert v.scan_ms == pytest.approx(1000.0)
    assert v.candidate.age_s == pytest.approx(0.0)


def test_verify_rejects_unknown_hidden_and_weak_candidates():
    radio, adapter, _, ex = setup(initial_cache_age_s=10.0)
    assert "not visible" in ex.verify(link=link(adapter), bssid="02:00:00:00:00:99", current_estimate_dbm=-74).reason
    radio, adapter, _, ex = setup(initial_cache_age_s=10.0)
    radio.hidden.add(CAND)  # still cached from long ago, not heard in the new scan
    assert "no fresh data" in ex.verify(link=link(adapter), bssid=CAND, current_estimate_dbm=-74).reason
    radio2, adapter2, _, ex2 = setup(cand_rssi=-68.0)
    v = ex2.verify(link=link(adapter2), bssid=CAND, current_estimate_dbm=-74.0)
    assert not v.ok and "+6.0 dB" in v.reason


def test_a_dip_never_makes_a_candidate_look_better():
    radio, adapter, _, ex = setup(cand_rssi=-67.0, cur_rssi=-74.0)
    # smoothed estimate says -80 (a dip); the live reading is -74 -> gain is only 7 dB
    v = ex.verify(link=link(adapter), bssid=CAND, current_estimate_dbm=-80.0)
    assert not v.ok and v.gain_db == pytest.approx(7.0)


def test_verify_notices_a_changed_link():
    radio, adapter, _, ex = setup()
    stale = LinkStatus(connected=True, ssid="testnet", bssid=OTHER, profile_name="testnet", rssi_dbm=-70)
    assert "link changed" in ex.verify(link=stale, bssid=CAND, current_estimate_dbm=-74).reason


def verified(ex, adapter):
    v = ex.verify(link=link(adapter), bssid=CAND, current_estimate_dbm=-74.0)
    assert v.ok
    return v


def test_successful_switch_same_subnet_flushes_arp():
    resets = []
    radio, adapter, net, ex = setup(sockets=lambda: resets.append(1) or 2)
    before = link(adapter)
    out = ex.switch(link=before, candidate=candidate(), verification=verified(ex, adapter))
    assert out.success and out.stage == "done" and out.final_bssid == CAND
    assert adapter.connect_calls == [("testnet", CAND)]
    assert out.connect.disconnect_seen and out.connect.honored
    assert "flush_arp" in net.calls and "renew_dhcp" not in net.calls
    assert out.gateway_changed is False and out.gateway_rtt_ms == 3.0
    assert out.sockets_reset == 2 and resets == [1]
    rec = out.to_switch_record(at=123.0)
    assert rec.initiator == "roampredict" and rec.honored and rec.candidate_class == "recent"
    assert rec.total_ms == pytest.approx(300.0) and rec.auth_ms == 100.0
    assert out.extra["post_rssi_dbm"] == -60.0


def test_changed_subnet_renews_dhcp():
    other_net = L3Snapshot(7, "Wi-Fi", "10.99.0.5", 24, "10.99.0.1")
    net = MockNetworkOps(snapshots=[DEFAULT_L3, other_net])
    radio, adapter, net, ex = setup(net=net)
    out = ex.switch(link=link(adapter), candidate=candidate(), verification=verified(ex, adapter))
    assert out.success and out.gateway_changed is True
    assert "renew_dhcp" in net.calls and "flush_arp" not in net.calls
    assert out.dhcp.duration_ms == 420.0
    assert out.to_switch_record(at=1.0).dhcp_ms == 420.0
    assert "ping 10.99.0.1" in net.calls


def test_without_admin_the_arp_flush_is_skipped_but_the_switch_works():
    net = MockNetworkOps(admin=False)
    radio, adapter, net, ex = setup(net=net)
    out = ex.switch(link=link(adapter), candidate=candidate(), verification=verified(ex, adapter))
    assert out.success and out.arp.skipped


def test_failed_connect_waits_for_windows_autoconnect():
    radio, adapter, _, ex = setup(connect_mode="fail", autoconnect_after_s=2.0)
    out = ex.switch(link=link(adapter), candidate=candidate(), verification=verified(ex, adapter))
    assert not out.success and out.fallback == "windows_autoconnect"
    assert adapter.profile_connects == []
    assert out.final_bssid is not None and not out.login_prompt_suspected


def test_failed_connect_falls_back_to_a_plain_profile_connection():
    radio, adapter, _, ex = setup(connect_mode="fail")
    out = ex.switch(link=link(adapter), candidate=candidate(), verification=verified(ex, adapter))
    assert not out.success and out.fallback == "plain_profile_connect"
    assert adapter.profile_connects == ["testnet"]
    assert link(adapter).connected  # Windows picked an AP by itself


@pytest.mark.parametrize("mode", ["stall", "auth_fail"])
def test_suspected_login_prompt_stops_and_leaves_it_to_windows(mode):
    radio, adapter, _, ex = setup(connect_mode=mode)
    out = ex.switch(link=link(adapter), candidate=candidate(), verification=verified(ex, adapter))
    assert not out.success and out.login_prompt_suspected
    assert out.fallback == "left_to_windows"
    assert adapter.profile_connects == []  # no second attempt that could pop up a prompt again


def test_driver_choosing_another_ap_is_reported():
    radio, adapter, _, ex = setup(connect_mode="other_bssid")
    out = ex.switch(link=link(adapter), candidate=candidate(), verification=verified(ex, adapter))
    assert not out.success and out.stage == "bssid"
    assert out.final_bssid == OTHER and not out.connect.honored
    assert "instead of" in out.reason


def test_campus_that_blocks_ping_is_checked_by_ip_address():
    net = MockNetworkOps(ping_ok=False)  # the gateway never answers ping, not even before
    radio, adapter, net, ex = setup(net=net)
    out = ex.switch(link=link(adapter), candidate=candidate(), verification=verified(ex, adapter))
    assert out.success and out.stage == "done"
    assert "does not answer ping" in out.extra["gateway_check"]
    assert "renew_dhcp" not in net.calls


def test_no_gateway_reply_is_a_failure_after_trying_dhcp():
    net = MockNetworkOps(ping_ok=[True, False])  # answered before the switch, silent after
    radio, adapter, net, ex = setup(net=net)
    out = ex.switch(link=link(adapter), candidate=candidate(), verification=verified(ex, adapter))
    assert not out.success and out.stage == "l3"
    assert "gateway" in out.reason and "renew_dhcp" in net.calls


def test_auth_reason_ranges():
    assert is_auth_reason(0x40001) and is_auth_reason(0x50005)
    assert not is_auth_reason(0x38001) and not is_auth_reason(0) and not is_auth_reason(None)
    assert not is_auth_reason(0x60000)


def test_config_validation():
    with pytest.raises(ValueError):
        ExecutorConfig(auth_stall_s=20.0, connect_timeout_s=12.0)
    with pytest.raises(ValueError):
        ExecutorConfig(scan_timeout_s=0)


def test_verify_applies_the_2g_handicap():
    aps = [ScriptedAp(CUR, -74.0), ScriptedAp(CAND, -62.0, freq_mhz=2412)]  # 2.4 GHz, reads +12 dB
    radio = ScriptedRadio(aps, connected_to=CUR, initial_cache_age_s=1.0)
    adapter = MockWlanAdapter(radio)
    ex = RoamExecutor(adapter, MockNetworkOps(), ExecutorConfig(), Telemetry(console=False))
    v = ex.verify(link=adapter.link_status(), bssid=CAND, current_estimate_dbm=-74.0, band_2g_penalty_db=7.0)
    assert not v.ok and v.gain_db == pytest.approx(5.0) and "2.4 GHz handicap" in v.reason
    assert ex.verify(link=adapter.link_status(), bssid=CAND, current_estimate_dbm=-74.0).ok  # no handicap given


def test_verify_can_trust_a_corrected_estimate_over_the_live_reading():
    radio, adapter, _, ex = setup(cand_rssi=-72.0, cur_rssi=-70.0, initial_cache_age_s=1.0)
    assert not ex.verify(link=link(adapter), bssid=CAND, current_estimate_dbm=-84.0).ok  # live -70 wins: +2 dB
    v = ex.verify(link=link(adapter), bssid=CAND, current_estimate_dbm=-84.0, trust_estimate=True)
    assert v.ok and v.gain_db == pytest.approx(12.0)
