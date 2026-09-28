import pytest

from roampredict.platform.base import LinkStatus
from roampredict.safety import KillSwitch, RoamRateLimiter, SafetyConfig, SafetyGate
from roampredict.validate import ValidationError

LINK = LinkStatus(connected=True, ssid="eduroam", bssid="02:00:00:00:00:01", profile_name="eduroam", rssi_dbm=-70)


def gate(**kw):
    cfg = SafetyConfig(**{"dry_run": False, "allowed_ssids": ("eduroam",), **kw})
    return SafetyGate(cfg, KillSwitch(None))


def test_dry_run_never_allows():
    g = SafetyGate(SafetyConfig(allowed_ssids=("eduroam",)), KillSwitch(None))
    assert g.config.dry_run
    d = g.check_roam(LINK, 0.0)
    assert not d.allowed and d.reason == "dry-run"


def test_allow_list_rules():
    assert not gate(allowed_ssids=()).check_roam(LINK, 0.0).allowed
    assert "not allow-listed" in gate(allowed_ssids=("other",)).check_roam(LINK, 0.0).reason
    assert not gate(allowed_profiles=("Other profile",)).check_roam(LINK, 0.0).allowed
    assert gate(allowed_profiles=("eduroam",)).check_roam(LINK, 0.0).allowed
    assert gate().check_roam(LINK, 0.0).allowed
    not_connected = LinkStatus(connected=False)
    assert not gate().check_roam(not_connected, 0.0).allowed


def test_kill_switch_file(tmp_path):
    path = tmp_path / "RoamPredict" / "KILL"
    ks = KillSwitch(path)
    assert not ks.active()
    ks.trip("testing")
    assert ks.active() and path.exists() and "testing" in ks.reason()
    ks.clear()
    assert not ks.active() and not path.exists()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("made by `roampredict kill`", encoding="utf-8")  # another process
    assert ks.active()
    g = SafetyGate(SafetyConfig(dry_run=False, allowed_ssids=("eduroam",)), ks)
    assert "kill switch" in g.check_roam(LINK, 0.0).reason


def test_rate_limiter():
    rl = RoamRateLimiter(min_interval_s=20, max_per_window=3, window_s=600)
    assert rl.check(0)[0]
    rl.record(0)
    assert not rl.check(10)[0]
    for t in (30, 60):
        assert rl.check(t)[0]
        rl.record(t)
    ok, why = rl.check(100)
    assert not ok and "3 switches" in why
    assert rl.check(631)[0]  # the first one left the window


def test_failures_trip_the_kill_switch():
    g = gate(max_consecutive_failures=2)
    g.record_result(False, "timeout")
    assert not g.kill_switch.active()
    g.record_result(True, "ok")
    g.record_result(False, "timeout")
    assert not g.kill_switch.active()  # success reset the counter
    g.record_result(False, "timeout")
    assert g.kill_switch.active()
    assert not g.check_roam(LINK, 0.0).allowed


def test_login_prompt_trips_immediately():
    g = gate()
    g.record_result(False, "802.1X stalled", login_prompt_suspected=True)
    assert g.kill_switch.active()
    assert "login prompt" in g.kill_switch.reason()


def test_config_validation():
    cfg = SafetyConfig(deny_bssids=("AA-BB-CC-DD-EE-02",))
    assert cfg.deny_bssids == ("aa:bb:cc:dd:ee:02",)
    with pytest.raises(ValidationError):
        SafetyConfig(deny_bssids=("ff:ff:ff:ff:ff:ff",))
    with pytest.raises(ValidationError):
        SafetyConfig(allowed_ssids=("",))
    with pytest.raises(ValueError):
        SafetyConfig(max_roams_per_window=0)
