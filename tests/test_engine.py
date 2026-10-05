"""The control loop end to end, on a scripted radio with virtual time."""

import pytest

from roampredict.engine import Engine, EngineConfig
from roampredict.platform.mock import MockNetworkOps, MockWlanAdapter, ScriptedAp, ScriptedRadio
from roampredict.roam.executor import ExecutorConfig, RoamExecutor
from roampredict.safety import KillSwitch, SafetyConfig, SafetyGate
from roampredict.telemetry import Telemetry
from roampredict.topology.predictor import Predictor
from roampredict.topology.store import TopologyStore

AP1 = "02:00:00:00:00:01"
AP2 = "02:00:00:00:00:02"
AP3 = "02:00:00:00:00:03"
WALL0 = 1_700_000_000.0


def falling(t):
    """-55 dBm, then -3 dB/s from t=5 s: crosses -75 at t = 11.67 s."""
    return -55.0 if t < 5 else -55.0 - 3.0 * (t - 5)


CROSSING_T = 5 + 20 / 3


def build(aps, *, dry_run=False, allowed=("testnet",), store=None, kill=None, engine_config=None):
    radio = ScriptedRadio(aps, connected_to=aps[0].bssid, scan_duration_s=1.0)
    adapter = MockWlanAdapter(radio)
    net = MockNetworkOps()
    tel = Telemetry(console=False, keep_in_memory=True)
    store = store or TopologyStore(":memory:")
    safety = SafetyGate(SafetyConfig(dry_run=dry_run, allowed_ssids=allowed), kill or KillSwitch(None))
    engine = Engine(
        adapter=adapter,
        net=net,
        store=store,
        predictor=Predictor(store),
        executor=RoamExecutor(adapter, net, ExecutorConfig(), tel),
        safety=safety,
        telemetry=tel,
        config=engine_config,
        wall_clock=lambda: WALL0 + radio.now(),
    )
    switch_times = []
    original = adapter.connect_bssid

    def recording_connect(*args, **kwargs):
        switch_times.append(radio.now())
        return original(*args, **kwargs)

    adapter.connect_bssid = recording_connect
    return radio, adapter, engine, tel, store, switch_times


def ticks(engine, adapter, seconds, on_tick=None):
    end = adapter.now() + seconds
    while adapter.now() < end - 1e-9:
        engine.tick()
        if on_tick:
            on_tick(adapter.now())
        adapter.sleep(0.25)


def kinds(tel, kind):
    return [e for e in tel.events() if e["kind"] == kind]


def test_active_mode_switches_before_the_signal_crosses_the_threshold():
    radio, adapter, engine, tel, store, times = build([ScriptedAp(AP1, falling), ScriptedAp(AP2, -50.0)])
    engine.run(duration_s=20.0)
    assert adapter.connect_calls == [("testnet", AP2)]
    assert len(times) == 1 and times[0] < CROSSING_T
    assert falling(times[0]) > -75.0  # acted on the prediction
    assert engine.switches_ok == 1
    sw = store.switches()
    assert sw[0].initiator == "roampredict" and sw[0].success and sw[0].to_bssid == AP2
    assert store.last_association(AP2) is not None
    assert kinds(tel, "decision") and kinds(tel, "switch_result")[0]["success"] is True


def test_dry_run_logs_once_and_checks_the_prediction_against_windows():
    radio, adapter, engine, tel, store, times = build([ScriptedAp(AP1, falling), ScriptedAp(AP2, -50.0)], dry_run=True)

    def windows_roams_at_13s(t):
        if t >= 13.0 and radio.current == AP1:
            radio.current = AP2

    ticks(engine, adapter, 16.0, windows_roams_at_13s)
    assert adapter.connect_calls == []
    assert len(kinds(tel, "would_switch")) == 1
    check = kinds(tel, "prediction_check")
    assert check and check[0]["hit"] is True and check[0]["lead_s"] > 0
    assert kinds(tel, "windows_roam")
    windows = [s for s in store.switches() if s.initiator == "windows"]
    assert windows and windows[0].detail["hit"] is True


def test_learning_skips_short_visits():
    aps = [ScriptedAp(AP1, -60.0), ScriptedAp(AP2, -58.0), ScriptedAp(AP3, -55.0)]
    radio, adapter, engine, tel, store, _ = build(aps)
    ticks(engine, adapter, 12.0)  # stay on AP1
    radio.current = AP2
    ticks(engine, adapter, 3.0)  # a short detour
    radio.current = AP3
    ticks(engine, adapter, 5.0)
    assert store.transition_counts(AP1) == {}  # not confirmed yet
    ticks(engine, adapter, 6.0)
    assert store.transition_counts(AP1) == {AP3: 1}
    assert store.transition_counts(AP2) == {}
    assert store.last_association(AP2) is not None  # the key-cache record is still kept


def test_kill_switch_blocks_switching():
    kill = KillSwitch(None)
    kill.trip("user pressed kill")
    radio, adapter, engine, tel, store, _ = build([ScriptedAp(AP1, falling), ScriptedAp(AP2, -50.0)], kill=kill)
    engine.run(duration_s=15.0)
    assert adapter.connect_calls == []
    assert kinds(tel, "kill_switch")
    assert "kill switch" in kinds(tel, "would_switch")[0]["gate"]


def test_not_allow_listed_network_is_only_observed():
    radio, adapter, engine, tel, store, _ = build([ScriptedAp(AP1, falling), ScriptedAp(AP2, -50.0)], allowed=("other",))
    engine.run(duration_s=15.0)
    assert adapter.connect_calls == []
    assert "not allow-listed" in kinds(tel, "would_switch")[0]["gate"]
    assert any("not acting on this network" in e["msg"] for e in kinds(tel, "warning"))


def test_short_disconnect_to_another_ap_counts_as_a_windows_roam():
    radio, adapter, engine, tel, store, _ = build([ScriptedAp(AP1, -60.0), ScriptedAp(AP2, -55.0)])
    ticks(engine, adapter, 3.0)
    radio.current = None
    ticks(engine, adapter, 2.0)
    radio.current = AP2
    ticks(engine, adapter, 1.0)
    roams = kinds(tel, "windows_roam")
    assert roams and roams[0]["dst"] == AP2


def test_waits_for_the_usual_next_ap_then_uses_it():
    store = TopologyStore(":memory:")
    for _ in range(5):
        store.record_transition(AP1, AP3, WALL0 - 86400)
    aps = [ScriptedAp(AP1, falling), ScriptedAp(AP2, -50.0), ScriptedAp(AP3, -62.0)]
    radio, adapter, engine, tel, store, times = build(aps, store=store)
    engine.run(duration_s=20.0)
    assert kinds(tel, "waiting")  # AP2 was already +8 dB but AP3 is where we usually go
    assert adapter.connect_calls == [("testnet", AP3)]
    assert times[0] < CROSSING_T


def test_waiting_can_be_turned_off():
    store = TopologyStore(":memory:")
    for _ in range(5):
        store.record_transition(AP1, AP3, WALL0 - 86400)
    aps = [ScriptedAp(AP1, falling), ScriptedAp(AP2, -50.0), ScriptedAp(AP3, -62.0)]
    radio, adapter, engine, tel, store, _ = build(aps, store=store, engine_config=EngineConfig(defer_to_learned=False))
    engine.run(duration_s=20.0)
    assert not kinds(tel, "waiting")
    assert adapter.connect_calls == [("testnet", AP2)]


def test_repeated_errors_are_reported_once_then_the_loop_stops():
    from roampredict.platform.base import WlanPermissionError

    radio, adapter, engine, tel, store, _ = build(
        [ScriptedAp(AP1, -60.0)], engine_config=EngineConfig(max_consecutive_errors=8)
    )

    def denied():
        raise WlanPermissionError("access denied (Location)")

    adapter.link_status = denied
    engine.run(duration_s=60.0)
    errors = kinds(tel, "error")
    assert len(errors) == 2  # the error once, then "8 errors in a row - stopping"
    assert "8 errors in a row" in errors[-1]["msg"]
    assert radio.now() < 5.0  # stopped early instead of spinning for 60 s


def test_engine_config_validation():
    with pytest.raises(ValueError):
        EngineConfig(sample_hz=100)
    with pytest.raises(ValueError):
        EngineConfig(degrading_scan_interval_s=0)


def test_link_loss_is_timed_and_stored_with_the_signal_before_it():
    radio, adapter, engine, tel, store, _ = build([ScriptedAp(AP1, -66.0), ScriptedAp(AP2, -55.0)], dry_run=True)
    ticks(engine, adapter, 4.0)
    radio.current = None
    ticks(engine, adapter, 3.0)
    radio.current = AP1
    ticks(engine, adapter, 1.0)
    down = kinds(tel, "link_down")
    assert len(down) == 1 and "lost at" in down[0]["msg"]
    assert "just before: -66.0 dBm" in down[0]["msg"] and down[0]["readings"][-1] == -66
    back = [e for e in kinds(tel, "connected") if e.get("outage_s") is not None]
    assert back and back[0]["outage_s"] == pytest.approx(3.0) and "after 3.0 s without Wi-Fi" in back[0]["msg"]
    [outage] = store.outages()
    assert outage.layer == "wifi" and outage.mode == "dry-run"
    assert outage.duration_ms == pytest.approx(3000.0) and outage.started_at == pytest.approx(WALL0 + 4.0)
    assert outage.last_rssi == pytest.approx(-66.0) and outage.from_bssid == AP1 and outage.to_bssid == AP1
    assert engine.session_summary() == "Wi-Fi link lost 1x, 3.0 s in total (longest 3.0 s)"


def test_a_roam_after_a_gap_reports_the_gap():
    radio, adapter, engine, tel, store, _ = build([ScriptedAp(AP1, -60.0), ScriptedAp(AP2, -55.0)])
    ticks(engine, adapter, 3.0)
    radio.current = None
    ticks(engine, adapter, 1.5)
    radio.current = AP2
    ticks(engine, adapter, 1.0)
    [roam] = kinds(tel, "windows_roam")
    assert "after 1.5 s without Wi-Fi" in roam["msg"]
    windows = [s for s in store.switches() if s.initiator == "windows"]
    assert windows[0].total_ms == pytest.approx(1500.0) and windows[0].detail["measured"] == "link down time"
    assert store.outages()[0].to_bssid == AP2


def test_stopping_during_an_outage_still_counts_it():
    radio, adapter, engine, tel, store, _ = build([ScriptedAp(AP1, -60.0)], dry_run=True)
    engine.run(duration_s=2.0)
    radio.current = None
    engine.run(duration_s=3.0)  # the user presses Ctrl+C while still disconnected
    [outage] = store.outages()
    assert outage.detail["ongoing"] is True and outage.duration_ms == pytest.approx(3000.0, abs=300)
    assert "stopped while the Wi-Fi link was down" in kinds(tel, "link_down")[-1]["msg"]
    assert "Wi-Fi link lost 1x" in kinds(tel, "stop")[-1]["msg"]


def test_own_switch_counts_as_an_outage_from_the_request():
    radio, adapter, engine, tel, store, _ = build([ScriptedAp(AP1, falling), ScriptedAp(AP2, -50.0)])
    engine.run(duration_s=20.0)
    assert engine.switches_ok == 1
    [outage] = store.outages()
    result = kinds(tel, "switch_result")[0]
    assert outage.mode == "active" and outage.detail["initiator"] == "roampredict"
    assert outage.duration_ms == pytest.approx(result["total_ms"]) and outage.to_bssid == AP2
    assert outage.detail["state"] == "ROAM_IMMINENT"


def test_windows_failed_attempts_show_the_reason_code_and_stage():
    from roampredict.platform.base import WlanEventKind

    radio, adapter, engine, tel, store, _ = build([ScriptedAp(AP1, -60.0)], dry_run=True)
    radio._emit(WlanEventKind.CONNECTION_FAILED, reason_code=0x4800F)
    radio._emit(WlanEventKind.CONNECTION_FAILED, reason_code=0x38002)
    engine.tick()
    msgs = [e["msg"] for e in kinds(tel, "warning")]
    assert any("reason 0x4800f" in m and "802.1X/security step" in m for m in msgs)
    assert any("reason 0x38002" in m and "802.1X" not in m for m in msgs)


class FakeProbe:
    label = "example.org:443"

    def __init__(self, events, final=()):
        self.events = list(events)
        self.final = list(final)
        self.started = False

    def start(self):
        self.started = True

    def poll(self):
        out, self.events = self.events, []
        return out

    def stop(self):
        return self.final


def test_internet_probe_outages_are_logged_and_stored():
    from roampredict.net.probe import Outage, ProbeEvent

    store = TopologyStore(":memory:")
    lost = Outage(WALL0 + 1.0, 7.4, 30)
    probe = FakeProbe(
        [ProbeEvent("down", Outage(WALL0 + 1.0, 0.5, 2, ongoing=True)), ProbeEvent("up", lost)],
        final=[ProbeEvent("end", Outage(WALL0 + 9.0, 1.0, 4, ongoing=True))],
    )
    radio, adapter, engine, tel, store, _ = build([ScriptedAp(AP1, -60.0)], dry_run=True, store=store)
    engine.probe = probe
    engine.run(duration_s=1.0)
    assert probe.started
    assert "no answer from example.org:443 since" in kinds(tel, "net_down")[0]["msg"]
    ups = kinds(tel, "net_up")
    assert "after 7.4 s" in ups[0]["msg"] and "stopped while the internet was not answering" in ups[1]["msg"]
    internet = sorted((o for o in store.outages() if o.layer == "internet"), key=lambda o: o.started_at)
    assert [o.duration_ms for o in internet] == [pytest.approx(7400.0), pytest.approx(1000.0)]
    assert internet[0].detail == {"target": "example.org:443", "lost": 30, "ongoing": False}
    assert "internet lost 2x, 8.4 s in total (longest 7.4 s)" in kinds(tel, "stop")[0]["msg"]
