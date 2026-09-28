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


def test_engine_config_validation():
    with pytest.raises(ValueError):
        EngineConfig(sample_hz=100)
    with pytest.raises(ValueError):
        EngineConfig(degrading_scan_interval_s=0)
