import math

import pytest

from roampredict.signal.trend import TrendEstimate
from roampredict.state_machine import RoamState, RoamStateMachine, SignalSnapshot, StateMachineConfig


def snap(t, rssi, slope=0.0, falling=False, ttt=math.inf):
    trend = TrendEstimate(
        t=t,
        slope_dbm_s=slope,
        level_dbm=rssi,
        n=12,
        span_s=3.0,
        r2=0.9,
        slope_stderr=0.1 if falling else 10.0,
        valid=True,
        significant=falling,
    )
    return SignalSnapshot(t=t, smoothed_dbm=rssi, trend=trend, ttt_s=ttt)


def run(sm, t0, seconds, rssi, **kw):
    t = t0
    while t < t0 + seconds - 1e-9:
        sm.update(snap(t, rssi, **kw))
        t += 0.25
    return t


def test_strong_steady_signal_stays_stable():
    sm = RoamStateMachine()
    run(sm, 0.0, 30.0, -55.0)
    assert sm.state is RoamState.STABLE
    assert not sm.history


def test_single_sample_dip_is_ignored():
    sm = RoamStateMachine()
    t = run(sm, 0.0, 5.0, -55.0)
    sm.update(snap(t, -85.0))  # one bad sample (it would be past the threshold)
    run(sm, t + 0.25, 5.0, -55.0)
    assert sm.state is RoamState.STABLE


def test_steady_decline_escalates_before_crossing_the_threshold():
    sm = RoamStateMachine()
    seen = []
    t = 0.0
    rssi = -55.0
    while rssi > -80:
        ttt = (rssi + 75.0) / 2.0 if rssi > -75 else 0.0  # falling 2 dB/s
        state = sm.update(snap(t, rssi, slope=-2.0, falling=True, ttt=ttt))
        seen.append((state, rssi))
        t += 0.25
        rssi -= 0.5
    states = [s for s, _ in seen]
    assert RoamState.DEGRADING in states
    first_imminent = next(r for s, r in seen if s is RoamState.ROAM_IMMINENT)
    assert first_imminent > -75.0  # predicted, not reacted
    assert states.index(RoamState.DEGRADING) < states.index(RoamState.ROAM_IMMINENT)


def test_hysteresis_between_enter_and_exit():
    cfg = StateMachineConfig()
    sm = RoamStateMachine(cfg)
    t = run(sm, 0.0, 2.0, -68.0)  # below degrade_enter (-67)
    assert sm.state is RoamState.DEGRADING
    t = run(sm, t, 10.0, -65.0)  # between enter and exit: stay
    assert sm.state is RoamState.DEGRADING
    t = run(sm, t, 1.5, -62.0)  # above exit, but not for long enough yet
    assert sm.state is RoamState.DEGRADING
    run(sm, t, 1.0, -62.0)
    assert sm.state is RoamState.STABLE


def test_imminent_calms_down_only_with_margin_and_time():
    sm = RoamStateMachine()
    t = run(sm, 0.0, 1.0, -76.0)
    assert sm.state is RoamState.ROAM_IMMINENT
    t = run(sm, t, 5.0, -73.0)  # only 2 dB above the threshold: not calm
    assert sm.state is RoamState.ROAM_IMMINENT
    run(sm, t, 2.5, -70.0)
    assert sm.state is RoamState.DEGRADING


def test_roam_lifecycle_and_cooldown():
    cfg = StateMachineConfig(cooldown_s=20.0)
    sm = RoamStateMachine(cfg)
    with pytest.raises(RuntimeError):
        sm.begin_roam(0.0)
    t = run(sm, 0.0, 1.0, -78.0)
    assert sm.wants_roam
    sm.begin_roam(t)
    assert sm.state is RoamState.ROAMING
    run(sm, t, 3.0, -80.0)  # updates during ROAMING change nothing
    assert sm.state is RoamState.ROAMING
    sm.end_roam(t + 1.0, success=True)
    assert sm.state is RoamState.COOLDOWN
    t2 = run(sm, t + 1.0, 19.0, -80.0)  # bad signal, but still cooling down
    assert sm.state is RoamState.COOLDOWN
    run(sm, t2, 1.5, -80.0)
    assert sm.state is RoamState.ROAM_IMMINENT  # after cooldown it may act again


def test_failure_uses_the_longer_cooldown():
    sm = RoamStateMachine(StateMachineConfig(cooldown_s=10.0, failure_cooldown_s=60.0))
    t = run(sm, 0.0, 1.0, -78.0)
    sm.begin_roam(t)
    sm.end_roam(t, success=False, reason="test")
    assert sm.cooldown_until == pytest.approx(t + 60.0)
    with pytest.raises(RuntimeError):
        sm.end_roam(t, success=True)


def test_settle_after_windows_roamed():
    sm = RoamStateMachine(StateMachineConfig(external_roam_settle_s=5.0))
    t = run(sm, 0.0, 1.0, -70.0)
    sm.settle(t, "Windows roamed")
    assert sm.state is RoamState.COOLDOWN
    run(sm, t, 6.0, -55.0)
    assert sm.state is RoamState.STABLE


def test_settle_is_ignored_while_we_are_roaming():
    sm = RoamStateMachine()
    t = run(sm, 0.0, 1.0, -78.0)
    sm.begin_roam(t)
    sm.settle(t, "our own switch")
    assert sm.state is RoamState.ROAMING


def test_reset_and_history_callback():
    events = []
    sm = RoamStateMachine(on_transition=events.append)
    t = run(sm, 0.0, 1.0, -70.0)
    sm.reset(t, "link down")
    assert sm.state is RoamState.STABLE
    assert [(e.src, e.dst) for e in events] == [
        (RoamState.STABLE, RoamState.DEGRADING),
        (RoamState.DEGRADING, RoamState.STABLE),
    ]
    assert events[-1].reason == "link down"
    assert len(sm.history) == 2


def test_slope_margin_ignores_steps_far_above_threshold():
    sm = RoamStateMachine(StateMachineConfig(slope_trigger_margin_db=8.0))
    run(sm, 0.0, 2.0, -60.0, slope=-5.0, falling=True, ttt=3.0)  # 15 dB above: ignore slope
    assert sm.state is RoamState.STABLE
    sm2 = RoamStateMachine()
    run(sm2, 0.0, 2.0, -60.0, slope=-5.0, falling=True, ttt=3.0)
    assert sm2.state is RoamState.ROAM_IMMINENT


@pytest.mark.parametrize(
    "kwargs",
    [
        {"degrade_enter_dbm": -80.0},  # below the roam threshold
        {"degrade_exit_dbm": -70.0},  # below enter
        {"falling_slope_dbm_s": 0.5},
        {"imminent_lead_s": 20.0},
        {"cooldown_s": -1.0},
        {"slope_trigger_margin_db": 0.0},
    ],
)
def test_config_validation(kwargs):
    with pytest.raises(ValueError):
        StateMachineConfig(**kwargs)


def test_imminent_says_why():
    sm = RoamStateMachine()
    run(sm, 0.0, 1.0, -78.0)
    assert sm.state is RoamState.ROAM_IMMINENT
    assert sm.history[-1].reason.startswith("already below -75 dBm")
    fast = RoamStateMachine()
    run(fast, 0.0, 1.0, -62.0, slope=-6.0, falling=True, ttt=2.0)
    assert fast.state is RoamState.ROAM_IMMINENT
    assert fast.history[-1].reason.startswith("falling fast")
