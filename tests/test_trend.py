"""Slope math: least squares, sliding window, time-to-threshold."""

import math
import random

import pytest

from roampredict.signal.filter import SignalFilter
from roampredict.signal.trend import SlidingRegression, TrendConfig, linear_fit, time_to_threshold


def test_exact_line_is_recovered():
    ts = [0.0, 0.25, 0.5, 0.75, 1.0, 1.25]
    ys = [-50.0 - 3.0 * t for t in ts]
    fit = linear_fit(ts, ys)
    assert fit.slope == pytest.approx(-3.0)
    assert fit.value_at(1.25) == pytest.approx(-53.75)
    assert fit.r2 == pytest.approx(1.0)
    assert fit.slope_stderr == pytest.approx(0.0, abs=1e-9)


def test_irregular_timestamps():
    ts = [0.0, 0.1, 0.35, 0.9, 1.0, 1.7]
    fit = linear_fit(ts, [-40.0 - 2.0 * t for t in ts])
    assert fit.slope == pytest.approx(-2.0)


def test_matches_textbook_formula():
    rng = random.Random(7)
    ts = [k * 0.25 + rng.uniform(-0.05, 0.05) for k in range(12)]
    ys = [-60 + rng.gauss(0, 4) for _ in ts]
    n = len(ts)
    st, sy = sum(ts), sum(ys)
    stt = sum(t * t for t in ts)
    sty = sum(t * y for t, y in zip(ts, ys))
    expected = (n * sty - st * sy) / (n * stt - st * st)
    assert linear_fit(ts, ys).slope == pytest.approx(expected, rel=1e-9)


def test_large_timestamps_are_numerically_stable():
    base = 1.7e9  # UNIX time: centring keeps this exact
    ts = [base + k * 0.25 for k in range(12)]
    fit = linear_fit(ts, [-50.0 - 1.5 * (t - base) for t in ts])
    assert fit.slope == pytest.approx(-1.5, rel=1e-6)


def test_noisy_slope_and_its_standard_error():
    rng = random.Random(3)
    slopes = []
    stderrs = []
    for _ in range(300):
        ts = [k * 0.25 for k in range(13)]  # 3 s at 4 Hz
        fit = linear_fit(ts, [-60 - 3.0 * t + rng.gauss(0, 2.0) for t in ts])
        slopes.append(fit.slope)
        stderrs.append(fit.slope_stderr)
    mean = sum(slopes) / len(slopes)
    spread = math.sqrt(sum((s - mean) ** 2 for s in slopes) / (len(slopes) - 1))
    assert mean == pytest.approx(-3.0, abs=0.15)
    # The reported standard error should describe the real spread of the estimate.
    assert sum(stderrs) / len(stderrs) == pytest.approx(spread, rel=0.25)


def test_bad_input():
    with pytest.raises(ValueError):
        linear_fit([0.0], [1.0])
    with pytest.raises(ValueError):
        linear_fit([0.0, 1.0], [1.0])
    with pytest.raises(ValueError):
        linear_fit([1.0, 1.0, 1.0], [1.0, 2.0, 3.0])


def test_window_keeps_only_recent_points():
    reg = SlidingRegression(TrendConfig(window_s=3.0))
    for k in range(40):  # 10 s: flat until 6.5 s, then falling 4 dB/s
        t = k * 0.25
        reg.add(t, -50.0 if t < 6.5 else -50.0 - 4.0 * (t - 6.5))
    est = reg.estimate()
    assert len(reg) == 13  # 6.75 s .. 9.75 s
    assert est.slope_dbm_s == pytest.approx(-4.0)
    assert est.level_dbm == pytest.approx(-50 - 4 * 3.25)
    assert est.valid and est.significant and est.falling


def test_validity_and_significance():
    reg = SlidingRegression(TrendConfig(window_s=3.0, min_points=6))
    for k in range(3):
        reg.add(k * 0.25, -60.0)
    assert not reg.estimate().valid
    rng = random.Random(5)
    for k in range(3, 20):
        reg.add(k * 0.25, -60.0 + rng.gauss(0, 2))
    est = reg.estimate()
    assert est.valid
    assert not est.falling  # noise around a flat line is not a trend


def test_time_going_backwards_restarts_the_window():
    reg = SlidingRegression()
    for k in range(10):
        reg.add(10 + k * 0.25, -60.0)
    reg.add(1.0, -70.0)
    assert len(reg) == 1


@pytest.mark.parametrize(
    "level, slope, threshold, expected",
    [
        (-60.0, -3.0, -75.0, 5.0),
        (-74.0, -0.5, -75.0, 2.0),
        (-75.0, -3.0, -75.0, 0.0),  # already there
        (-80.0, +2.0, -75.0, 0.0),  # already below
        (-60.0, 0.0, -75.0, math.inf),  # flat
        (-60.0, +1.0, -75.0, math.inf),  # rising
        (float("nan"), -1.0, -75.0, math.inf),
    ],
)
def test_time_to_threshold(level, slope, threshold, expected):
    assert time_to_threshold(level, slope, threshold) == pytest.approx(expected)


def test_prediction_through_the_whole_pipeline():
    """-2.5 dB/s decline with reading noise and one hand dip: 4 s before the
    crossing, the predicted time-to-threshold must be close to the truth."""
    rng = random.Random(11)
    filt = SignalFilter()
    reg = SlidingRegression()
    crossing_t = 10.0  # -50 - 2.5 * (t - 0) reaches -75 at t = 10
    est = None
    for k in range(25):  # up to t = 6 s
        t = k * 0.25
        reading = round(-50.0 - 2.5 * t + rng.gauss(0, 1.5))
        if k == 18:
            reading -= 14  # hand over the antenna
        sample = filt.update(t, reading)
        reg.add(t, sample.despiked)
        est = reg.estimate()
    assert est is not None and est.falling
    ttt = time_to_threshold(est.level_dbm, est.slope_dbm_s, -75.0)
    assert ttt == pytest.approx(crossing_t - 6.0, abs=1.0)
