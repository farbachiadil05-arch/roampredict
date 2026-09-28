import math
import random

import pytest

from roampredict.signal.filter import EmaSmoother, FilterConfig, Kalman1D, SignalFilter, SpikeRejector


def feed(rejector, values):
    return [rejector.update(v) for v in values]


def test_single_dip_is_rejected():
    rej = SpikeRejector(window=5, threshold_db=6.0, confirm=2)
    out = feed(rej, [-60, -61, -60, -59, -60, -76, -60, -61])
    value, rejected = out[5]
    assert rejected
    assert value == pytest.approx(-60)
    assert not any(r for _, r in out[6:])


def test_real_step_is_accepted_after_confirmation():
    rej = SpikeRejector(window=5, threshold_db=6.0, confirm=2)
    out = feed(rej, [-60, -60, -61, -60, -75, -76, -75])
    assert out[4] == (pytest.approx(-60), True)  # first low reading held back
    assert out[5] == (-76, False)  # second one confirms the new level
    assert out[6] == (-75, False)


def test_opposite_outliers_do_not_confirm_each_other():
    rej = SpikeRejector(window=5, threshold_db=6.0, confirm=2)
    out = feed(rej, [-60, -60, -60, -60, -75, -45])
    assert out[4][1] and out[5][1]


def test_confirm_one_disables_rejection():
    rej = SpikeRejector(window=5, threshold_db=6.0, confirm=1)
    out = feed(rej, [-60, -60, -60, -80])
    assert out[3] == (-80, False)


def test_threshold_widens_with_noise():
    rej = SpikeRejector(window=5, threshold_db=6.0, mad_k=3.0)
    out = feed(rej, [-60, -55, -61, -56, -62])  # noisy but every reading accepted
    assert not any(r for _, r in out)
    # median -60, MAD 2 -> 3 * 1.4826 * 2 = 8.9 dB
    assert rej.threshold() == pytest.approx(3 * 1.4826 * 2)


def test_ema_reaches_63_percent_after_one_time_constant():
    ema = EmaSmoother(tau_s=1.0)
    ema.update(0.0, 0.0)
    value = 0.0
    for k in range(1, 5):
        value = ema.update(k * 0.25, 10.0)
    assert value == pytest.approx(10.0 * (1 - math.exp(-1.0)), rel=1e-6)


def test_ema_handles_uneven_spacing():
    a, b = EmaSmoother(1.0), EmaSmoother(1.0)
    a.update(0.0, 0.0)
    b.update(0.0, 0.0)
    for t in (0.5, 1.0):
        a.update(t, 10.0)
    b.update(1.0, 10.0)  # one late reading instead of two
    assert a.update(1.0, 10.0) == pytest.approx(b.update(1.0, 10.0))


def test_kalman_converges_and_gets_more_certain():
    rng = random.Random(1)
    kf = Kalman1D(process_var_per_s=0.5, meas_var=9.0)
    est = 0.0
    variances = []
    for k in range(200):
        est = kf.update(k * 0.25, -65.0 + rng.gauss(0, 3))
        variances.append(kf.variance)
    assert est == pytest.approx(-65.0, abs=1.5)
    assert variances[-1] < variances[1]


def test_filter_pipeline_and_gap_reset():
    f = SignalFilter(FilterConfig(smoother="ema", ema_tau_s=1.0, reset_gap_s=2.0))
    for k in range(20):
        s = f.update(k * 0.25, -55.0)
    assert s.smoothed == pytest.approx(-55.0)
    s = f.update(20 * 0.25, -80.0)  # single dip: rejected, smoothed barely moves
    assert s.rejected and s.smoothed == pytest.approx(-55.0)
    s = f.update(20.0, -80.0)  # after a long gap (new AP): accepted immediately
    assert not s.rejected and s.smoothed == -80.0


def test_kalman_mode_works():
    f = SignalFilter(FilterConfig(smoother="kalman"))
    for k in range(40):
        s = f.update(k * 0.25, -70.0)
    assert s.smoothed == pytest.approx(-70.0)


def test_filter_rejects_nan_and_bad_config():
    f = SignalFilter()
    with pytest.raises(ValueError):
        f.update(0.0, float("nan"))
    with pytest.raises(ValueError):
        FilterConfig(smoother="median")
    with pytest.raises(ValueError):
        FilterConfig(spike_confirm=9, spike_window=5)
    with pytest.raises(ValueError):
        FilterConfig(ema_tau_s=0)
