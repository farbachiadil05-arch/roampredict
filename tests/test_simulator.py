"""The simulator: geometry, radio model, driver model and the comparison."""

import random

import pytest

from simulator.floorplan import school_floor, segments_intersect
from simulator.link_model import LinkModel
from simulator.radio import RadioParams, RadioWorld, compute_mean_rssi
from simulator.run import format_table, run_comparison, summarize
from simulator.strategies import DriverConfig, ReactiveStrategy, RunContext, SimDriver, compute_metrics
from simulator.walker import SCENARIOS, Walker, Waypoint
from roampredict.topology.store import TopologyStore


def test_segments_intersect():
    assert segments_intersect((0, 0), (2, 2), (0, 2), (2, 0))
    assert not segments_intersect((0, 0), (1, 0), (0, 1), (1, 1))
    assert segments_intersect((0, 0), (2, 0), (1, 0), (1, 1))  # touching counts


def test_walls_attenuate():
    plan = school_floor()
    assert plan.wall_loss(5, 15, 7, 17) == 0.0  # same room
    assert plan.wall_loss(5, 15, 5, 10) == 12.0  # through the hallway wall
    assert plan.wall_loss(10, 15, 20, 15) == 16.0  # into the next classroom


def test_walker_timing():
    w = Walker([Waypoint(0, 0, pause_s=5), Waypoint(13, 0, pause_s=2)], speed_mps=1.3)
    assert w.duration == pytest.approx(17.0)
    assert w.position(2) == (0, 0)
    assert w.position(10) == pytest.approx((6.5, 0.0))
    assert w.position(100) == (13, 0)
    assert w.speed(10) == pytest.approx(1.3) and w.speed(1) == 0.0


def test_radio_world_is_deterministic_per_seed():
    plan = school_floor()
    walker = Walker(SCENARIOS["walk_out"].waypoints)
    params = RadioParams()
    mean = compute_mean_rssi(plan, walker, params)
    a = RadioWorld(plan, walker, params, seed=1, mean_rssi=mean)
    b = RadioWorld(plan, walker, params, seed=1, mean_rssi=mean)
    c = RadioWorld(plan, walker, params, seed=2, mean_rssi=mean)
    bssid = plan.aps[0].bssid
    series_a = [a.measured_rssi(bssid, t / 4) for t in range(200)]
    assert series_a == [b.measured_rssi(bssid, t / 4) for t in range(200)]
    assert series_a != [c.measured_rssi(bssid, t / 4) for t in range(200)]
    assert all(float(v).is_integer() for v in series_a)  # Windows reports whole dBm


def test_link_model_assumptions():
    lm = LinkModel()
    rng = random.Random(0)
    assert lm.pmk_valid(-3600.0, 0.0) and not lm.pmk_valid(-9 * 3600.0, 0.0) and not lm.pmk_valid(None, 0.0)
    parts = lm.app_switch(rng, ft_available=True, pmk_cached=False)
    assert parts.auth_kind == "full_eap"  # WlanConnect is assumed not to use 802.11r
    assert parts.total_s == pytest.approx(parts.disconnect_s + parts.assoc_s + parts.auth_s + parts.dhcp_s)
    assert lm.driver_roam(rng, ft_available=True, pmk_cached=False).auth_kind == "ft"
    assert lm.driver_roam(rng, ft_available=False, pmk_cached=True).auth_kind == "pmk_cache"


def test_reactive_driver_roams_on_its_own():
    plan = school_floor()
    walker = Walker(SCENARIOS["walk_out"].waypoints)
    world = RadioWorld(plan, walker, RadioParams(), seed=0)
    driver = SimDriver(world, LinkModel(), DriverConfig(), random.Random(0))
    ReactiveStrategy().run(driver, world.walk_duration, RunContext(TopologyStore(":memory:"), 0.0))
    assert driver.roams, "the simulated Windows must roam by itself"
    segs = driver.segments
    assert segs[0].t0 == 0.0 and segs[-1].t1 == pytest.approx(world.walk_duration)
    assert all(a.t1 == pytest.approx(b.t0) for a, b in zip(segs, segs[1:]))  # no holes in the timeline
    m = compute_metrics(driver, world.walk_duration, scenario="walk_out", seed=0, strategy="reactive")
    assert m.roams >= 1 and m.outage_s > 0


def test_comparison_is_deterministic():
    a = run_comparison(["corner_seat"], seeds=2, ft_modes=(False,))
    b = run_comparison(["corner_seat"], seeds=2, ft_modes=(False,))
    assert a.metrics == b.metrics
    assert len(a.metrics) == 2 * 3
    table = format_table(a)
    table.encode("ascii")
    for label in a.labels.values():
        assert label in table


def test_predictive_beats_the_baselines_where_it_should():
    """Robust claims only (10 walks): fewer ping-pongs than the naive threshold
    in the weak corner, and less outage than Windows alone walking out of class."""
    rows = {(r.scenario, r.strategy): r for r in summarize(run_comparison(["walk_out", "corner_seat"], seeds=10, ft_modes=(False,)))}
    assert rows[("corner_seat", "predictive")].pingpong_total < rows[("corner_seat", "threshold")].pingpong_total
    assert rows[("walk_out", "predictive")].outage_mean < rows[("walk_out", "reactive")].outage_mean


def test_plot_is_written(tmp_path):
    pytest.importorskip("matplotlib")
    from simulator.plot import plot_comparison

    comparison = run_comparison(["walk_out"], seeds=1, ft_modes=(False,))
    path = plot_comparison(comparison, tmp_path / "sim.png")
    assert path.exists() and path.stat().st_size > 10_000
