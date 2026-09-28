"""Run the comparison: 3 strategies x scenarios x random seeds (x 802.11r on/off).

    python -m simulator.run --seeds 20 --plot sim.png
    roampredict simulate --seeds 20 --plot sim.png      (same thing)

Every seed is one walk with its own shadowing, reading noise, hand dips and
"cached keys from earlier today".  All strategies of one seed see exactly the
same radio conditions.  RoamPredict's SQLite memory is kept across the seeds of
a scenario - like walking the same route every day - so the first walk is a
cold start and later walks use the learned "usual next AP".
"""

from __future__ import annotations

import argparse
import math
import random
import statistics
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from roampredict.topology.store import TopologyStore
from simulator.floorplan import FloorPlan, school_floor
from simulator.link_model import LinkModel
from simulator.radio import RadioParams, RadioWorld, compute_mean_rssi
from simulator.strategies import (
    DriverConfig,
    PredictiveStrategy,
    ReactiveStrategy,
    RoamRecord,
    RunContext,
    RunMetrics,
    SimDriver,
    ThresholdStrategy,
    compute_metrics,
)
from simulator.walker import SCENARIOS, Walker

__all__ = ["Trace", "Comparison", "SummaryRow", "run_comparison", "summarize", "format_table", "main"]

BASE_WALL = 1_760_000_000.0  # arbitrary epoch for the simulated calendar


@dataclass
class Trace:
    """One run, kept for plotting."""

    strategy: str
    label: str
    times: list[float]
    serving_rssi: list[float | None]
    serving: list[str | None]
    down: list[bool]
    roams: list[RoamRecord]


@dataclass
class Comparison:
    metrics: list[RunMetrics]
    traces: dict[tuple[str, bool], list[Trace]]
    labels: dict[str, str]
    link_model: LinkModel
    seeds: int
    plan: FloorPlan
    routes: dict[str, list[tuple[float, float]]] = field(default_factory=dict)


@dataclass(frozen=True)
class SummaryRow:
    scenario: str
    network_ft: bool
    strategy: str
    label: str
    n: int
    outage_mean: float
    outage_sd: float
    longest_mean: float
    roams_mean: float
    pingpong_mean: float
    pingpong_total: int
    reconnects_mean: float
    weak_mean: float


def default_strategies() -> list[ReactiveStrategy | ThresholdStrategy | PredictiveStrategy]:
    return [ReactiveStrategy(), ThresholdStrategy(), PredictiveStrategy()]


def initial_key_cache(plan: FloorPlan, seed: int, warm_prob: float = 0.5) -> dict[str, float]:
    """Which APs we already used earlier today (so a cached key may exist).

    Returns ``bssid -> time of that association`` in seconds relative to the
    start of the walk (negative = before the walk).
    """
    rng = random.Random(f"keys-{seed}")
    return {ap.bssid: -rng.uniform(0.5, 11.0) * 3600.0 for ap in plan.aps if rng.random() < warm_prob}


def _trace(driver: SimDriver, strategy: str, label: str, duration: float) -> Trace:
    times, rssi, serving, down = [], [], [], []
    floor = driver.link_model.link_floor_dbm
    t = 0.0
    while t <= duration:
        b = driver.bssid_at(t)
        value = None if b is None else driver.world.link_rssi(b, t)
        times.append(t)
        rssi.append(value)
        serving.append(b)
        down.append(b is None or driver.in_l3_gap(t) or (value is not None and value < floor))
        t += 0.1
    return Trace(strategy, label, times, rssi, serving, down, list(driver.roams))


def run_comparison(
    scenarios: Sequence[str] | None = None,
    seeds: int = 10,
    ft_modes: Sequence[bool] = (False, True),
    *,
    link_model: LinkModel | None = None,
    radio: RadioParams | None = None,
    driver_config: DriverConfig | None = None,
    strategies: Sequence[ReactiveStrategy | ThresholdStrategy | PredictiveStrategy] | None = None,
    progress: Callable[[str], None] | None = None,
) -> Comparison:
    scenarios = list(scenarios or SCENARIOS)
    link_model = link_model or LinkModel()
    radio = radio or RadioParams()
    driver_config = driver_config or DriverConfig()
    strategies = list(strategies or default_strategies())
    plan = school_floor()
    metrics: list[RunMetrics] = []
    traces: dict[tuple[str, bool], list[Trace]] = {}
    routes: dict[str, list[tuple[float, float]]] = {}

    for name in scenarios:
        scenario = SCENARIOS[name]
        walker = Walker(scenario.waypoints, scenario.speed_mps)
        routes[name] = [walker.position(k * 0.5) for k in range(int(walker.duration / 0.5) + 1)]
        mean = compute_mean_rssi(plan, walker, radio)
        for ft in ft_modes:
            store = TopologyStore(":memory:")
            for seed in range(seeds):
                if progress:
                    progress(f"{name} {'with' if ft else 'without'} 802.11r, walk {seed + 1}/{seeds}")
                world = RadioWorld(plan, walker, radio, seed=seed, mean_rssi=mean)
                keys = initial_key_cache(plan, seed)
                wall_base = BASE_WALL + seed * 86400.0 + (0.5 if ft else 0.0)
                for bssid, t_assoc in keys.items():
                    store.record_association(bssid, "eduroam", wall_base + t_assoc, "windows")
                ctx = RunContext(store=store, wall_base=wall_base)
                for strategy in strategies:
                    rng = random.Random(f"{name}-{ft}-{seed}-{strategy.name}")
                    driver = SimDriver(world, link_model, driver_config, rng, network_ft=ft, pmk_history=keys)
                    strategy.run(driver, world.walk_duration, ctx)
                    metrics.append(
                        compute_metrics(driver, world.walk_duration, scenario=name, seed=seed, strategy=strategy.name)
                    )
                    if seed == 0:
                        traces.setdefault((name, ft), []).append(
                            _trace(driver, strategy.name, strategy.label, world.walk_duration)
                        )
            store.close()
    return Comparison(
        metrics=metrics,
        traces=traces,
        labels={s.name: s.label for s in strategies},
        link_model=link_model,
        seeds=seeds,
        plan=plan,
        routes=routes,
    )


def _mean_sd(values: Sequence[float]) -> tuple[float, float]:
    if not values:
        return math.nan, math.nan
    return statistics.fmean(values), (statistics.stdev(values) if len(values) > 1 else 0.0)


def summarize(comparison: Comparison) -> list[SummaryRow]:
    groups: dict[tuple[str, bool, str], list[RunMetrics]] = {}
    for m in comparison.metrics:
        groups.setdefault((m.scenario, m.network_ft, m.strategy), []).append(m)
    rows = []
    for (scenario, ft, strategy), ms in groups.items():
        outage_mean, outage_sd = _mean_sd([m.outage_s for m in ms])
        rows.append(
            SummaryRow(
                scenario=scenario,
                network_ft=ft,
                strategy=strategy,
                label=comparison.labels.get(strategy, strategy),
                n=len(ms),
                outage_mean=outage_mean,
                outage_sd=outage_sd,
                longest_mean=statistics.fmean(m.longest_outage_s for m in ms),
                roams_mean=statistics.fmean(m.roams for m in ms),
                pingpong_mean=statistics.fmean(m.pingpongs for m in ms),
                pingpong_total=sum(m.pingpongs for m in ms),
                reconnects_mean=statistics.fmean(m.reconnects for m in ms),
                weak_mean=statistics.fmean(m.weak_s for m in ms),
            )
        )
    return rows


def format_table(comparison: Comparison) -> str:
    rows = summarize(comparison)
    lines = ["Assumptions (replace with your own measurements):"]
    lines += [f"  - {line}" for line in comparison.link_model.describe()]
    lines.append(f"  - {comparison.seeds} random walks per scenario; mean +/- standard deviation")
    lines.append("  - outage: link unusable (switching, reconnecting, or below the floor); weak: usable but below -75 dBm")
    for (scenario, ft) in sorted({(r.scenario, r.network_ft) for r in rows}, key=lambda k: (list(SCENARIOS).index(k[0]), k[1])):
        lines.append("")
        lines.append(f"{scenario} - {SCENARIOS[scenario].description}")
        lines.append(f"network {'WITH' if ft else 'WITHOUT'} 802.11r")
        header = f"  {'strategy':<36}{'outage (s)':>16}{'longest (s)':>13}{'roams':>8}{'ping-pong':>11}{'weak (s)':>10}"
        lines.append(header)
        lines.append("  " + "-" * (len(header) - 2))
        for r in sorted((r for r in rows if r.scenario == scenario and r.network_ft == ft), key=lambda r: list(comparison.labels).index(r.strategy)):
            lines.append(
                f"  {r.label:<36}{r.outage_mean:>9.2f} +/-{r.outage_sd:>4.2f}{r.longest_mean:>13.2f}"
                f"{r.roams_mean:>8.2f}{r.pingpong_mean:>11.2f}{r.weak_mean:>10.1f}"
            )
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="simulator.run", description="Compare roaming strategies in a simulated school.")
    parser.add_argument("--seeds", type=int, default=10, help="random walks per scenario (default 10)")
    parser.add_argument("--scenario", action="append", choices=sorted(SCENARIOS), help="limit to a scenario (repeatable)")
    parser.add_argument("--ft", choices=("both", "on", "off"), default="both", help="802.11r on the simulated network")
    parser.add_argument("--plot", default="roampredict_sim.png", help="output PNG (default roampredict_sim.png)")
    parser.add_argument("--no-plot", action="store_true", help="skip the matplotlib figure")
    args = parser.parse_args(argv)
    if args.seeds < 1:
        parser.error("--seeds must be >= 1")
    ft_modes = {"both": (False, True), "on": (True,), "off": (False,)}[args.ft]

    def progress(msg: str) -> None:
        sys.stderr.write(f"\r  simulating: {msg:<60}")
        sys.stderr.flush()

    comparison = run_comparison(args.scenario, args.seeds, ft_modes, progress=progress)
    sys.stderr.write("\r" + " " * 80 + "\r")
    print(format_table(comparison))
    if not args.no_plot:
        try:
            from simulator.plot import plot_comparison
        except ImportError as exc:  # matplotlib missing
            print(f"\n(no plot: {exc}; install with: pip install matplotlib)")
        else:
            path = plot_comparison(comparison, args.plot)
            print(f"\nPlot saved to {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
