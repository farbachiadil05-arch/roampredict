"""Matplotlib figure for the simulator comparison (static PNG).

Top row: one example walk per strategy - the signal of the AP you are connected
to, with red bands where the link was down.  Below: outage, roams and ping-pong
per scenario, for a network without and with 802.11r.  The exact numbers (the
"table view" of this figure) are printed by ``simulator.run``.
"""

from __future__ import annotations

import statistics
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # no display needed
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402
from matplotlib.patches import Patch  # noqa: E402

from simulator.run import Comparison, Trace  # noqa: E402
from simulator.walker import SCENARIOS  # noqa: E402

__all__ = ["plot_comparison", "STRATEGY_COLORS"]

SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_2 = "#52514e"
MUTED = "#898781"
GRID = "#e1e0d9"
BASELINE = "#c3c2b7"
CRITICAL = "#d03b3b"  # status color: link down
# Fixed per strategy (validated categorical slots 1-3; colour follows the strategy).
STRATEGY_COLORS = {"predictive": "#2a78d6", "reactive": "#eb6834", "threshold": "#1baf7a"}
FALLBACK_COLOR = "#898781"

METRICS = (
    ("outage_s", "Outage per walk (s)"),
    ("roams", "Roams per walk"),
    ("pingpongs", "Ping-pong roams per walk"),
)


def _style(ax: plt.Axes) -> None:
    ax.set_facecolor(SURFACE)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(BASELINE)
        ax.spines[side].set_linewidth(0.8)
    ax.tick_params(colors=MUTED, labelcolor=INK_2, labelsize=8, length=0)
    ax.grid(axis="y", color=GRID, linewidth=0.6, linestyle="-")
    ax.set_axisbelow(True)


def _short_ap(name: str) -> str:
    return name.replace("AP-", "")


def _plot_trace(ax: plt.Axes, trace: Trace, names: dict[str, str], floor_dbm: float, roam_dbm: float) -> None:
    color = STRATEGY_COLORS.get(trace.strategy, FALLBACK_COLOR)
    t = trace.times
    y = [float("nan") if v is None else v for v in trace.serving_rssi]
    ax.plot(t, y, color=color, linewidth=1.5, solid_capstyle="round", solid_joinstyle="round", zorder=3)

    # Link-down bands.
    start = None
    for i, down in enumerate(trace.down + [False]):
        if down and start is None:
            start = t[i]
        elif not down and start is not None:
            end = t[min(i, len(t) - 1)]
            ax.axvspan(start, end, color=CRITICAL, alpha=0.14, linewidth=0, zorder=1)
            start = None

    # Reference lines, labelled directly (solid hairlines, not dashed).
    x_end = t[-1] if t else 1.0
    for level, text in ((roam_dbm, f"roam threshold {roam_dbm:.0f}"), (floor_dbm, f"link floor {floor_dbm:.0f}")):
        ax.axhline(level, color=BASELINE, linewidth=0.8, zorder=2)
        ax.text(x_end, level + 0.8, text, ha="right", va="bottom", fontsize=7, color=MUTED)

    # Label which AP we are on, once per connection.
    last = None
    for ti, value, bssid in zip(t, y, trace.serving):
        if bssid is not None and bssid != last and value == value:  # value == value: not NaN
            ax.text(ti, min(value + 3.0, -24.0), _short_ap(names.get(bssid, bssid[-5:])), fontsize=8, color=INK_2, ha="left", va="bottom")
        if bssid is not None:
            last = bssid
    ax.set_ylim(-97, -20)
    ax.set_xlim(0, x_end)
    ax.set_xlabel("time (s)", fontsize=8, color=INK_2)


def plot_comparison(comparison: Comparison, path: str | Path) -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    scenarios = [s for s in SCENARIOS if any(m.scenario == s for m in comparison.metrics)]
    ft_modes = sorted({m.network_ft for m in comparison.metrics})
    strategies = list(comparison.labels)
    names = {ap.bssid: ap.name for ap in comparison.plan.aps}
    floor = comparison.link_model.link_floor_dbm

    fig = plt.figure(figsize=(15, 4.2 + 3.3 * len(ft_modes)), dpi=120, facecolor=SURFACE, layout="constrained")
    grid = fig.add_gridspec(1 + len(ft_modes), 3, height_ratios=[1.25] + [1.0] * len(ft_modes))

    # -- example walk ------------------------------------------------------------------
    key = (scenarios[0], ft_modes[0]) if scenarios else None
    traces = comparison.traces.get(key, []) if key else []
    by_strategy = {m.strategy: m for m in comparison.metrics if key and m.scenario == key[0] and m.network_ft == key[1] and m.seed == 0}
    for i, trace in enumerate(traces[:3]):
        ax = fig.add_subplot(grid[0, i])
        _style(ax)
        _plot_trace(ax, trace, names, floor, -75.0)
        m = by_strategy.get(trace.strategy)
        detail = f"outage {m.outage_s:.1f} s, {m.roams} roams" if m else ""
        ax.set_title(f"{trace.label}\n{detail}", fontsize=9, color=INK, loc="left")
        if i == 0:
            ax.set_ylabel("signal of the connected AP (dBm)", fontsize=8, color=INK_2)
    if key:
        net = "with" if key[1] else "without"
        fig.text(
            0.005,
            1.0,
            f"Example walk: {key[0]} ({net} 802.11r), walk #1 - "
            f"{SCENARIOS[key[0]].description}",
            fontsize=10,
            color=INK,
            ha="left",
            va="bottom",
        )

    # -- comparison bars -----------------------------------------------------------------
    width = 0.14
    step = width + 0.012  # thin bars with a small surface gap between neighbours
    for row, ft in enumerate(ft_modes, start=1):
        for col, (field, title) in enumerate(METRICS):
            ax = fig.add_subplot(grid[row, col])
            _style(ax)
            for k, strategy in enumerate(strategies):
                xs, means, sds = [], [], []
                for g, scenario in enumerate(scenarios):
                    values = [
                        float(getattr(m, field))
                        for m in comparison.metrics
                        if m.scenario == scenario and m.network_ft == ft and m.strategy == strategy
                    ]
                    if not values:
                        continue
                    xs.append(g + (k - (len(strategies) - 1) / 2) * step)
                    means.append(statistics.fmean(values))
                    sds.append(statistics.stdev(values) if len(values) > 1 else 0.0)
                ax.bar(xs, means, width=width, color=STRATEGY_COLORS.get(strategy, FALLBACK_COLOR), zorder=3)
                if field == "outage_s":
                    ax.errorbar(xs, means, yerr=sds, fmt="none", ecolor=MUTED, elinewidth=0.8, capsize=0, zorder=4)
            ax.set_xticks(range(len(scenarios)))
            ax.set_xticklabels(scenarios, fontsize=8)
            ax.set_xlim(-0.6, len(scenarios) - 0.4)
            ax.set_ylim(bottom=0)
            net = "WITH" if ft else "without"
            ax.set_title(f"{title} - network {net} 802.11r", fontsize=9, color=INK, loc="left")

    handles = [Patch(color=STRATEGY_COLORS.get(s, FALLBACK_COLOR), label=comparison.labels[s]) for s in strategies]
    handles.append(Patch(color=CRITICAL, alpha=0.3, label="link down (outage)"))
    handles.append(Line2D([], [], color=MUTED, linewidth=0.8, label="1 standard deviation (outage)"))
    fig.legend(
        handles=handles,
        loc="outside lower center",
        ncol=len(handles),
        frameon=False,
        fontsize=8,
        labelcolor=INK_2,
    )
    fig.suptitle(
        f"RoamPredict simulator - {comparison.seeds} walks per scenario "
        "(assumed switch timings; see the printed table and README)",
        fontsize=11,
        color=INK,
        x=0.005,
        ha="left",
        y=1.035,
    )
    fig.savefig(out, facecolor=SURFACE, bbox_inches="tight")
    plt.close(fig)
    return out
