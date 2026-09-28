"""Signal trend: least-squares slope over a sliding time window, and the
predicted time until the signal reaches the roam threshold.

The regression runs on the *despiked* readings, not on the EMA output: an EMA
delays the level by about its time constant (at -3 dBm/s and tau = 1 s that is
3 dB, i.e. one second of warning lost).  The regression window already
averages out the noise, and its fitted value at "now" is not delayed.
"""

from __future__ import annotations

import math
from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass

__all__ = [
    "LinearFit",
    "linear_fit",
    "TrendConfig",
    "TrendEstimate",
    "SlidingRegression",
    "time_to_threshold",
]


@dataclass(frozen=True)
class LinearFit:
    slope: float  # units of y per second
    t_mean: float
    y_mean: float
    r2: float
    slope_stderr: float
    n: int

    def value_at(self, t: float) -> float:
        return self.y_mean + self.slope * (t - self.t_mean)


def linear_fit(ts: Sequence[float], ys: Sequence[float]) -> LinearFit:
    """Ordinary least squares ``y = a + b t``, centred for numerical stability."""
    n = len(ts)
    if n != len(ys):
        raise ValueError("ts and ys must have the same length")
    if n < 2:
        raise ValueError("need at least two points")
    t_mean = math.fsum(ts) / n
    y_mean = math.fsum(ys) / n
    sxx = math.fsum((t - t_mean) ** 2 for t in ts)
    if sxx <= 1e-12:
        raise ValueError("timestamps must not all be equal")
    sxy = math.fsum((t - t_mean) * (y - y_mean) for t, y in zip(ts, ys))
    slope = sxy / sxx
    ss_tot = math.fsum((y - y_mean) ** 2 for y in ys)
    ss_res = max(0.0, math.fsum((y - (y_mean + slope * (t - t_mean))) ** 2 for t, y in zip(ts, ys)))
    r2 = 1.0 - ss_res / ss_tot if ss_tot > 0 else 1.0
    stderr = math.sqrt(ss_res / (n - 2) / sxx) if n > 2 else math.inf
    return LinearFit(slope=slope, t_mean=t_mean, y_mean=y_mean, r2=r2, slope_stderr=stderr, n=n)


@dataclass(frozen=True)
class TrendConfig:
    window_s: float = 3.0  # regression window
    min_points: int = 6  # readings needed before the trend is trusted
    min_span_fraction: float = 0.6  # ...and they must cover 60% of the window
    t_stat_min: float = 2.0  # |slope| / stderr needed to call it a real trend

    def __post_init__(self) -> None:
        if self.window_s <= 0:
            raise ValueError("window_s must be > 0")
        if self.min_points < 3:
            raise ValueError("min_points must be >= 3")
        if not 0 < self.min_span_fraction <= 1:
            raise ValueError("min_span_fraction must be in (0, 1]")
        if self.t_stat_min < 0:
            raise ValueError("t_stat_min must be >= 0")


@dataclass(frozen=True)
class TrendEstimate:
    t: float
    slope_dbm_s: float
    level_dbm: float  # fitted value at the newest reading
    n: int
    span_s: float
    r2: float
    slope_stderr: float
    valid: bool  # enough readings over enough time
    significant: bool  # valid and the slope is clearly not noise

    @property
    def falling(self) -> bool:
        return self.valid and self.significant and self.slope_dbm_s < 0


class SlidingRegression:
    """Keeps the last ``window_s`` seconds of readings and fits a line."""

    def __init__(self, config: TrendConfig | None = None) -> None:
        self.config = config or TrendConfig()
        self._points: deque[tuple[float, float]] = deque()

    def reset(self) -> None:
        self._points.clear()

    def __len__(self) -> int:
        return len(self._points)

    def add(self, t: float, y: float) -> None:
        if self._points and t < self._points[-1][0]:
            self.reset()  # time went backwards: start over
        if self._points and t == self._points[-1][0]:
            self._points.pop()  # same timestamp: keep the newest reading
        self._points.append((t, y))
        cutoff = t - self.config.window_s
        while self._points and self._points[0][0] < cutoff:
            self._points.popleft()

    def estimate(self) -> TrendEstimate:
        if not self._points:
            return TrendEstimate(math.nan, 0.0, math.nan, 0, 0.0, 0.0, math.inf, False, False)
        t_last, y_last = self._points[-1]
        n = len(self._points)
        span = t_last - self._points[0][0]
        if n < 2 or span <= 0:
            return TrendEstimate(t_last, 0.0, y_last, n, span, 0.0, math.inf, False, False)
        ts = [p[0] for p in self._points]
        ys = [p[1] for p in self._points]
        fit = linear_fit(ts, ys)
        cfg = self.config
        valid = n >= cfg.min_points and span >= cfg.min_span_fraction * cfg.window_s
        significant = valid and fit.slope != 0 and abs(fit.slope) >= cfg.t_stat_min * fit.slope_stderr
        return TrendEstimate(
            t=t_last,
            slope_dbm_s=fit.slope,
            level_dbm=fit.value_at(t_last),
            n=n,
            span_s=span,
            r2=fit.r2,
            slope_stderr=fit.slope_stderr,
            valid=valid,
            significant=significant,
        )


def time_to_threshold(level_dbm: float, slope_dbm_s: float, threshold_dbm: float) -> float:
    """Seconds until a straight-line trend reaches ``threshold_dbm``.

    Returns 0 if the level is already at or below the threshold and ``inf`` if
    the signal is not falling.
    """
    if math.isnan(level_dbm) or math.isnan(slope_dbm_s):
        return math.inf
    if level_dbm <= threshold_dbm:
        return 0.0
    if slope_dbm_s >= 0:
        return math.inf
    return (threshold_dbm - level_dbm) / slope_dbm_s
