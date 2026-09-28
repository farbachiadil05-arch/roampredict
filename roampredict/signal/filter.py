"""RSSI cleaning: drop one-sample spikes, then smooth (EMA or Kalman).

Raw RSSI from Windows moves a few dB from one reading to the next and now and
then drops 10+ dB for a single reading (a hand over the antenna, someone walking
past).  The pipeline here turns that into a steady signal:

1. :class:`SpikeRejector` ignores single-sample outliers but accepts a new level
   once it has been seen ``confirm`` times in a row, so a real drop (walking out
   of the room) is only delayed by ``confirm - 1`` samples.
2. :class:`EmaSmoother` or :class:`Kalman1D` smooths what is left.  Both handle
   uneven sample spacing (Windows timing is never exact).
"""

from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass
from statistics import median

__all__ = [
    "FilterConfig",
    "SpikeRejector",
    "EmaSmoother",
    "Kalman1D",
    "FilteredSample",
    "SignalFilter",
]


@dataclass(frozen=True)
class FilterConfig:
    smoother: str = "ema"  # "ema" or "kalman"
    ema_tau_s: float = 1.0  # EMA time constant
    kalman_process_var: float = 2.0  # dB^2 per second: how fast the true level may wander
    kalman_meas_var: float = 6.0  # dB^2: noise of one reading
    spike_window: int = 5  # readings used as the reference level
    spike_threshold_db: float = 6.0  # minimum deviation that counts as a spike
    spike_mad_k: float = 3.0  # ...or k robust sigmas, whichever is larger
    spike_confirm: int = 2  # readings in a row needed to accept a new level
    reset_gap_s: float = 2.0  # start over after a gap this long

    def __post_init__(self) -> None:
        if self.smoother not in ("ema", "kalman"):
            raise ValueError("smoother must be 'ema' or 'kalman'")
        for name in (
            "ema_tau_s",
            "kalman_process_var",
            "kalman_meas_var",
            "spike_threshold_db",
            "spike_mad_k",
            "reset_gap_s",
        ):
            if not getattr(self, name) > 0:
                raise ValueError(f"{name} must be > 0")
        if self.spike_window < 3:
            raise ValueError("spike_window must be >= 3")
        if not 1 <= self.spike_confirm <= self.spike_window:
            raise ValueError("spike_confirm must be between 1 and spike_window")


class SpikeRejector:
    """Median-based outlier rejection with confirmation of real level changes."""

    def __init__(
        self,
        window: int = 5,
        threshold_db: float = 6.0,
        mad_k: float = 3.0,
        confirm: int = 2,
    ) -> None:
        self._threshold_db = threshold_db
        self._mad_k = mad_k
        self._confirm = confirm
        self._history: deque[float] = deque(maxlen=window)
        self._pending: list[float] = []

    def reset(self) -> None:
        self._history.clear()
        self._pending.clear()

    def threshold(self) -> float:
        """Current spike threshold: fixed floor or 3 robust sigmas (MAD)."""
        if len(self._history) < 3:
            return self._threshold_db
        center = median(self._history)
        mad = median(abs(v - center) for v in self._history)
        return max(self._threshold_db, self._mad_k * 1.4826 * mad)

    def update(self, value: float) -> tuple[float, bool]:
        """Return ``(value_to_use, rejected)``."""
        if not self._history:
            self._history.append(value)
            return value, False
        reference = median(self._history)
        limit = self.threshold()
        deviation = value - reference
        if abs(deviation) <= limit:
            self._pending.clear()
            self._history.append(value)
            return value, False

        # Outlier candidate. Keep it pending; a run of similar readings on the
        # same side of the reference means the level really changed.
        if self._pending and (self._pending[-1] - reference) * deviation < 0:
            self._pending.clear()
        self._pending.append(value)
        del self._pending[: -self._confirm]
        if len(self._pending) >= self._confirm and max(self._pending) - min(self._pending) <= limit:
            self._history.clear()
            self._history.extend(self._pending)
            self._pending.clear()
            return value, False
        return reference, True


class EmaSmoother:
    """Exponential moving average with a time constant (works for uneven dt)."""

    def __init__(self, tau_s: float) -> None:
        if tau_s <= 0:
            raise ValueError("tau_s must be > 0")
        self._tau = tau_s
        self._value: float | None = None
        self._t: float | None = None

    def reset(self) -> None:
        self._value = None
        self._t = None

    def update(self, t: float, x: float) -> float:
        if self._value is None or self._t is None:
            self._value, self._t = x, t
            return x
        dt = max(0.0, t - self._t)
        self._t = t
        alpha = 1.0 - math.exp(-dt / self._tau)
        self._value += alpha * (x - self._value)
        return self._value


class Kalman1D:
    """Scalar Kalman filter for a random-walk level (RSSI in dBm).

    Process noise grows with the time since the last reading, so a late sample
    is trusted more than one that arrives right on time.
    """

    def __init__(self, process_var_per_s: float, meas_var: float) -> None:
        if process_var_per_s <= 0 or meas_var <= 0:
            raise ValueError("variances must be > 0")
        self._q = process_var_per_s
        self._r = meas_var
        self._x: float | None = None
        self._p = meas_var
        self._t: float | None = None

    def reset(self) -> None:
        self._x = None
        self._p = self._r
        self._t = None

    @property
    def variance(self) -> float:
        return self._p

    def update(self, t: float, z: float) -> float:
        if self._x is None or self._t is None:
            self._x, self._p, self._t = z, self._r, t
            return z
        dt = max(0.0, t - self._t)
        self._t = t
        p_pred = self._p + self._q * dt
        gain = p_pred / (p_pred + self._r)
        self._x += gain * (z - self._x)
        self._p = (1.0 - gain) * p_pred
        return self._x


@dataclass(frozen=True)
class FilteredSample:
    t: float
    raw: float
    despiked: float
    smoothed: float
    rejected: bool


class SignalFilter:
    """Spike rejection followed by smoothing.  Resets itself after a gap."""

    def __init__(self, config: FilterConfig | None = None) -> None:
        self.config = config or FilterConfig()
        c = self.config
        self._spikes = SpikeRejector(c.spike_window, c.spike_threshold_db, c.spike_mad_k, c.spike_confirm)
        self._smoother: EmaSmoother | Kalman1D
        if c.smoother == "ema":
            self._smoother = EmaSmoother(c.ema_tau_s)
        else:
            self._smoother = Kalman1D(c.kalman_process_var, c.kalman_meas_var)
        self._last_t: float | None = None

    def reset(self) -> None:
        self._spikes.reset()
        self._smoother.reset()
        self._last_t = None

    def update(self, t: float, raw: float) -> FilteredSample:
        if not math.isfinite(raw):
            raise ValueError("RSSI must be a finite number")
        if self._last_t is not None and (t < self._last_t or t - self._last_t > self.config.reset_gap_s):
            self.reset()
        self._last_t = t
        despiked, rejected = self._spikes.update(raw)
        smoothed = self._smoother.update(t, despiked)
        return FilteredSample(t=t, raw=raw, despiked=despiked, smoothed=smoothed, rejected=rejected)
