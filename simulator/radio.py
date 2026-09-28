"""Radio model: what each AP's signal looks like at the walker's position.

    link_rssi(ap, t)     = tx - PL(d) - walls + shadow(ap, t) + dip(t)
    measured_rssi(ap, t) = round(link_rssi + reading_noise)

* PL(d): log-distance path loss, free-space loss at 1 m plus 10*n*log10(d).
* walls: attenuation of every wall/door crossed by the straight line.
* shadow: slow, spatially correlated fading per AP (Gauss-Markov process that
  decorrelates over a few metres of walking, and slowly even when standing).
* dip: rare one-reading drops of 8-15 dB on ALL APs (hand over the antenna).
* reading_noise: what makes consecutive Windows RSSI readings differ.

Everything is pre-computed on a 50 ms grid from a seed, so all strategies of the
same run see exactly the same radio conditions (a fair comparison).
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass

from simulator.floorplan import AccessPoint, FloorPlan
from simulator.walker import Walker

__all__ = ["RadioParams", "RadioWorld", "compute_mean_rssi"]

_C = 299_792_458.0


@dataclass(frozen=True)
class RadioParams:
    path_loss_exponent: float = 2.2
    shadow_sigma_db: float = 3.0
    shadow_decorrelation_m: float = 4.0
    shadow_drift_tau_s: float = 45.0  # people moving around change things slowly
    reading_sigma_db: float = 2.0
    dip_rate_per_s: float = 1.0 / 40.0
    dip_depth_db: tuple[float, float] = (8.0, 15.0)
    dip_duration_s: float = 0.25
    hearing_floor_dbm: float = -92.0  # weaker APs do not show up in scans
    grid_dt: float = 0.05
    tail_s: float = 30.0  # extra simulated time after the walk ends


def free_space_loss_1m(freq_mhz: float) -> float:
    return 20.0 * math.log10(4.0 * math.pi * freq_mhz * 1e6 / _C)


def _mean_rssi_at(plan: FloorPlan, ap: AccessPoint, x: float, y: float, params: RadioParams) -> float:
    d = max(1.0, math.hypot(x - ap.x, y - ap.y))
    path_loss = free_space_loss_1m(ap.freq_mhz) + 10.0 * params.path_loss_exponent * math.log10(d)
    return ap.tx_power_dbm - path_loss - plan.wall_loss(ap.x, ap.y, x, y)


def compute_mean_rssi(plan: FloorPlan, walker: Walker, params: RadioParams) -> dict[str, list[float]]:
    """Deterministic part of the signal along the walk (depends only on the route)."""
    n = int((walker.duration + params.tail_s) / params.grid_dt) + 2
    out: dict[str, list[float]] = {ap.bssid: [] for ap in plan.aps}
    for k in range(n):
        x, y = walker.position(k * params.grid_dt)
        for ap in plan.aps:
            out[ap.bssid].append(_mean_rssi_at(plan, ap, x, y, params))
    return out


class RadioWorld:
    def __init__(
        self,
        plan: FloorPlan,
        walker: Walker,
        params: RadioParams,
        seed: int,
        mean_rssi: dict[str, list[float]] | None = None,
    ) -> None:
        self.plan = plan
        self.walker = walker
        self.params = params
        self.seed = seed
        self.walk_duration = walker.duration
        self.duration = walker.duration + params.tail_s
        dt = params.grid_dt
        self._dt = dt
        self._mean = mean_rssi or compute_mean_rssi(plan, walker, params)
        self._n = len(next(iter(self._mean.values())))
        rng = random.Random(f"radio-{seed}")

        speeds = [walker.speed(k * dt) for k in range(self._n)]
        self._shadow: dict[str, list[float]] = {}
        self._noise: dict[str, list[float]] = {}
        sigma = params.shadow_sigma_db
        for ap in plan.aps:
            s = rng.gauss(0.0, sigma)
            series = []
            for k in range(self._n):
                rho = math.exp(-(speeds[k] * dt / params.shadow_decorrelation_m) - dt / params.shadow_drift_tau_s)
                s = rho * s + math.sqrt(max(0.0, 1.0 - rho * rho)) * sigma * rng.gauss(0.0, 1.0)
                series.append(s)
            self._shadow[ap.bssid] = series
            self._noise[ap.bssid] = [rng.gauss(0.0, params.reading_sigma_db) for _ in range(self._n)]

        self._dip = [0.0] * self._n
        dip_len = max(1, round(params.dip_duration_s / dt))
        k = 0
        while k < self._n:
            if rng.random() < params.dip_rate_per_s * dt:
                depth = rng.uniform(*params.dip_depth_db)
                for j in range(k, min(self._n, k + dip_len)):
                    self._dip[j] = -depth
                k += dip_len
            else:
                k += 1

    def _index(self, t: float) -> int:
        return min(self._n - 1, max(0, int(t / self._dt)))

    def link_rssi(self, bssid: str, t: float) -> float:
        k = self._index(t)
        return self._mean[bssid][k] + self._shadow[bssid][k] + self._dip[k]

    def measured_rssi(self, bssid: str, t: float) -> float:
        k = self._index(t)
        return float(round(self._mean[bssid][k] + self._shadow[bssid][k] + self._dip[k] + self._noise[bssid][k]))

    def audible(self, bssid: str, t: float) -> bool:
        return self.link_rssi(bssid, t) >= self.params.hearing_floor_dbm

    def position(self, t: float) -> tuple[float, float]:
        return self.walker.position(t)
