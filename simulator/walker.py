"""A virtual person walking a scripted route, and the scenarios we test."""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass

__all__ = ["Waypoint", "Scenario", "Walker", "SCENARIOS"]


@dataclass(frozen=True)
class Waypoint:
    x: float
    y: float
    pause_s: float = 0.0  # stand still here after arriving
    speed_mps: float | None = None  # walking speed to reach this point


@dataclass(frozen=True)
class Scenario:
    name: str
    description: str
    waypoints: tuple[Waypoint, ...]
    speed_mps: float = 1.3


class Walker:
    """Piecewise-linear position over time."""

    def __init__(self, waypoints: Sequence[Waypoint], speed_mps: float = 1.3) -> None:
        if len(waypoints) < 1:
            raise ValueError("need at least one waypoint")
        self._legs: list[tuple[float, float, float, float, float, float]] = []  # t0, t1, x0, y0, x1, y1
        t = 0.0
        first = waypoints[0]
        if first.pause_s > 0:
            self._legs.append((t, t + first.pause_s, first.x, first.y, first.x, first.y))
            t += first.pause_s
        prev = first
        for wp in waypoints[1:]:
            speed = wp.speed_mps or speed_mps
            dist = math.hypot(wp.x - prev.x, wp.y - prev.y)
            if dist > 0:
                self._legs.append((t, t + dist / speed, prev.x, prev.y, wp.x, wp.y))
                t += dist / speed
            if wp.pause_s > 0:
                self._legs.append((t, t + wp.pause_s, wp.x, wp.y, wp.x, wp.y))
                t += wp.pause_s
            prev = wp
        self._start = (first.x, first.y)
        self._end = (prev.x, prev.y)
        self.duration = t

    def position(self, t: float) -> tuple[float, float]:
        for t0, t1, x0, y0, x1, y1 in self._legs:
            if t0 <= t <= t1:
                f = 0.0 if t1 == t0 else (t - t0) / (t1 - t0)
                return x0 + (x1 - x0) * f, y0 + (y1 - y0) * f
        return self._start if t <= 0 else self._end

    def speed(self, t: float) -> float:
        for t0, t1, x0, y0, x1, y1 in self._legs:
            if t0 <= t < t1:
                return 0.0 if t1 == t0 else math.hypot(x1 - x0, y1 - y0) / (t1 - t0)
        return 0.0


SCENARIOS: dict[str, Scenario] = {
    s.name: s
    for s in (
        Scenario(
            "walk_out",
            "Class ends: seat in classroom A -> door -> along the hallway -> seat in classroom C",
            (
                Waypoint(4.0, 15.5, pause_s=20.0),
                Waypoint(11.25, 13.0),
                Waypoint(11.25, 10.0),
                Waypoint(40.0, 10.0),
                Waypoint(41.25, 12.5),
                Waypoint(38.0, 17.0, pause_s=20.0),
            ),
        ),
        Scenario(
            "corner_seat",
            "Into classroom E and 60 s in a corner where three APs are all weak (-70..-75 dBm), then out",
            (
                Waypoint(4.0, 15.5, pause_s=15.0),
                Waypoint(11.25, 13.0),
                Waypoint(11.25, 10.0),
                Waypoint(16.75, 9.0),
                Waypoint(16.75, 7.0),
                Waypoint(18.0, 5.0, pause_s=60.0),
                Waypoint(16.75, 7.0),
                Waypoint(16.75, 10.0),
                Waypoint(22.0, 10.0, pause_s=10.0),
            ),
        ),
        Scenario(
            "hallway_pass",
            "Walking the whole hallway west -> east without stopping (several APs in a row)",
            (
                Waypoint(1.0, 10.0, pause_s=10.0),
                Waypoint(59.0, 10.0, speed_mps=1.4, pause_s=10.0),
            ),
        ),
    )
}
