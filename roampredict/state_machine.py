"""Roam state machine: STABLE -> DEGRADING -> ROAM_IMMINENT -> ROAMING -> COOLDOWN.

Anti-flapping rules:

* Every condition must hold continuously for a *dwell* time before a
  transition (``dwell_s`` to escalate, the longer ``recover_dwell_s`` to calm
  down).  One odd reading never changes the state.
* Enter and exit thresholds differ (hysteresis): DEGRADING starts below
  ``degrade_enter_dbm`` but only ends above ``degrade_exit_dbm``.
* After a roam the machine sits in COOLDOWN for ``cooldown_s`` (longer after a
  failure), which is the minimum time between roams and stops ping-pong.

The machine never starts a roam by itself: the engine calls :meth:`begin_roam`
only when a verified candidate exists and the safety gate allows it.
"""

from __future__ import annotations

import math
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

from roampredict.signal.trend import TrendEstimate

__all__ = [
    "RoamState",
    "StateMachineConfig",
    "SignalSnapshot",
    "Transition",
    "RoamStateMachine",
]


class RoamState(str, Enum):
    STABLE = "STABLE"
    DEGRADING = "DEGRADING"
    ROAM_IMMINENT = "ROAM_IMMINENT"
    ROAMING = "ROAMING"
    COOLDOWN = "COOLDOWN"


@dataclass(frozen=True)
class StateMachineConfig:
    roam_threshold_dbm: float = -75.0
    degrade_enter_dbm: float = -67.0
    degrade_exit_dbm: float = -63.0
    falling_slope_dbm_s: float = -1.0  # a trend at least this steep counts as "falling"
    degrade_horizon_s: float = 10.0  # DEGRADING if the threshold is predicted within this time
    imminent_lead_s: float = 4.0  # ROAM_IMMINENT if it is predicted within this time
    imminent_exit_margin_db: float = 3.0  # leave ROAM_IMMINENT only this far above the threshold
    slope_trigger_margin_db: float | None = None  # if set: slope alarms only within this many dB of the threshold
    dwell_s: float = 0.5  # a worse condition must hold this long
    recover_dwell_s: float = 2.0  # a better condition must hold this long
    cooldown_s: float = 20.0  # minimum time between roams
    failure_cooldown_s: float = 60.0  # after a failed roam
    external_roam_settle_s: float = 5.0  # after Windows roamed or reconnected by itself

    def __post_init__(self) -> None:
        if not self.degrade_exit_dbm > self.degrade_enter_dbm > self.roam_threshold_dbm:
            raise ValueError("need degrade_exit_dbm > degrade_enter_dbm > roam_threshold_dbm")
        if self.falling_slope_dbm_s >= 0:
            raise ValueError("falling_slope_dbm_s must be negative")
        if not 0 < self.imminent_lead_s < self.degrade_horizon_s:
            raise ValueError("need 0 < imminent_lead_s < degrade_horizon_s")
        if self.slope_trigger_margin_db is not None and self.slope_trigger_margin_db <= 0:
            raise ValueError("slope_trigger_margin_db must be > 0 (or None to disable)")
        for name in (
            "imminent_exit_margin_db",
            "dwell_s",
            "recover_dwell_s",
            "cooldown_s",
            "failure_cooldown_s",
            "external_roam_settle_s",
        ):
            if getattr(self, name) < 0:
                raise ValueError(f"{name} must be >= 0")


@dataclass(frozen=True)
class SignalSnapshot:
    t: float
    smoothed_dbm: float
    trend: TrendEstimate
    ttt_s: float  # predicted seconds until the roam threshold


@dataclass(frozen=True)
class Transition:
    t: float
    src: RoamState
    dst: RoamState
    reason: str


class _Hold:
    """Remembers since when a condition has been continuously true."""

    __slots__ = ("since",)

    def __init__(self) -> None:
        self.since: float | None = None

    def update(self, t: float, condition: bool) -> None:
        if condition:
            if self.since is None:
                self.since = t
        else:
            self.since = None

    def held(self, t: float, duration: float) -> bool:
        return self.since is not None and t - self.since >= duration - 1e-9

    def reset(self) -> None:
        self.since = None


class RoamStateMachine:
    def __init__(
        self,
        config: StateMachineConfig | None = None,
        on_transition: Callable[[Transition], None] | None = None,
    ) -> None:
        self.config = config or StateMachineConfig()
        self._state = RoamState.STABLE
        self._on_transition = on_transition
        self._cooldown_until = -math.inf
        self._degrade = _Hold()
        self._imminent = _Hold()
        self._recover = _Hold()
        self._calm = _Hold()
        self.history: deque[Transition] = deque(maxlen=500)

    @property
    def state(self) -> RoamState:
        return self._state

    @property
    def cooldown_until(self) -> float:
        return self._cooldown_until

    @property
    def wants_roam(self) -> bool:
        return self._state is RoamState.ROAM_IMMINENT

    def update(self, snap: SignalSnapshot) -> RoamState:
        c = self.config
        t = snap.t
        rssi = snap.smoothed_dbm
        steep = (
            snap.trend.falling
            and snap.trend.slope_dbm_s <= c.falling_slope_dbm_s
            and (c.slope_trigger_margin_db is None or rssi <= c.roam_threshold_dbm + c.slope_trigger_margin_db)
        )
        self._degrade.update(t, rssi < c.degrade_enter_dbm or (steep and snap.ttt_s <= c.degrade_horizon_s))
        self._imminent.update(t, rssi <= c.roam_threshold_dbm or (steep and snap.ttt_s <= c.imminent_lead_s))
        self._recover.update(t, rssi >= c.degrade_exit_dbm and not snap.trend.falling)
        self._calm.update(
            t,
            rssi > c.roam_threshold_dbm + c.imminent_exit_margin_db
            and not (steep and snap.ttt_s <= 2 * c.imminent_lead_s),
        )

        if self._state is RoamState.ROAMING:
            return self._state
        if self._state is RoamState.COOLDOWN:
            if t < self._cooldown_until:
                return self._state
            self._go(RoamState.STABLE, t, "cooldown over")

        state = self._state
        if state is RoamState.STABLE:
            if self._imminent.held(t, c.dwell_s):
                self._go(RoamState.ROAM_IMMINENT, t, "fast drop: " + _describe(snap))
            elif self._degrade.held(t, c.dwell_s):
                self._go(RoamState.DEGRADING, t, _describe(snap))
        elif state is RoamState.DEGRADING:
            if self._imminent.held(t, c.dwell_s):
                self._go(RoamState.ROAM_IMMINENT, t, _describe(snap))
            elif self._recover.held(t, c.recover_dwell_s):
                self._go(RoamState.STABLE, t, "recovered: " + _describe(snap))
        elif state is RoamState.ROAM_IMMINENT:
            if self._calm.held(t, c.recover_dwell_s):
                self._go(RoamState.DEGRADING, t, "signal recovered: " + _describe(snap))
        return self._state

    def begin_roam(self, t: float) -> None:
        if self._state is not RoamState.ROAM_IMMINENT:
            raise RuntimeError(f"begin_roam() called in state {self._state.value}")
        self._go(RoamState.ROAMING, t, "switch started")

    def end_roam(self, t: float, success: bool, reason: str = "") -> None:
        if self._state is not RoamState.ROAMING:
            raise RuntimeError(f"end_roam() called in state {self._state.value}")
        wait = self.config.cooldown_s if success else self.config.failure_cooldown_s
        self._cooldown_until = t + wait
        self._reset_holds()
        label = "switch succeeded" if success else "switch failed"
        self._go(RoamState.COOLDOWN, t, f"{label}{': ' + reason if reason else ''} (cooldown {wait:.0f} s)")

    def settle(self, t: float, reason: str) -> None:
        """Windows roamed or reconnected on its own: wait for the new link to settle."""
        if self._state is RoamState.ROAMING:
            return
        self._cooldown_until = max(self._cooldown_until, t + self.config.external_roam_settle_s)
        self._reset_holds()
        if self._state is RoamState.COOLDOWN:
            return
        self._go(RoamState.COOLDOWN, t, reason)

    def reset(self, t: float, reason: str) -> None:
        """Link lost: forget everything signal-related."""
        self._reset_holds()
        if self._state is not RoamState.STABLE:
            self._go(RoamState.STABLE, t, reason)

    def _reset_holds(self) -> None:
        for hold in (self._degrade, self._imminent, self._recover, self._calm):
            hold.reset()

    def _go(self, dst: RoamState, t: float, reason: str) -> None:
        if dst is self._state:
            return
        transition = Transition(t=t, src=self._state, dst=dst, reason=reason)
        self._state = dst
        self.history.append(transition)
        if self._on_transition is not None:
            self._on_transition(transition)


def _describe(snap: SignalSnapshot) -> str:
    ttt = "never" if math.isinf(snap.ttt_s) else f"{snap.ttt_s:.1f} s"
    slope = f"{snap.trend.slope_dbm_s:+.1f} dB/s" if snap.trend.valid else "n/a"
    return f"rssi {snap.smoothed_dbm:.1f} dBm, slope {slope}, time-to-threshold {ttt}"
