"""The simulated Windows driver and the three strategies we compare.

:class:`SimDriver` plays the role of Windows + the Wi-Fi driver.  It implements
the ``MockRadio`` protocol, so the real RoamPredict engine runs on top of it
through ``MockWlanAdapter`` exactly as it would on Windows.  Like real Windows,
it ALWAYS does its own reactive roaming as well (default trigger -80 dBm), in
every strategy - RoamPredict only adds requests on top.

Strategies:

1. ``reactive``   - Windows alone ("normal reactive roaming at -80 dBm").
2. ``threshold``  - a naive app: raw reading below -75 dBm -> scan -> switch to
                    the strongest AP if it is >= 5 dB above that raw reading.
3. ``predictive`` - the real RoamPredict engine (filter, trend, state machine,
                    topology memory, safe executor) in active mode.
"""

from __future__ import annotations

import bisect
import math
import random
from dataclasses import dataclass, field

from roampredict.engine import Engine, EngineConfig
from roampredict.platform.base import (
    BssEntry,
    CommandResult,
    ConnectResult,
    L3Snapshot,
    LinkStatus,
    NetworkOps,
    PingResult,
    RoamCapabilities,
    WlanEvent,
    WlanEventKind,
    freq_to_channel,
)
from roampredict.platform.mock import DEFAULT_L3, MockWlanAdapter
from roampredict.roam.executor import ExecutorConfig, RoamExecutor
from roampredict.safety import KillSwitch, SafetyConfig, SafetyGate
from roampredict.signal.filter import FilterConfig
from roampredict.signal.trend import TrendConfig
from roampredict.state_machine import StateMachineConfig
from roampredict.telemetry import Telemetry
from roampredict.topology.predictor import Predictor, PredictorConfig
from roampredict.topology.store import TopologyStore
from simulator.link_model import LinkModel
from simulator.radio import RadioWorld

__all__ = [
    "DriverConfig",
    "Segment",
    "RoamRecord",
    "SimDriver",
    "SimNetworkOps",
    "RunContext",
    "ReactiveStrategy",
    "ThresholdStrategy",
    "PredictiveStrategy",
    "RunMetrics",
    "compute_metrics",
]

_UNREACHABLE_REASON = 0x28005  # a generic "network not available" style reason code


@dataclass(frozen=True)
class DriverConfig:
    """How the simulated Windows/driver roams by itself (assumptions)."""

    roam_trigger_dbm: float = -80.0
    trigger_hold_s: float = 1.0
    avg_tau_s: float = 1.0
    roam_scan_s: float = 1.5  # partial scan once the trigger fired
    min_delta_db: float = 6.0
    retry_s: float = 5.0
    link_loss_dbm: float = -90.0  # beacons lost below this...
    link_loss_s: float = 1.5  # ...for this long -> disconnect
    autoconnect_delay_s: float = 2.0
    bg_scan_interval_s: float = 60.0
    app_scan_s: float = 2.5  # a full scan requested through WlanScan
    scan_miss_prob: float = 0.05
    cache_expiry_s: float = 120.0
    connect_min_dbm: float = -88.0
    sample_dt: float = 0.25


@dataclass
class Segment:
    t0: float
    t1: float
    bssid: str | None  # None = not associated (switching or disconnected)
    cause: str


@dataclass(frozen=True)
class RoamRecord:
    t_start: float
    t_end: float
    src: str | None
    dst: str
    initiator: str  # "driver" | "app" | "autoconnect"
    auth_kind: str


class SimDriver:
    GRID = 0.05

    def __init__(
        self,
        world: RadioWorld,
        link_model: LinkModel,
        config: DriverConfig,
        rng: random.Random,
        *,
        ssid: str = "eduroam",
        profile: str = "eduroam",
        network_ft: bool = False,
        pmk_history: dict[str, float] | None = None,
    ) -> None:
        self.world = world
        self.link_model = link_model
        self.cfg = config
        self.rng = rng
        self.ssid = ssid
        self.profile = profile
        self.network_ft = network_ft
        self.t = 0.0
        self.pmk: dict[str, float] = dict(pmk_history or {})
        self.events: list[WlanEvent] = []
        self.cache: dict[str, tuple[float, float]] = {}
        self.segments: list[Segment] = []
        self.l3_gaps: list[tuple[float, float]] = []
        self.roams: list[RoamRecord] = []
        self.current: str | None = None
        self._aps = {ap.bssid: ap for ap in world.plan.aps}
        self._caps = RoamCapabilities(
            ft=network_ft, rrm_neighbor_report=True, bss_transition=True, rsn_preauth=False, enterprise=True
        )
        self._busy = False
        self._pending_roam: tuple[float, str, str, str, float, str | None, float] | None = None
        self._pending_scan_done: float | None = None
        self._next_bg_scan = rng.uniform(5.0, config.bg_scan_interval_s)
        self._next_sample = 0.0
        self._avg: float | None = None
        self._below_since: float | None = None
        self._roam_scan_until: float | None = None
        self._retry_at = 0.0
        self._lost_since: float | None = None
        self._disconnected_at: float | None = None
        self._l3_ready_at = 0.0
        self._last_bssid: str | None = None

        # The walk starts while already connected to the strongest AP.
        self._scan(0.0, emit=False)
        start = max(self.cache, key=lambda b: self.cache[b][0])
        self.pmk.setdefault(start, -1800.0)
        self._set_link(start, 0.0, "initial")

    # -- time --------------------------------------------------------------------------

    def now(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        end = self.t + max(0.0, seconds)
        while self.t < end - 1e-9:
            self.t = min(end, self.t + self.GRID)
            self._on_time()
        if self.segments:
            self.segments[-1].t1 = self.t

    def _on_time(self) -> None:
        t = self.t
        if self._pending_scan_done is not None and t >= self._pending_scan_done - 1e-9:
            self._pending_scan_done = None
            self._scan(t, emit=True)
        if t >= self._next_bg_scan:
            self._next_bg_scan = t + self.cfg.bg_scan_interval_s
            self._scan(t, emit=True)
        if self._pending_roam is not None and t >= self._pending_roam[0] - 1e-9:
            self._finish_roam()
        if t + 1e-9 >= self._next_sample:
            self._next_sample += self.cfg.sample_dt
            if not self._busy:
                self._driver_step(t)

    # -- Windows' own behaviour -----------------------------------------------------------

    def _emit(self, kind: WlanEventKind, bssid: str | None = None, reason_code: int | None = None) -> None:
        self.events.append(WlanEvent(t=self.t, kind=kind, bssid=bssid, profile=self.profile, reason_code=reason_code))

    def _set_link(self, bssid: str | None, t: float, cause: str) -> None:
        if self.segments:
            self.segments[-1].t1 = t
        self.segments.append(Segment(t, t, bssid, cause))
        if bssid is not None:
            self._last_bssid = bssid
        self.current = bssid

    def _reset_driver_state(self) -> None:
        self._avg = None
        self._below_since = None
        self._roam_scan_until = None
        self._retry_at = self.t
        self._lost_since = None

    def _scan(self, t: float, *, emit: bool) -> None:
        for bssid in self._aps:
            if self.world.audible(bssid, t) and self.rng.random() >= self.cfg.scan_miss_prob:
                self.cache[bssid] = (self.world.measured_rssi(bssid, t), t)
        for bssid in [b for b, (_, heard) in self.cache.items() if t - heard > self.cfg.cache_expiry_s]:
            del self.cache[bssid]
        if emit:
            self._emit(WlanEventKind.SCAN_COMPLETE)

    def _driver_step(self, t: float) -> None:
        cfg = self.cfg
        if self._pending_roam is not None:
            return
        if self.current is None:
            if self._disconnected_at is not None and t - self._disconnected_at >= cfg.autoconnect_delay_s:
                self._autoconnect(t)
            return
        if self.world.link_rssi(self.current, t) < cfg.link_loss_dbm:
            if self._lost_since is None:
                self._lost_since = t
            if t - self._lost_since >= cfg.link_loss_s:
                self._drop(t, "link lost")
                return
        else:
            self._lost_since = None
        reading = self.world.measured_rssi(self.current, t)
        if self._avg is None:
            self._avg = reading
        else:
            self._avg += (1.0 - math.exp(-cfg.sample_dt / cfg.avg_tau_s)) * (reading - self._avg)

        if self._roam_scan_until is not None:
            if t + 1e-9 >= self._roam_scan_until:
                self._roam_scan_until = None
                self._scan(t, emit=True)
                heard_now = [b for b, (_, heard) in self.cache.items() if b != self.current and t - heard < 0.01]
                best = max(heard_now, key=lambda b: self.cache[b][0], default=None)
                if best is not None and self.cache[best][0] >= self._avg + cfg.min_delta_db:
                    self._start_roam(best, t)
                else:
                    self._retry_at = t + cfg.retry_s
            return
        if self._avg < cfg.roam_trigger_dbm:
            if self._below_since is None:
                self._below_since = t
            if t - self._below_since >= cfg.trigger_hold_s and t >= self._retry_at:
                self._roam_scan_until = t + cfg.roam_scan_s
        else:
            self._below_since = None

    def _start_roam(self, dst: str, t: float) -> None:
        parts = self.link_model.driver_roam(
            self.rng, ft_available=self.network_ft, pmk_cached=self.link_model.pmk_valid(self.pmk.get(dst), t)
        )
        src = self.current
        self._emit(WlanEventKind.ROAMING_START, src)
        self._set_link(None, t, "driver roam")
        self._pending_roam = (t + parts.total_s, dst, "driver", parts.auth_kind, t, src, parts.dhcp_s)

    def _autoconnect(self, t: float) -> None:
        reachable = [b for b in self._aps if self.world.link_rssi(b, t) >= self.cfg.connect_min_dbm]
        if not reachable:
            self._disconnected_at = t  # try again later
            return
        dst = max(reachable, key=lambda b: self.world.measured_rssi(b, t))
        parts = self.link_model.reconnect(self.rng, pmk_cached=self.link_model.pmk_valid(self.pmk.get(dst), t))
        self._emit(WlanEventKind.CONNECTION_START)
        self._pending_roam = (t + parts.assoc_s + parts.auth_s, dst, "autoconnect", parts.auth_kind, t, self._last_bssid, parts.dhcp_s)

    def _finish_roam(self) -> None:
        assert self._pending_roam is not None
        _, dst, initiator, kind, t_start, src, dhcp_s = self._pending_roam
        self._pending_roam = None
        self._set_link(dst, self.t, f"{initiator} done")
        self.pmk[dst] = self.t
        self.roams.append(RoamRecord(t_start, self.t, src, dst, initiator, kind))
        self._l3_ready_at = self.t + dhcp_s
        if dhcp_s > 0:
            self.l3_gaps.append((self.t, self.t + dhcp_s))
        self._disconnected_at = None
        if initiator == "driver":
            self._emit(WlanEventKind.ROAMING_END, dst)
        else:
            self._emit(WlanEventKind.CONNECTED, dst)
            self._emit(WlanEventKind.CONNECTION_COMPLETE, dst, 0)
        self._reset_driver_state()

    def _drop(self, t: float, cause: str) -> None:
        self._emit(WlanEventKind.DISCONNECTED, self.current)
        self._set_link(None, t, cause)
        self._disconnected_at = t
        self._reset_driver_state()

    # -- MockRadio protocol -------------------------------------------------------------------

    def link(self) -> LinkStatus:
        if self.current is None:
            return LinkStatus(connected=False)
        rssi = self.world.measured_rssi(self.current, self.t)
        return LinkStatus(
            connected=True,
            ssid=self.ssid,
            bssid=self.current,
            profile_name=self.profile,
            rssi_dbm=rssi,
            signal_quality=int(max(0, min(100, 2 * (rssi + 100)))),
            channel=self._aps[self.current].channel,
            auth="WPA2-Enterprise",
            cipher="CCMP",
            onex=True,
        )

    def cached_bss(self) -> list[BssEntry]:
        out = []
        for bssid, (rssi, heard) in self.cache.items():
            if bssid == self.current:
                rssi, heard = self.world.measured_rssi(bssid, self.t), self.t
            ap = self._aps[bssid]
            channel, band = freq_to_channel(ap.freq_mhz)
            out.append(
                BssEntry(
                    bssid=bssid,
                    ssid=self.ssid,
                    rssi_dbm=rssi,
                    freq_mhz=ap.freq_mhz,
                    channel=channel,
                    band=band,
                    age_s=max(0.0, self.t - heard),
                    capabilities=self._caps,
                )
            )
        return out

    def start_scan(self, ssid: str | None) -> None:
        if self._pending_scan_done is None:
            self._pending_scan_done = self.t + self.cfg.app_scan_s

    def wait_scan(self, timeout_s: float) -> bool:
        if self._pending_scan_done is None:
            return True
        wait = self._pending_scan_done - self.t
        if wait > timeout_s:
            self.advance(timeout_s)
            return False
        self.advance(max(0.0, wait) + 1e-6)
        return True

    def connect(self, profile: str, ssid: str, bssid: str, timeout_s: float, auth_stall_s: float) -> ConnectResult:
        t0 = self.t
        old = self.current
        timeline: list[tuple[float, str]] = []

        def mark(kind: WlanEventKind, b: str | None = None, code: int | None = None) -> None:
            self._emit(kind, b, code)
            timeline.append((round((self.t - t0) * 1000.0, 1), kind.value))

        self._busy = True
        try:
            self._pending_roam = None  # WlanConnect overrides whatever the driver was doing
            if old is not None:
                mark(WlanEventKind.DISCONNECTING, old)
                mark(WlanEventKind.DISCONNECTED, old)
            mark(WlanEventKind.CONNECTION_START)
            self._set_link(None, t0, "app switch")
            if self.world.link_rssi(bssid, t0) < self.cfg.connect_min_dbm:
                self.advance(min(timeout_s, 4.0))
                mark(WlanEventKind.CONNECTION_FAILED, bssid, _UNREACHABLE_REASON)
                self._disconnected_at = self.t
                return ConnectResult(
                    requested_bssid=bssid,
                    connected=False,
                    final_bssid=None,
                    total_ms=(self.t - t0) * 1000.0,
                    disconnect_seen=old is not None,
                    failure_reason="requested AP not reachable",
                    reason_code=_UNREACHABLE_REASON,
                    events=tuple(timeline),
                )
            parts = self.link_model.app_switch(
                self.rng, ft_available=self.network_ft, pmk_cached=self.link_model.pmk_valid(self.pmk.get(bssid), t0)
            )
            self.advance(parts.disconnect_s)
            mark(WlanEventKind.ASSOCIATING, bssid)
            self.advance(parts.assoc_s)
            mark(WlanEventKind.ASSOCIATED, bssid)
            mark(WlanEventKind.AUTHENTICATING, bssid)
            self.advance(parts.auth_s)
            mark(WlanEventKind.CONNECTED, bssid)
            mark(WlanEventKind.CONNECTION_COMPLETE, bssid, 0)
            self._set_link(bssid, self.t, "app switch done")
            self.pmk[bssid] = self.t
            self._l3_ready_at = self.t + parts.dhcp_s
            self.l3_gaps.append((self.t, self.t + parts.dhcp_s))
            self.roams.append(RoamRecord(t0, self.t, old, bssid, "app", parts.auth_kind))
            self._disconnected_at = None
            self._reset_driver_state()
            return ConnectResult(
                requested_bssid=bssid,
                connected=True,
                final_bssid=bssid,
                total_ms=(self.t - t0) * 1000.0,
                assoc_ms=parts.assoc_s * 1000.0,
                auth_ms=parts.auth_s * 1000.0,
                disconnect_seen=old is not None,
                events=tuple(timeline),
            )
        finally:
            self._busy = False

    def connect_any(self, profile: str) -> None:
        reachable = [b for b in self._aps if self.world.link_rssi(b, self.t) >= self.cfg.connect_min_dbm]
        if reachable:
            best = max(reachable, key=lambda b: self.world.measured_rssi(b, self.t))
            self.connect(profile, self.ssid, best, 12.0, 6.0)

    def profiles(self) -> list[str]:
        return [self.profile]

    def drain_events(self) -> list[WlanEvent]:
        events, self.events = self.events, []
        return events

    # -- analysis helpers ---------------------------------------------------------------------

    def l3_ready(self) -> bool:
        return self.current is not None and self.t >= self._l3_ready_at

    def bssid_at(self, t: float) -> str | None:
        starts = [s.t0 for s in self.segments]
        i = bisect.bisect_right(starts, t) - 1
        if i < 0:
            return None
        seg = self.segments[i]
        return seg.bssid

    def in_l3_gap(self, t: float) -> bool:
        return any(a <= t < b for a, b in self.l3_gaps)


class SimNetworkOps(NetworkOps):
    """The IP layer of the simulated laptop: one subnet for the whole floor."""

    def __init__(self, driver: SimDriver) -> None:
        self.driver = driver

    def snapshot(self, interface_guid: str) -> L3Snapshot:
        if self.driver.current is None:
            return L3Snapshot(DEFAULT_L3.if_index, DEFAULT_L3.friendly_name, None, None, None)
        return DEFAULT_L3

    def ping(self, host: str, timeout_ms: int) -> PingResult:
        d = self.driver
        if d.l3_ready() and d.current is not None and d.world.link_rssi(d.current, d.t) >= d.link_model.link_floor_dbm:
            d.advance(0.004)
            return PingResult(ok=True, rtt_ms=4.0)
        d.advance(timeout_ms / 1000.0)
        return PingResult(ok=False, rtt_ms=None, error="timed out")

    def flush_arp(self, snapshot: L3Snapshot) -> CommandResult:
        self.driver.advance(0.01)
        return CommandResult(ok=True, skipped=False, duration_ms=10.0, detail="flushed (simulated)")

    def renew_dhcp(self, snapshot: L3Snapshot) -> CommandResult:
        self.driver.advance(0.3)
        return CommandResult(ok=True, skipped=False, duration_ms=300.0, detail="renewed (simulated)")

    def is_admin(self) -> bool:
        return True


@dataclass
class RunContext:
    store: TopologyStore  # RoamPredict's memory; shared across repeated walks
    wall_base: float
    keep_events: bool = False


class ReactiveStrategy:
    name = "reactive"
    label = "Reactive (Windows alone, -80 dBm)"

    def run(self, driver: SimDriver, duration_s: float, ctx: RunContext) -> Telemetry | None:
        driver.advance(duration_s)
        return None


@dataclass
class ThresholdStrategy:
    threshold_dbm: float = -75.0
    min_gain_db: float = 5.0
    tick_s: float = 0.25
    scan_timeout_s: float = 4.5
    name: str = "threshold"
    label: str = "Simple threshold (-75 dBm, +5 dB)"

    def run(self, driver: SimDriver, duration_s: float, ctx: RunContext) -> Telemetry | None:
        adapter = MockWlanAdapter(driver)
        while adapter.now() < duration_s:
            link = adapter.link_status()
            if link.connected and link.rssi_dbm is not None and link.rssi_dbm < self.threshold_dbm:
                adapter.request_scan(link.ssid)
                adapter.wait_for_scan(self.scan_timeout_s)
                others = [e for e in adapter.bss_list() if e.ssid == link.ssid and e.bssid != link.bssid]
                best = max(others, key=lambda e: e.rssi_dbm, default=None)
                if best is not None and link.profile_name and link.ssid and best.rssi_dbm >= link.rssi_dbm + self.min_gain_db:
                    adapter.connect_bssid(link.profile_name, link.ssid, best.bssid, timeout_s=12.0, auth_stall_s=6.0)
            adapter.sleep(self.tick_s)
        return None


@dataclass
class PredictiveStrategy:
    engine_config: EngineConfig = field(default_factory=EngineConfig)
    sm_config: StateMachineConfig = field(default_factory=StateMachineConfig)
    predictor_config: PredictorConfig = field(default_factory=PredictorConfig)
    executor_config: ExecutorConfig = field(default_factory=ExecutorConfig)
    filter_config: FilterConfig = field(default_factory=FilterConfig)
    trend_config: TrendConfig = field(default_factory=TrendConfig)
    name: str = "predictive"
    label: str = "RoamPredict (predictive)"

    def run(self, driver: SimDriver, duration_s: float, ctx: RunContext) -> Telemetry | None:
        adapter = MockWlanAdapter(driver)
        net = SimNetworkOps(driver)
        telemetry = Telemetry(console=False, keep_in_memory=ctx.keep_events)
        safety = SafetyGate(
            SafetyConfig(dry_run=False, allowed_ssids=(driver.ssid,), min_roam_interval_s=self.sm_config.cooldown_s),
            KillSwitch(None),
        )
        engine = Engine(
            adapter=adapter,
            net=net,
            store=ctx.store,
            predictor=Predictor(ctx.store, self.predictor_config),
            executor=RoamExecutor(adapter, net, self.executor_config, telemetry),
            safety=safety,
            telemetry=telemetry,
            filter_config=self.filter_config,
            trend_config=self.trend_config,
            sm_config=self.sm_config,
            config=self.engine_config,
            wall_clock=lambda: ctx.wall_base + driver.now(),
        )
        engine.run(duration_s=duration_s)
        return telemetry


@dataclass(frozen=True)
class RunMetrics:
    scenario: str
    network_ft: bool
    seed: int
    strategy: str
    outage_s: float  # time the link was unusable (switching, reconnecting, or below the floor)
    longest_outage_s: float
    roams: int  # AP changes, by anyone
    pingpongs: int  # A -> B -> A within the ping-pong window
    app_switches: int
    driver_roams: int
    reconnects: int
    weak_s: float  # associated and usable, but weaker than the roam threshold ("sticky")
    mean_rssi_dbm: float  # while associated


def compute_metrics(
    driver: SimDriver,
    duration_s: float,
    *,
    scenario: str,
    seed: int,
    strategy: str,
    pingpong_window_s: float = 30.0,
    weak_dbm: float = -75.0,
) -> RunMetrics:
    grid = 0.05
    floor = driver.link_model.link_floor_dbm
    weak = 0.0
    outage = 0.0
    longest = 0.0
    run = 0.0
    rssi_sum = 0.0
    rssi_n = 0
    n = int(duration_s / grid)
    for k in range(n):
        t = (k + 0.5) * grid
        bssid = driver.bssid_at(t)
        if bssid is not None:
            rssi = driver.world.link_rssi(bssid, t)
            rssi_sum += rssi
            rssi_n += 1
        down = bssid is None or driver.in_l3_gap(t) or driver.world.link_rssi(bssid, t) < floor
        if down:
            outage += grid
            run += grid
            longest = max(longest, run)
        else:
            run = 0.0
            if bssid is not None and driver.world.link_rssi(bssid, t) < weak_dbm:
                weak += grid

    changes = [r for r in driver.roams if r.src is not None and r.src != r.dst and r.t_end <= duration_s]
    pingpongs = sum(
        1
        for a, b in zip(changes, changes[1:])
        if b.dst == a.src and b.t_end - a.t_end <= pingpong_window_s
    )
    return RunMetrics(
        scenario=scenario,
        network_ft=driver.network_ft,
        seed=seed,
        strategy=strategy,
        outage_s=round(outage, 3),
        longest_outage_s=round(longest, 3),
        roams=len(changes),
        pingpongs=pingpongs,
        app_switches=sum(1 for r in changes if r.initiator == "app"),
        driver_roams=sum(1 for r in changes if r.initiator == "driver"),
        reconnects=sum(1 for r in driver.roams if r.initiator == "autoconnect" and r.t_end <= duration_s),
        weak_s=round(weak, 3),
        mean_rssi_dbm=round(rssi_sum / rssi_n, 2) if rssi_n else math.nan,
    )
