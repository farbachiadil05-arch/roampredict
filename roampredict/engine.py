"""The control loop: sample -> filter -> trend -> state machine -> rank -> act.

One :meth:`Engine.tick` runs about four times per second:

1. Drain Windows notifications (scan complete, roam start/end, failures).
2. Read the link (SSID, BSSID, profile name, RSSI).
3. Notice what Windows did on its own - a roam or a reconnect - and learn from
   it: association time, the A -> B transition, and the roam duration when the
   driver reports roaming start/end.
4. Filter the RSSI, update the trend, predict the time to the roam threshold,
   update the state machine.
5. DEGRADING / ROAM_IMMINENT: keep the BSS list fresh (cached reads every
   second, a real scan at most every ``degrading_scan_interval_s``, because
   every scan costs lag spikes).
6. ROAM_IMMINENT: rank candidates, verify the best one (fresh scan, >= 8 dB
   stronger), then either log what we WOULD do (dry-run, kill switch, rate
   limit...) or switch.

Time comes from the adapter, so the same code runs in real time on Windows and
in virtual time inside the simulator.
"""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from roampredict.platform.base import (
    BssEntry,
    LinkStatus,
    NetworkOps,
    WlanAdapter,
    WlanError,
    WlanEvent,
    WlanEventKind,
    WlanPermissionError,
)
from roampredict.roam.executor import RoamExecutor, Verification
from roampredict.safety import SafetyGate
from roampredict.signal.filter import FilterConfig, SignalFilter
from roampredict.signal.trend import SlidingRegression, TrendConfig, time_to_threshold
from roampredict.state_machine import (
    RoamState,
    RoamStateMachine,
    SignalSnapshot,
    StateMachineConfig,
    Transition,
)
from roampredict.telemetry import Telemetry
from roampredict.topology.predictor import CandidateInput, Predictor, ScoreBreakdown, classify_candidate
from roampredict.topology.store import Sighting, SwitchRecord, TopologyStore

__all__ = ["EngineConfig", "Engine"]


@dataclass(frozen=True)
class EngineConfig:
    sample_hz: float = 4.0
    degrading_scan_interval_s: float = 6.0
    bss_refresh_interval_s: float = 1.0
    stable_bss_refresh_interval_s: float = 15.0
    sighting_write_interval_s: float = 5.0
    verify_backoff_s: float = 3.0
    no_candidate_log_interval_s: float = 10.0
    max_roam_gap_s: float = 10.0  # a reconnect to another AP within this time counts as a roam
    min_dwell_learn_s: float = 10.0  # learn "A -> B" only after staying on B this long
    defer_to_learned: bool = True  # wait for the usual next AP while the link has time left
    learned_min_count: int = 3
    learned_min_share: float = 0.6
    defer_min_ttt_s: float = 1.5
    link_down_report_s: float = 2.0
    prediction_window_s: float = 120.0
    association_retention_days: float = 30.0
    max_consecutive_errors: int = 40
    log_samples: bool = False

    def __post_init__(self) -> None:
        if not 0.5 <= self.sample_hz <= 20:
            raise ValueError("sample_hz must be between 0.5 and 20")
        for name in (
            "degrading_scan_interval_s",
            "bss_refresh_interval_s",
            "stable_bss_refresh_interval_s",
            "sighting_write_interval_s",
            "verify_backoff_s",
            "max_roam_gap_s",
            "min_dwell_learn_s",
            "prediction_window_s",
        ):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be > 0")


class Engine:
    def __init__(
        self,
        *,
        adapter: WlanAdapter,
        net: NetworkOps,
        store: TopologyStore,
        predictor: Predictor,
        executor: RoamExecutor,
        safety: SafetyGate,
        telemetry: Telemetry,
        filter_config: FilterConfig | None = None,
        trend_config: TrendConfig | None = None,
        sm_config: StateMachineConfig | None = None,
        config: EngineConfig | None = None,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        self.adapter = adapter
        self.net = net
        self.store = store
        self.predictor = predictor
        self.executor = executor
        self.safety = safety
        self.telemetry = telemetry
        self.config = config or EngineConfig()
        self.wall_clock = wall_clock
        self.filter = SignalFilter(filter_config)
        self.trend = SlidingRegression(trend_config)
        self.sm = RoamStateMachine(sm_config, on_transition=self._on_transition)

        self._link: LinkStatus | None = None
        self._last_connected: LinkStatus | None = None
        self._down_since: float | None = None
        self._down_reported = False
        self._bss: list[BssEntry] = []
        self._bss_read_at = -math.inf
        self._scan_requested_at = -math.inf
        self._sightings_written_at = -math.inf
        self._recently_left: dict[str, float] = {}
        self._episode_logged = False
        self._defer_logged = False
        self._verify_blocked_until = -math.inf
        self._last_no_candidate_log = -math.inf
        self._prediction: tuple[str, str, float] | None = None  # (from, predicted, monotonic t)
        self._assoc_bssid: str | None = None
        self._assoc_since: float | None = None
        self._anchor: str | None = None  # last AP we really stayed on
        self._pending_transition: tuple[str, str, float] | None = None
        self._roaming_start: float | None = None
        self._roaming_end: tuple[float, str | None] | None = None
        self._kill_seen = False
        self._permission_warned = False
        self.last_snapshot: SignalSnapshot | None = None
        self.switches_attempted = 0
        self.switches_ok = 0
        self.last_requested_bssid: str | None = None

    # -- main loop -------------------------------------------------------------------

    def run(self, stop: threading.Event | None = None, duration_s: float | None = None) -> None:
        period = 1.0 / self.config.sample_hz
        start = self.adapter.now()
        next_tick = start
        errors = 0
        last_error = ""
        mode = "DRY-RUN" if self.safety.config.dry_run else "ACTIVE"
        self.telemetry.emit("start", f"RoamPredict started ({mode}, {self.config.sample_hz:g} samples/s)", mode=mode)
        self.store.prune_associations(self.wall_clock() - self.config.association_retention_days * 86400)
        try:
            while stop is None or not stop.is_set():
                try:
                    self.tick()
                    errors = 0
                    last_error = ""
                except WlanError as exc:
                    errors += 1
                    if str(exc) != last_error:  # the same error every tick is reported once
                        last_error = str(exc)
                        self.telemetry.emit("error", f"Wi-Fi API error: {exc}", code=exc.code)
                    if errors >= self.config.max_consecutive_errors:
                        self.telemetry.emit("error", f"{errors} errors in a row - stopping: {last_error}")
                        break
                now = self.adapter.now()
                if duration_s is not None and now - start >= duration_s:
                    break
                next_tick += period
                delay = next_tick - now
                if delay > 0:
                    self.adapter.sleep(delay)
                else:
                    next_tick = now  # fell behind (e.g. during a switch): do not try to catch up
        finally:
            self.telemetry.emit(
                "stop",
                f"RoamPredict stopped ({self.switches_ok}/{self.switches_attempted} switches succeeded)",
                attempted=self.switches_attempted,
                succeeded=self.switches_ok,
            )

    def tick(self) -> None:
        now = self.adapter.now()
        self._check_kill_switch()
        self._handle_events(self.adapter.poll_events())
        link = self.adapter.link_status()

        if not link.connected or link.bssid is None or link.rssi_dbm is None:
            self._on_disconnected(link, now)
            return

        last = self._last_connected
        if last is None:
            self._on_connected(link, first=True)
        elif last.bssid != link.bssid:
            gap = 0.0 if self._down_since is None else now - self._down_since
            if last.ssid == link.ssid and gap <= self.config.max_roam_gap_s:
                self._on_windows_roam(last, link)
            else:
                self._on_connected(link, first=False)
        elif self._down_since is not None:
            self._on_connected(link, first=False)
        self._link = link
        self._last_connected = link
        self._down_since = None
        self._down_reported = False
        self._note_association(link.bssid, now)
        self._commit_transition(now)

        sample = self.filter.update(now, link.rssi_dbm)
        self.trend.add(now, sample.despiked)
        est = self.trend.estimate()
        level = est.level_dbm if est.valid else sample.smoothed
        slope = est.slope_dbm_s if est.valid else 0.0
        ttt = time_to_threshold(level, slope, self.sm.config.roam_threshold_dbm)
        snap = SignalSnapshot(t=now, smoothed_dbm=sample.smoothed, trend=est, ttt_s=ttt)
        self.last_snapshot = snap
        state = self.sm.update(snap)
        if self.config.log_samples:
            self.telemetry.emit(
                "sample",
                f"{link.rssi_dbm:.0f} dBm raw, {sample.smoothed:.1f} smoothed, slope {slope:+.2f} dB/s, {state.value}",
                raw=link.rssi_dbm,
                despiked=sample.despiked,
                smoothed=round(sample.smoothed, 2),
                slope=round(slope, 3),
                ttt=None if math.isinf(ttt) else round(ttt, 2),
                rejected=sample.rejected,
                state=state.value,
            )

        if state in (RoamState.DEGRADING, RoamState.ROAM_IMMINENT):
            self._maybe_scan(now, link)
            self._maybe_read_bss(now, link, self.config.bss_refresh_interval_s)
        else:
            self._maybe_read_bss(now, link, self.config.stable_bss_refresh_interval_s)

        if state is RoamState.ROAM_IMMINENT:
            self._consider_roam(now, link, level)
        else:
            self._episode_logged = False
            self._defer_logged = False

    # -- link changes -----------------------------------------------------------------

    def _on_disconnected(self, link: LinkStatus, now: float) -> None:
        if self._down_since is None:
            self._down_since = now
            self._reset_signal()
            self.sm.reset(now, "link down")
        elif not self._down_reported and now - self._down_since >= self.config.link_down_report_s:
            self._down_reported = True
            prev = self._last_connected
            self.telemetry.emit("link_down", "Wi-Fi link lost", bssid=None if prev is None else prev.bssid)
        self._link = link

    def _on_connected(self, link: LinkStatus, *, first: bool) -> None:
        wall = self.wall_clock()
        assert link.bssid is not None
        self.store.record_association(link.bssid, link.ssid, wall, "startup" if first else "windows")
        self.telemetry.emit(
            "connected",
            f"connected to {link.ssid!r} via {link.bssid} (profile {link.profile_name!r}, "
            f"{link.rssi_dbm:.0f} dBm, {link.auth or 'unknown security'})",
            ssid=link.ssid,
            bssid=link.bssid,
            profile=link.profile_name,
            rssi=link.rssi_dbm,
            auth=link.auth,
            rssi_source=link.rssi_source,
        )
        if not self.safety.config.dry_run:
            gate = self.safety.link_allowed(link)
            if not gate.allowed:
                self.telemetry.emit("warning", f"active mode, but not acting on this network: {gate.reason}")
        self._reset_signal()
        if not first:
            self.sm.settle(self.adapter.now(), "reconnected")

    def _on_windows_roam(self, prev: LinkStatus, link: LinkStatus) -> None:
        assert prev.bssid is not None and link.bssid is not None
        now = self.adapter.now()
        wall = self.wall_clock()
        duration_ms = None
        if self._roaming_start is not None and self._roaming_end is not None:
            end_t, end_bssid = self._roaming_end
            if end_t >= self._roaming_start and now - end_t < 30 and end_bssid in (None, link.bssid):
                duration_ms = (end_t - self._roaming_start) * 1000.0
        self._roaming_start = None
        self._roaming_end = None

        last_assoc = self.store.last_association(link.bssid)
        cls = classify_candidate(
            None if last_assoc is None else wall - last_assoc, self.predictor.config.recent_assoc_ttl_s
        )
        self.store.record_association(link.bssid, link.ssid, wall, "windows")
        self._note_association(link.bssid, now)
        self._recently_left[prev.bssid] = wall

        detail: dict[str, object] = {}
        if self._prediction is not None:
            from_bssid, predicted, t_pred = self._prediction
            if from_bssid == prev.bssid and now - t_pred <= self.config.prediction_window_s:
                hit = predicted == link.bssid
                detail = {"predicted": predicted, "hit": hit, "lead_s": round(now - t_pred, 1)}
                self.telemetry.emit(
                    "prediction_check",
                    f"dry-run prediction {'HIT' if hit else 'MISS'}: predicted {predicted}, Windows chose "
                    f"{link.bssid}, {now - t_pred:.1f} s after our decision",
                    **detail,
                )
            self._prediction = None

        self.store.record_switch(
            SwitchRecord(
                at=wall,
                initiator="windows",
                success=True,
                from_bssid=prev.bssid,
                to_bssid=link.bssid,
                candidate_class=cls,
                total_ms=duration_ms,
                reason="Windows roamed on its own",
                detail=detail,
            )
        )
        timing = f" in {duration_ms:.0f} ms" if duration_ms is not None else " (driver did not report roam timing)"
        self.telemetry.emit(
            "windows_roam",
            f"Windows roamed {prev.bssid} -> {link.bssid} ({cls}){timing}",
            src=prev.bssid,
            dst=link.bssid,
            candidate_class=cls,
            duration_ms=duration_ms,
        )
        self._reset_signal()
        self.sm.settle(now, "Windows roamed on its own")

    def _note_association(self, bssid: str, now: float) -> None:
        """Track where we stay.  A brief visit (shorter than ``min_dwell_learn_s``)
        is skipped when learning, so a detour A -> B (3 s) -> C teaches "A -> C"."""
        prev, since = self._assoc_bssid, self._assoc_since
        if prev == bssid:
            return
        if prev is not None and since is not None and now - since >= self.config.min_dwell_learn_s:
            self._anchor = prev
        self._pending_transition = None
        if self._anchor is not None and self._anchor != bssid:
            self._pending_transition = (self._anchor, bssid, now)
        self._assoc_bssid, self._assoc_since = bssid, now

    def _commit_transition(self, now: float) -> None:
        if self._pending_transition is None:
            return
        src, dst, since = self._pending_transition
        if self._assoc_bssid != dst:
            self._pending_transition = None
        elif now - since >= self.config.min_dwell_learn_s:
            self.store.record_transition(src, dst, self.wall_clock())
            self._anchor = dst
            self._pending_transition = None

    def _handle_events(self, events: list[WlanEvent], own: bool = False) -> None:
        for ev in events:
            if ev.kind is WlanEventKind.SCAN_COMPLETE:
                self.executor.note_scan_complete(ev.t)
                self._bss_read_at = -math.inf  # re-read the cached list on this tick
            elif ev.kind is WlanEventKind.ROAMING_START:
                self._roaming_start = ev.t
            elif ev.kind is WlanEventKind.ROAMING_END:
                self._roaming_end = (ev.t, ev.bssid)
            elif ev.kind is WlanEventKind.CONNECTION_FAILED and not own:
                self.telemetry.emit("warning", f"Windows reported a failed connection attempt (reason {ev.reason_code})")

    def _check_kill_switch(self) -> None:
        active = self.safety.kill_switch.active()
        if active and not self._kill_seen:
            self.telemetry.emit("kill_switch", f"kill switch ACTIVE - not switching ({self.safety.kill_switch.reason()})")
        elif not active and self._kill_seen:
            self.telemetry.emit("kill_switch", "kill switch cleared")
        self._kill_seen = active

    def _on_transition(self, tr: Transition) -> None:
        self.telemetry.emit("state", f"{tr.src.value} -> {tr.dst.value}: {tr.reason}", src=tr.src.value, dst=tr.dst.value)

    def _reset_signal(self) -> None:
        self.filter.reset()
        self.trend.reset()

    # -- BSS list upkeep ------------------------------------------------------------------

    def _maybe_scan(self, now: float, link: LinkStatus) -> None:
        if now - self._scan_requested_at < self.config.degrading_scan_interval_s:
            return
        self._scan_requested_at = now
        try:
            self.adapter.request_scan(link.ssid)
        except WlanError as exc:
            self.telemetry.emit("warning", f"scan request refused: {exc}")

    def _maybe_read_bss(self, now: float, link: LinkStatus, interval: float) -> None:
        if now - self._bss_read_at < interval:
            return
        self._bss_read_at = now
        try:
            self._bss = self.adapter.bss_list()
        except WlanPermissionError as exc:
            self._bss = []
            if not self._permission_warned:
                self._permission_warned = True
                self.telemetry.emit("error", str(exc))
            return
        if now - self._sightings_written_at >= self.config.sighting_write_interval_s:
            self._sightings_written_at = now
            wanted = set(self.safety.config.allowed_ssids) | {link.ssid}
            self.store.upsert_sightings(
                (
                    Sighting(
                        bssid=e.bssid,
                        ssid=e.ssid,
                        rssi_dbm=e.rssi_dbm,
                        channel=e.channel,
                        freq_mhz=e.freq_mhz,
                        band=e.band.value,
                        ft=e.capabilities.ft,
                        rrm=e.capabilities.rrm_neighbor_report,
                        btm=e.capabilities.bss_transition,
                        preauth=e.capabilities.rsn_preauth,
                        mdid=e.capabilities.mobility_domain,
                    )
                    for e in self._bss
                    if e.ssid in wanted
                ),
                self.wall_clock(),
            )

    # -- decisions --------------------------------------------------------------------------

    def _rank(self, link: LinkStatus, estimate: float, entries: list[BssEntry]) -> list[ScoreBreakdown]:
        assert link.ssid is not None
        candidates = [
            CandidateInput(e.bssid, e.ssid, e.rssi_dbm, e.age_s, e.channel, e.band.value)
            for e in entries
            if e.ssid == link.ssid
        ]
        return self.predictor.rank(
            current_bssid=link.bssid,
            current_rssi_dbm=estimate,
            ssid=link.ssid,
            candidates=candidates,
            now=self.wall_clock(),
            recently_left=self._recently_left,
            deny=self.safety.deny,
        )

    def _usual_next(self, current: str, ranked: list[ScoreBreakdown]) -> tuple[ScoreBreakdown, float, int] | None:
        """The AP we almost always go to next from ``current``, if it is visible."""
        cfg = self.config
        counts = self.store.transition_counts(current)
        total = sum(counts.values())
        if total == 0:
            return None
        bssid, n = max(counts.items(), key=lambda kv: kv[1])
        share = n / total
        if n < cfg.learned_min_count or share < cfg.learned_min_share:
            return None
        for r in ranked:
            if r.bssid == bssid:
                return r, share, n
        return None

    def _consider_roam(self, now: float, link: LinkStatus, estimate: float) -> None:
        if now < self._verify_blocked_until:
            return
        assert link.ssid is not None and link.bssid is not None
        ranked = self._rank(link, estimate, self._bss)
        best = Predictor.best(ranked)

        # Topology memory: if the AP we usually go to next is visible but not yet
        # good enough, and the current link still has time left, wait for it
        # instead of jumping to an AP we would probably leave again soon.
        snap = self.last_snapshot
        usual = self._usual_next(link.bssid, ranked) if self.config.defer_to_learned else None
        if (
            usual is not None
            and not usual[0].eligible
            and (best is None or best.bssid != usual[0].bssid)
            and snap is not None
            and snap.ttt_s > self.config.defer_min_ttt_s
        ):
            target, share, n = usual
            if not self._defer_logged:
                self._defer_logged = True
                self.telemetry.emit(
                    "waiting",
                    f"waiting for the usual next AP {target.bssid} (learned {n}x, {share:.0%}): "
                    f"{target.gain_db:+.1f} dB so far; link has ~{snap.ttt_s:.1f} s left",
                    candidate=target.as_dict(),
                )
            return

        if best is None:
            if now - self._last_no_candidate_log >= self.config.no_candidate_log_interval_s:
                self._last_no_candidate_log = now
                self.telemetry.emit(
                    "no_candidate",
                    f"signal is falling ({estimate:.0f} dBm) but no AP qualifies yet",
                    ranking=[r.as_dict() for r in ranked[:3]],
                )
            return

        gate = self.safety.check_roam(link, now)
        if not gate.allowed and self._episode_logged:
            return
        verification = self.executor.verify(link=link, bssid=best.bssid, current_estimate_dbm=estimate)
        self._bss_read_at = -math.inf
        if not verification.ok and verification.entries:
            # The refreshed list may point elsewhere: re-rank once on it.
            reranked = self._rank(link, estimate, list(verification.entries))
            alt = Predictor.best(reranked)
            if alt is not None and alt.bssid != best.bssid:
                second = self.executor.verify(link=link, bssid=alt.bssid, current_estimate_dbm=estimate)
                if second.ok:
                    best, ranked, verification = alt, reranked, second
        if not verification.ok:
            self._verify_blocked_until = self.adapter.now() + self.config.verify_backoff_s
            self.telemetry.emit(
                "not_verified",
                f"not switching to {best.bssid}: {verification.reason}",
                candidate=best.as_dict(),
                verify=verification.as_dict(),
            )
            return

        gate = self.safety.check_roam(link, self.adapter.now())  # re-check: verifying can take seconds
        if not gate.allowed:
            self._episode_logged = True
            self._prediction = (link.bssid, best.bssid, self.adapter.now())
            self.telemetry.emit(
                "would_switch",
                f"WOULD switch {link.bssid} -> {best.bssid} ({verification.gain_db:+.1f} dB, score {best.total:.2f}, "
                f"{best.candidate_class}) - not acting: {gate.reason}",
                gate=gate.reason,
                ranking=[r.as_dict() for r in ranked[:5]],
                verify=verification.as_dict(),
            )
            return
        self._switch(link, best, verification, ranked)

    def _switch(
        self,
        link: LinkStatus,
        best: ScoreBreakdown,
        verification: Verification,
        ranked: list[ScoreBreakdown],
    ) -> None:
        assert link.bssid is not None
        t_start = self.adapter.now()
        self.telemetry.emit(
            "decision",
            f"switching {link.bssid} -> {best.bssid} ({verification.gain_db:+.1f} dB, score {best.total:.2f}, "
            f"{best.candidate_class})",
            ranking=[r.as_dict() for r in ranked[:5]],
            verify=verification.as_dict(),
        )
        self.sm.begin_roam(t_start)
        self.safety.record_attempt(t_start)
        self.switches_attempted += 1
        self.last_requested_bssid = best.bssid

        outcome = self.executor.switch(link=link, candidate=best, verification=verification)
        t_end = self.adapter.now()
        wall = self.wall_clock()
        self.safety.record_result(outcome.success, outcome.reason, login_prompt_suspected=outcome.login_prompt_suspected)
        self.sm.end_roam(t_end, outcome.success, outcome.reason)
        if outcome.success:
            self.switches_ok += 1
        self.store.record_switch(outcome.to_switch_record(wall))
        self._handle_events(self.adapter.poll_events(), own=True)

        new_link = self.adapter.link_status()
        if new_link.connected and new_link.bssid is not None:
            if new_link.bssid != link.bssid:
                self.store.record_association(new_link.bssid, new_link.ssid, wall, "roampredict")
                self._note_association(new_link.bssid, t_end)
                self._recently_left[link.bssid] = wall
            self._last_connected = new_link
            self._down_since = None
        else:
            self._down_since = t_end
        self._link = new_link
        self._reset_signal()

        c = outcome.connect
        timing = ""
        if c is not None:
            timing = f", connect {c.total_ms:.0f} ms"
            if c.auth_ms is not None:
                timing += f" (auth {c.auth_ms:.0f} ms)"
        if outcome.l3_ms is not None:
            timing += f", IP ready after {outcome.l3_ms:.0f} ms"
        status = "OK" if outcome.success else "FAILED"
        self.telemetry.emit(
            "switch_result",
            f"{status}: {outcome.reason} [{best.candidate_class}{timing}; fallback={outcome.fallback}]",
            success=outcome.success,
            requested=best.bssid,
            final=outcome.final_bssid,
            candidate_class=best.candidate_class,
            total_ms=None if c is None else c.total_ms,
            assoc_ms=None if c is None else c.assoc_ms,
            auth_ms=None if c is None else c.auth_ms,
            l3_ms=outcome.l3_ms,
            detail=outcome.detail(),
        )
        if self.safety.kill_switch.active():
            self._check_kill_switch()
