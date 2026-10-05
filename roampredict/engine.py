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

Every stretch without a Wi-Fi link is timed and stored as an outage, with the
signal just before the loss; with ``run --probe`` the internet probe's
outages are stored too.  Walks with Windows alone (dry-run) and active walks
can then be compared with ``roampredict report``.

Time comes from the adapter, so the same code runs in real time on Windows and
in virtual time inside the simulator.
"""

from __future__ import annotations

import math
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from roampredict.net.probe import ConnectivityProbe, ProbeEvent, format_clock
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
from roampredict.roam.executor import RoamExecutor, Verification, is_auth_reason
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
from roampredict.topology.store import OutageRecord, Sighting, SwitchRecord, TopologyStore

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
    loss_readings: int = 8  # raw readings shown when the link is lost
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
        probe: ConnectivityProbe | None = None,
        build_info: str = "",
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
        self.probe = probe
        self.build_info = build_info  # shown in the start line, so a pasted log says which code ran
        self.filter = SignalFilter(filter_config)
        self.trend = SlidingRegression(trend_config)
        self.sm = RoamStateMachine(sm_config, on_transition=self._on_transition)

        self._link: LinkStatus | None = None
        self._last_connected: LinkStatus | None = None
        self._down_since: float | None = None
        self._down_wall: float | None = None
        self._down_reported = False
        self._loss: dict[str, Any] = {}  # the signal just before the link was lost
        self._recent_raw: deque[float] = deque(maxlen=max(1, self.config.loss_readings))
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
        self.session_outages: dict[str, list[float]] = {"wifi": [], "internet": []}  # seconds

    # -- main loop -------------------------------------------------------------------

    def run(self, stop: threading.Event | None = None, duration_s: float | None = None) -> None:
        period = 1.0 / self.config.sample_hz
        start = self.adapter.now()
        next_tick = start
        errors = 0
        last_error = ""
        mode = "DRY-RUN" if self.safety.config.dry_run else "ACTIVE"
        build = f", {self.build_info}" if self.build_info else ""
        self.telemetry.emit(
            "start", f"RoamPredict started ({mode}, {self.config.sample_hz:g} samples/s{build})", mode=mode, build=self.build_info
        )
        self.store.prune_associations(self.wall_clock() - self.config.association_retention_days * 86400)
        if self.probe is not None:
            self.probe.start()
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
            self._finish_session()
            self.telemetry.emit(
                "stop",
                f"RoamPredict stopped ({self.switches_ok}/{self.switches_attempted} switches succeeded). "
                f"This session: {self.session_summary()}",
                attempted=self.switches_attempted,
                succeeded=self.switches_ok,
                wifi_outages_s=[round(v, 2) for v in self.session_outages["wifi"]],
                internet_outages_s=[round(v, 2) for v in self.session_outages["internet"]],
            )

    def tick(self) -> None:
        now = self.adapter.now()
        self._check_kill_switch()
        self._handle_events(self.adapter.poll_events())
        self._handle_probe_events()
        link = self.adapter.link_status()

        if not link.connected or link.bssid is None or link.rssi_dbm is None:
            self._on_disconnected(link, now)
            return

        last = self._last_connected
        # Only a loss we saw happen is an outage (not "disconnected when RoamPredict started").
        outage_s = None if self._down_since is None or last is None else now - self._down_since
        if last is None:
            self._on_connected(link, first=True)
        elif last.bssid != link.bssid:
            if last.ssid == link.ssid and (outage_s or 0.0) <= self.config.max_roam_gap_s:
                self._on_windows_roam(last, link, outage_s)
            else:
                self._on_connected(link, first=False, outage_s=outage_s)
        elif self._down_since is not None:
            self._on_connected(link, first=False, outage_s=outage_s)
        if outage_s is not None and last is not None:
            self._record_wifi_outage(outage_s, last.bssid, link.bssid)
        self._link = link
        self._last_connected = link
        self._down_since = None
        self._down_wall = None
        self._down_reported = False
        self._note_association(link.bssid, now)
        self._commit_transition(now)

        self._recent_raw.append(link.rssi_dbm)
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
            self._down_wall = self.wall_clock()
            self._loss = self._loss_context()
            self._reset_signal()
            self.sm.reset(now, "link lost - waiting for Windows to reconnect")
        elif not self._down_reported and now - self._down_since >= self.config.link_down_report_s:
            self._down_reported = True
            prev = self._last_connected
            wall = self._down_wall if self._down_wall is not None else self.wall_clock()
            self.telemetry.emit(
                "link_down",
                f"Wi-Fi link lost at {format_clock(wall)}{_describe_loss(self._loss)}",
                bssid=None if prev is None else prev.bssid,
                **self._loss,
            )
        self._link = link

    def _loss_context(self) -> dict[str, Any]:
        """What the signal looked like just before the link went away (or a switch began)."""
        snap = self.last_snapshot
        if not self._recent_raw or snap is None:
            return {}
        return {
            "smoothed": round(snap.smoothed_dbm, 1),
            "slope": round(snap.trend.slope_dbm_s, 2) if snap.trend.valid else None,
            "state": self.sm.state.value,
            "readings": [round(r) for r in self._recent_raw],
            "rssi_source": None if self._last_connected is None else self._last_connected.rssi_source,
        }

    def _record_wifi_outage(self, outage_s: float, from_bssid: str | None, to_bssid: str | None) -> None:
        started = self._down_wall if self._down_wall is not None else self.wall_clock() - outage_s
        loss, self._loss = self._loss, {}
        self.session_outages["wifi"].append(outage_s)
        self.store.record_outage(
            OutageRecord(
                started_at=started,
                duration_ms=outage_s * 1000.0,
                layer="wifi",
                mode=self._mode(),
                from_bssid=from_bssid,
                to_bssid=to_bssid,
                last_rssi=loss.get("smoothed"),
                detail=loss,
            )
        )

    def _mode(self) -> str:
        return "dry-run" if self.safety.config.dry_run else "active"

    def _on_connected(self, link: LinkStatus, *, first: bool, outage_s: float | None = None) -> None:
        wall = self.wall_clock()
        assert link.bssid is not None
        self.store.record_association(link.bssid, link.ssid, wall, "startup" if first else "windows")
        after = "" if outage_s is None else f" after {outage_s:.1f} s without Wi-Fi"
        self.telemetry.emit(
            "connected",
            f"connected to {link.ssid!r} via {link.bssid} (profile {link.profile_name!r}, "
            f"{link.rssi_dbm:.0f} dBm, {link.auth or 'unknown security'}){after}",
            ssid=link.ssid,
            bssid=link.bssid,
            profile=link.profile_name,
            rssi=link.rssi_dbm,
            auth=link.auth,
            rssi_source=link.rssi_source,
            outage_s=None if outage_s is None else round(outage_s, 2),
        )
        if not self.safety.config.dry_run:
            gate = self.safety.link_allowed(link)
            if not gate.allowed:
                self.telemetry.emit("warning", f"active mode, but not acting on this network: {gate.reason}")
        self._reset_signal()
        if not first:
            self.sm.settle(self.adapter.now(), "reconnected")

    def _on_windows_roam(self, prev: LinkStatus, link: LinkStatus, outage_s: float | None = None) -> None:
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

        total_ms = duration_ms
        if outage_s is not None:
            # The link was seen down in between: that gap is what the user felt.
            total_ms = outage_s * 1000.0
            detail["measured"] = "link down time"
        elif duration_ms is not None:
            detail["measured"] = "driver roam events"
        self.store.record_switch(
            SwitchRecord(
                at=wall,
                initiator="windows",
                success=True,
                from_bssid=prev.bssid,
                to_bssid=link.bssid,
                candidate_class=cls,
                total_ms=total_ms,
                reason="Windows roamed on its own",
                detail=detail,
            )
        )
        if outage_s is not None:
            timing = f" after {outage_s:.1f} s without Wi-Fi"
        elif duration_ms is not None:
            timing = f" in {duration_ms:.0f} ms"
        else:
            timing = " (no gap seen; the driver did not report roam timing)"
        self.telemetry.emit(
            "windows_roam",
            f"Windows roamed {prev.bssid} -> {link.bssid} ({cls}){timing}",
            src=prev.bssid,
            dst=link.bssid,
            candidate_class=cls,
            duration_ms=duration_ms,
            outage_s=None if outage_s is None else round(outage_s, 2),
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
                stage = " - failed in the 802.1X/security step" if is_auth_reason(ev.reason_code) else ""
                self.telemetry.emit(
                    "warning",
                    f"Windows reported a failed connection attempt: {self.adapter.reason_text(ev.reason_code)}{stage}",
                    reason_code=ev.reason_code,
                )

    def _handle_probe_events(self) -> None:
        if self.probe is not None:
            for ev in self.probe.poll():
                self._on_probe_event(ev)

    def _on_probe_event(self, ev: ProbeEvent) -> None:
        o = ev.outage
        label = "" if self.probe is None else self.probe.label
        since = format_clock(o.start_wall)
        if ev.kind == "down":
            self.telemetry.emit("net_down", f"no answer from {label} since {since}", target=label, since=o.start_wall)
            return
        self.session_outages["internet"].append(o.duration_s)
        self.store.record_outage(
            OutageRecord(
                started_at=o.start_wall,
                duration_ms=o.duration_s * 1000.0,
                layer="internet",
                mode=self._mode(),
                to_bssid=None if self._last_connected is None else self._last_connected.bssid,
                detail={"target": label, "lost": o.lost, "ongoing": o.ongoing},
            )
        )
        if ev.kind == "up":
            msg = f"internet answers again after {o.duration_s:.1f} s (no answer since {since}, {o.lost} probes lost)"
        else:
            msg = f"stopped while the internet was not answering ({o.duration_s:.1f} s since {since})"
        self.telemetry.emit("net_up", msg, target=label, outage_s=round(o.duration_s, 2), lost=o.lost)

    def _finish_session(self) -> None:
        """Count outages still running at the end: stopping mid-outage must not hide one."""
        if self.probe is not None:
            for ev in self.probe.stop():
                self._on_probe_event(ev)
        if self._down_since is not None and self._last_connected is not None:
            outage_s = self.adapter.now() - self._down_since
            self._loss["ongoing"] = True
            self._record_wifi_outage(outage_s, self._last_connected.bssid, None)
            self._down_since = None
            self.telemetry.emit("link_down", f"stopped while the Wi-Fi link was down ({outage_s:.1f} s so far)")

    def session_summary(self) -> str:
        parts = []
        for layer, label in (("wifi", "Wi-Fi link"), ("internet", "internet")):
            if layer == "internet" and self.probe is None:
                continue
            values = self.session_outages[layer]
            if values:
                parts.append(f"{label} lost {len(values)}x, {sum(values):.1f} s in total (longest {max(values):.1f} s)")
            else:
                parts.append(f"{label} never lost")
        return "; ".join(parts)

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
        self._recent_raw.clear()

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
        wall_start = self.wall_clock()
        signal_before = self._loss_context()
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
        c = outcome.connect
        # Our own switches count as outages too, measured from the request - which
        # can only make RoamPredict look worse, never better, than Windows alone.
        went_down = c is not None and (c.disconnect_seen or c.final_bssid != link.bssid)
        if went_down:
            self._down_wall = wall_start
            self._loss = {**signal_before, "initiator": "roampredict"}
        if new_link.connected and new_link.bssid is not None:
            if new_link.bssid != link.bssid:
                self.store.record_association(new_link.bssid, new_link.ssid, wall, "roampredict")
                self._note_association(new_link.bssid, t_end)
                self._recently_left[link.bssid] = wall
            if went_down and c is not None:
                own_s = c.total_ms / 1000.0 if outcome.success else t_end - t_start
                self._record_wifi_outage(own_s, link.bssid, new_link.bssid)
            self._last_connected = new_link
            self._down_since = None
            self._down_wall = None
        else:
            self._down_since = t_start  # the reconnect by Windows will close this outage
            if self._down_wall is None:
                self._down_wall = wall_start
        self._link = new_link
        self._reset_signal()

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


def _describe_loss(loss: dict[str, Any]) -> str:
    if "smoothed" not in loss:
        return ""
    slope = loss.get("slope")
    trend = "" if slope is None else f", slope {slope:+.1f} dB/s"
    estimated = " (estimated)" if loss.get("rssi_source") == "quality" else ""
    readings = " ".join(str(r) for r in loss.get("readings", []))
    return f" - just before: {loss['smoothed']:.1f} dBm{estimated}{trend}, state {loss['state']}; last readings: {readings}"
