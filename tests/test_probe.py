"""Internet outages from probe results: tracker logic and the background probe."""

import time

import pytest

from roampredict.net.probe import ConnectivityProbe, Outage, OutageTracker, format_clock

WALL0 = 1_700_000_000.0


def feed(tracker, results, interval=0.25, rtt=0.02):
    """Probe results (True = answered) every ``interval`` s; returns the events."""
    events = []
    t = 0.0
    for answered in results:
        done = t + (rtt if answered else 0.001)
        ev = tracker.add(t, WALL0 + t, done, answered)
        if ev is not None:
            events.append((t, ev))
        t += interval
    return events


def test_a_single_lost_probe_is_not_an_outage():
    tracker = OutageTracker()
    assert feed(tracker, [True, False, True, True]) == []
    assert tracker.outages == [] and tracker.total_s == 0.0 and tracker.longest is None


def test_outage_runs_from_the_first_lost_probe_to_the_first_answer():
    tracker = OutageTracker()
    events = feed(tracker, [True, False, False, False, True])
    assert [ev.kind for _, ev in events] == ["down", "up"]
    down_t, down = events[0]
    assert down_t == pytest.approx(0.5) and down.outage.start_wall == pytest.approx(WALL0 + 0.25)
    up = events[1][1].outage
    assert up.lost == 3 and not up.ongoing
    assert up.duration_s == pytest.approx(1.0 + 0.02 - 0.25)  # sent at 0.25 s, answer back at 1.02 s
    assert tracker.outages == [up] and tracker.longest is up


def test_finish_counts_an_outage_that_is_still_running():
    tracker = OutageTracker()
    feed(tracker, [True, False, False])
    ev = tracker.finish(now=2.0)
    assert ev is not None and ev.kind == "end" and ev.outage.ongoing
    assert ev.outage.duration_s == pytest.approx(1.75)
    assert tracker.finish(now=3.0) is None  # nothing left
    lone = OutageTracker()
    feed(lone, [True, False])
    assert lone.finish(now=1.0) is None  # one lost probe at the end is still not an outage


def test_tracker_validation_and_text():
    with pytest.raises(ValueError):
        OutageTracker(min_lost=0)
    text = Outage(WALL0, 6.25, 25).describe()
    assert "6.2 s" in text or "6.3 s" in text
    assert "(25 probes lost)" in text and format_clock(WALL0) in text
    assert format_clock(WALL0 + 0.75).endswith(".7")


class ScriptedPinger:
    timeout_s = 0.05

    def __init__(self, results):
        self.results = list(results)

    def ping(self):
        answered = self.results.pop(0) if self.results else True
        return 12.0 if answered else None


def test_probe_once_with_virtual_clocks():
    now = [0.0]
    probe = ConnectivityProbe(
        ScriptedPinger([True, False, False, True]),
        "example.org:443",
        clock=lambda: now[0],
        wall=lambda: WALL0 + now[0],
    )
    kinds = []
    for _ in range(4):
        probe.probe_once()
        kinds += [ev.kind for ev in probe.poll()]
        now[0] += 0.25
    assert kinds == ["down", "up"]
    assert (probe.probes, probe.lost) == (4, 2)
    assert probe.stop() == []  # never started: stopping is harmless


def test_background_thread_reports_an_outage_still_running_at_stop():
    probe = ConnectivityProbe(ScriptedPinger([True] + [False] * 1000), "example.org:443", interval_s=0.01)
    probe.start()
    deadline = time.monotonic() + 5.0
    seen = []
    while time.monotonic() < deadline and not seen:
        seen = probe.poll()
        time.sleep(0.01)
    assert seen and seen[0].kind == "down"
    final = probe.stop()
    assert final and final[-1].kind == "end" and final[-1].outage.ongoing
    with pytest.raises(ValueError):
        ConnectivityProbe(ScriptedPinger([]), "x", interval_s=0)
