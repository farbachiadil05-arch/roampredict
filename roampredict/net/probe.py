"""Internet outages: how long nothing came back, measured with a steady probe.

The Wi-Fi link being up is not the same as the internet working: after a
reconnect Windows may still be busy with 802.1X, DHCP or ARP.  A probe that
knocks on one internet host a few times per second (a TCP connect, see
:class:`roampredict.net.latency.TcpPinger`) shows the time that really
matters to apps.

* :class:`OutageTracker` turns probe results into outages.  It is plain logic
  with no threads or clocks of its own, so it is easy to test.
* :class:`ConnectivityProbe` runs the probe in a background thread while
  ``roampredict run`` watches the signal; the engine collects its events on
  every tick, so all output appears in one log with one clock.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

__all__ = ["ConnectivityProbe", "Outage", "OutageTracker", "ProbeEvent", "format_clock"]


class _Pinger(Protocol):
    timeout_s: float

    def ping(self) -> float | None: ...


def format_clock(wall: float) -> str:
    """UNIX time as local ``HH:MM:SS.s`` (tenths, to line up with other logs)."""
    tenths = int((wall % 1) * 10)
    return f"{time.strftime('%H:%M:%S', time.localtime(wall))}.{tenths}"


@dataclass(frozen=True)
class Outage:
    start_wall: float  # UNIX time the first unanswered probe was sent
    duration_s: float  # from then until the first answer came back (or until the end)
    lost: int  # probes without an answer
    ongoing: bool = False  # still no answer when the measurement stopped

    def describe(self) -> str:
        end = format_clock(self.start_wall + self.duration_s)
        tail = " (still no answer at the end)" if self.ongoing else ""
        return f"{format_clock(self.start_wall)} -> {end}  {self.duration_s:5.1f} s  ({self.lost} probes lost){tail}"


@dataclass(frozen=True)
class ProbeEvent:
    kind: str  # "down": outage confirmed, "up": answers again, "end": measuring stopped during an outage
    outage: Outage


class OutageTracker:
    """Turns a stream of probe results into outages.

    One unanswered probe is not an outage (a single lost packet happens on any
    busy network); ``min_lost`` unanswered probes in a row are.  An outage runs
    from sending the first unanswered probe until the first answer arrives, so
    it is accurate to about one probe interval.
    """

    def __init__(self, min_lost: int = 2) -> None:
        if min_lost < 1:
            raise ValueError("min_lost must be >= 1")
        self.min_lost = min_lost
        self.outages: list[Outage] = []
        self._first: tuple[float, float] | None = None  # (monotonic, wall) of the first unanswered probe
        self._lost = 0

    def add(self, sent: float, sent_wall: float, done: float, answered: bool) -> ProbeEvent | None:
        """One probe: sent at ``sent`` (monotonic) / ``sent_wall``, finished at ``done``."""
        if not answered:
            if self._first is None:
                self._first = (sent, sent_wall)
            self._lost += 1
            if self._lost == self.min_lost:
                return ProbeEvent("down", Outage(self._first[1], done - self._first[0], self._lost, ongoing=True))
            return None
        event = None
        if self._first is not None and self._lost >= self.min_lost:
            outage = Outage(self._first[1], done - self._first[0], self._lost)
            self.outages.append(outage)
            event = ProbeEvent("up", outage)
        self._first, self._lost = None, 0
        return event

    def finish(self, now: float) -> ProbeEvent | None:
        """Measuring stops: an outage still running counts up to ``now``."""
        first, lost = self._first, self._lost
        self._first, self._lost = None, 0
        if first is None or lost < self.min_lost:
            return None
        outage = Outage(first[1], now - first[0], lost, ongoing=True)
        self.outages.append(outage)
        return ProbeEvent("end", outage)

    @property
    def total_s(self) -> float:
        return sum(o.duration_s for o in self.outages)

    @property
    def longest(self) -> Outage | None:
        return max(self.outages, key=lambda o: o.duration_s, default=None)


class ConnectivityProbe:
    """Probes in a background thread; :meth:`poll` hands the events to the engine."""

    def __init__(
        self,
        pinger: _Pinger,
        label: str,
        interval_s: float = 0.25,
        min_lost: int = 2,
        *,
        clock: Callable[[], float] = time.monotonic,
        wall: Callable[[], float] = time.time,
    ) -> None:
        if interval_s <= 0:
            raise ValueError("interval_s must be > 0")
        self.pinger = pinger
        self.label = label
        self.interval_s = interval_s
        self.tracker = OutageTracker(min_lost)
        self.probes = 0
        self.lost = 0
        self._clock = clock
        self._wall = wall
        self._lock = threading.Lock()
        self._events: list[ProbeEvent] = []
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def probe_once(self) -> float:
        """Send one probe and record it; returns how long it took (seconds)."""
        sent, sent_wall = self._clock(), self._wall()
        rtt = self.pinger.ping()
        done = self._clock()
        with self._lock:
            self.probes += 1
            if rtt is None:
                self.lost += 1
            event = self.tracker.add(sent, sent_wall, done, rtt is not None)
            if event is not None:
                self._events.append(event)
        return done - sent

    def _run(self) -> None:
        while not self._stop_event.is_set():
            took = self.probe_once()
            self._stop_event.wait(max(0.0, self.interval_s - took))

    def start(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(target=self._run, daemon=True, name="roampredict-probe")
            self._thread.start()

    def poll(self) -> list[ProbeEvent]:
        with self._lock:
            events, self._events = self._events, []
        return events

    def stop(self) -> list[ProbeEvent]:
        """Stop probing; returns the events not collected yet (including an outage still running)."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=self.pinger.timeout_s + 1.0)
        with self._lock:
            event = self.tracker.finish(self._clock())
            if event is not None:
                self._events.append(event)
        return self.poll()
