"""Latency under load ("bufferbloat") and resetting RoamPredict's own sockets.

Honest scope: Python cannot flush the Wi-Fi driver's transmit queue on
Windows, and RoamPredict does not touch other programs' connections.  What
this module does:

* :class:`SocketRegistry` - RoamPredict's own sockets register here and are
  closed after a switch, so they reconnect over the new path instead of
  waiting for stale TCP retransmissions.
* :func:`measure_latency` / :func:`bufferbloat_test` - ping while idle and
  while a download runs, to show how much queueing delay the link adds.  Run
  it before and after a switch (or at different spots) to compare.

Pingers: ICMP through ``IcmpSendEcho`` on Windows (no admin needed), or the
time of a TCP connect anywhere (useful when a campus network blocks ICMP).
"""

from __future__ import annotations

import http.client
import socket
import ssl
import statistics
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urljoin, urlsplit

__all__ = [
    "SocketRegistry",
    "SOCKETS",
    "Pinger",
    "TcpPinger",
    "IcmpPinger",
    "LatencyStats",
    "measure_latency",
    "DownloadLoad",
    "BufferbloatResult",
    "bufferbloat_test",
]


class SocketRegistry:
    """RoamPredict's own sockets (never anybody else's)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sockets: set[socket.socket] = set()

    def register(self, sock: socket.socket) -> socket.socket:
        with self._lock:
            self._sockets.add(sock)
        return sock

    def unregister(self, sock: socket.socket) -> None:
        with self._lock:
            self._sockets.discard(sock)

    def __len__(self) -> int:
        with self._lock:
            return len(self._sockets)

    def reset_all(self) -> int:
        """Close every registered socket; returns how many were closed."""
        with self._lock:
            sockets, self._sockets = self._sockets, set()
        for sock in sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass
        return len(sockets)


SOCKETS = SocketRegistry()


class Pinger(Protocol):
    description: str

    def ping(self) -> float | None:
        """Round-trip time in ms, or None if lost."""


class TcpPinger:
    """Latency = time to complete a TCP handshake (works where ICMP is blocked)."""

    def __init__(self, host: str, port: int = 443, timeout_s: float = 1.0) -> None:
        if not 0 < port < 65536:
            raise ValueError("port must be 1..65535")
        self.host = host
        self.port = port
        self.timeout_s = timeout_s
        self.description = f"TCP connect to {host}:{port}"

    def ping(self) -> float | None:
        started = time.perf_counter()
        try:
            sock = socket.create_connection((self.host, self.port), timeout=self.timeout_s)
        except OSError:
            return None
        rtt = (time.perf_counter() - started) * 1000.0
        SOCKETS.register(sock)
        try:
            sock.close()
        finally:
            SOCKETS.unregister(sock)
        return rtt


class IcmpPinger:
    """ICMP echo through Windows' IcmpSendEcho (no admin rights needed)."""

    def __init__(self, host: str, timeout_ms: int = 1000) -> None:
        from roampredict.net.l3 import WindowsNetworkOps

        self._net = WindowsNetworkOps()
        self.host = host
        self.timeout_ms = timeout_ms
        self.description = f"ICMP ping to {host}"

    def ping(self) -> float | None:
        result = self._net.ping(self.host, self.timeout_ms)
        return result.rtt_ms if result.ok else None


@dataclass(frozen=True)
class LatencyStats:
    n: int
    lost: int
    min_ms: float | None
    median_ms: float | None
    p90_ms: float | None
    max_ms: float | None

    @staticmethod
    def from_samples(samples: list[float | None]) -> LatencyStats:
        ok = sorted(s for s in samples if s is not None)
        if not ok:
            return LatencyStats(len(samples), len(samples), None, None, None, None)
        p90 = ok[min(len(ok) - 1, int(round(0.9 * (len(ok) - 1))))]
        return LatencyStats(len(samples), len(samples) - len(ok), ok[0], statistics.median(ok), p90, ok[-1])

    def describe(self) -> str:
        if self.median_ms is None:
            return f"all {self.n} probes lost"
        return (
            f"median {self.median_ms:.1f} ms, p90 {self.p90_ms:.1f} ms, min {self.min_ms:.1f}, max {self.max_ms:.1f} "
            f"({self.lost}/{self.n} lost)"
        )


def measure_latency(
    pinger: Pinger,
    seconds: float,
    interval_s: float = 0.2,
    *,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> LatencyStats:
    samples: list[float | None] = []
    end = clock() + seconds
    while clock() < end:
        started = clock()
        samples.append(pinger.ping())
        remaining = interval_s - (clock() - started)
        if remaining > 0:
            sleep(remaining)
    return LatencyStats.from_samples(samples)


class DownloadLoad(threading.Thread):
    """Downloads ``url`` (http/https) for up to ``max_seconds`` to load the link."""

    def __init__(self, url: str, max_seconds: float, chunk_size: int = 64 * 1024) -> None:
        super().__init__(daemon=True, name="roampredict-load")
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError("the load URL must be http:// or https:// with a host name")
        self.url = url
        self.max_seconds = max_seconds
        self.chunk_size = chunk_size
        self.bytes_read = 0
        self.error: str | None = None
        self.started_at: float | None = None
        self.finished_at: float | None = None
        self._stop_event = threading.Event()

    def stop(self) -> None:
        self._stop_event.set()

    def _open(self, url: str, redirects: int = 3) -> tuple[http.client.HTTPConnection, http.client.HTTPResponse, socket.socket | None]:
        parts = urlsplit(url)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        conn: http.client.HTTPConnection
        if parts.scheme == "https":
            conn = http.client.HTTPSConnection(parts.hostname, parts.port, timeout=10, context=ssl.create_default_context())
        else:
            conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=10)
        conn.request("GET", path, headers={"User-Agent": "RoamPredict latency test"})
        # Keep the socket object itself: http.client may hand it over to the
        # response and set conn.sock to None.
        sock = conn.sock
        if sock is not None:
            SOCKETS.register(sock)
        resp = conn.getresponse()
        if resp.status in (301, 302, 303, 307, 308) and redirects > 0:
            location = resp.getheader("Location")
            self._close(conn, resp, sock)
            if not location:
                raise OSError(f"redirect without a Location header from {url}")
            return self._open(urljoin(url, location), redirects - 1)
        if resp.status != 200:
            status = resp.status
            self._close(conn, resp, sock)
            raise OSError(f"HTTP {status} from {url}")
        return conn, resp, sock

    @staticmethod
    def _close(conn: http.client.HTTPConnection, resp: http.client.HTTPResponse | None, sock: socket.socket | None) -> None:
        if sock is not None:
            SOCKETS.unregister(sock)
        if resp is not None:
            resp.close()
        conn.close()

    def run(self) -> None:
        self.started_at = time.monotonic()
        opened = None
        try:
            opened = self._open(self.url)
            _, resp, _ = opened
            while not self._stop_event.is_set() and time.monotonic() - self.started_at < self.max_seconds:
                chunk = resp.read(self.chunk_size)
                if not chunk:
                    break
                self.bytes_read += len(chunk)
        except (OSError, http.client.HTTPException, ValueError) as exc:
            self.error = str(exc)
        finally:
            self.finished_at = time.monotonic()
            if opened is not None:
                self._close(*opened)

    @property
    def mbps(self) -> float | None:
        if self.started_at is None or self.finished_at is None or self.finished_at <= self.started_at:
            return None
        return self.bytes_read * 8 / (self.finished_at - self.started_at) / 1e6


@dataclass(frozen=True)
class BufferbloatResult:
    idle: LatencyStats
    loaded: LatencyStats
    download_mbps: float | None
    error: str | None

    @property
    def added_ms(self) -> float | None:
        if self.idle.median_ms is None or self.loaded.median_ms is None:
            return None
        return self.loaded.median_ms - self.idle.median_ms

    def verdict(self) -> str:
        added = self.added_ms
        if added is None:
            return "could not measure"
        if added < 30:
            return f"low queueing delay (+{added:.0f} ms under load)"
        if added < 100:
            return f"moderate queueing delay (+{added:.0f} ms under load)"
        return f"high queueing delay (+{added:.0f} ms under load) - calls and games will lag while downloading"


def bufferbloat_test(
    pinger: Pinger,
    url: str,
    idle_s: float = 10.0,
    load_s: float = 10.0,
    interval_s: float = 0.2,
    ramp_s: float = 1.0,
) -> BufferbloatResult:
    idle = measure_latency(pinger, idle_s, interval_s)
    load = DownloadLoad(url, max_seconds=ramp_s + load_s + 5)
    load.start()
    time.sleep(ramp_s)
    loaded = measure_latency(pinger, load_s, interval_s)
    load.stop()
    load.join(timeout=5)
    return BufferbloatResult(idle=idle, loaded=loaded, download_mbps=load.mbps, error=load.error)
