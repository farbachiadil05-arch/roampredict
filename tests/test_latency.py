import http.server
import socket
import threading

import pytest

from roampredict.net.latency import (
    SOCKETS,
    BufferbloatResult,
    DownloadLoad,
    LatencyStats,
    SocketRegistry,
    TcpPinger,
    failure_kind,
    bufferbloat_test,
    measure_latency,
)

PAYLOAD = b"x" * (2 * 1024 * 1024)


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path == "/big":
            self.send_response(200)
            self.send_header("Content-Length", str(len(PAYLOAD)))
            self.end_headers()
            self.wfile.write(PAYLOAD)
        elif self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/big")
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self.send_error(404)

    def log_message(self, *args):
        pass


@pytest.fixture
def server():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def test_stats_from_samples():
    stats = LatencyStats.from_samples([10.0, None, 30.0, 20.0, 40.0])
    assert (stats.n, stats.lost, stats.min_ms, stats.median_ms, stats.max_ms) == (5, 1, 10.0, 25.0, 40.0)
    assert "1/5 lost" in stats.describe()
    empty = LatencyStats.from_samples([None, None])
    assert empty.median_ms is None and "lost" in empty.describe()


def test_measure_latency_with_a_virtual_clock():
    now = [0.0]

    class Fake:
        description = "fake"

        def ping(self):
            now[0] += 0.01
            return 5.0

    stats = measure_latency(Fake(), 1.0, 0.2, clock=lambda: now[0], sleep=lambda s: now.__setitem__(0, now[0] + s))
    assert stats.n == 5 and stats.median_ms == 5.0


def test_tcp_pinger(server):
    port = int(server.rsplit(":", 1)[1])
    assert TcpPinger("127.0.0.1", port).ping() is not None
    with socket.socket() as s:  # a port nobody listens on
        s.bind(("127.0.0.1", 0))
        closed_port = s.getsockname()[1]
    refused = TcpPinger("127.0.0.1", closed_port, timeout_s=0.5)
    assert refused.ping() is None
    assert list(refused.failures) == [failure_kind(ConnectionRefusedError())]
    with pytest.raises(ValueError):
        TcpPinger("127.0.0.1", 0)


def test_socket_registry_closes_only_its_own_sockets():
    reg = SocketRegistry()
    a, b = socket.socketpair()
    other, other2 = socket.socketpair()
    reg.register(a)
    reg.register(b)
    assert reg.reset_all() == 2 and len(reg) == 0
    assert a.fileno() == -1 and b.fileno() == -1
    assert other.fileno() != -1  # not registered: untouched
    other.close()
    other2.close()


def test_download_load_follows_redirects(server):
    load = DownloadLoad(server + "/redirect", max_seconds=10)
    load.start()
    load.join(10)
    assert load.error is None and load.bytes_read == len(PAYLOAD)
    assert load.mbps and load.mbps > 0
    assert len(SOCKETS) == 0  # its socket was registered and released


def test_download_errors_are_reported(server):
    load = DownloadLoad(server + "/nothing", max_seconds=5)
    load.run()
    assert "404" in load.error
    with pytest.raises(ValueError):
        DownloadLoad("ftp://example.org/file", 5)


def test_bufferbloat_test_end_to_end(server):
    class Pinger:
        description = "fake"

        def ping(self):
            return 12.0

    result = bufferbloat_test(Pinger(), server + "/big", idle_s=0.3, load_s=0.3, interval_s=0.1, ramp_s=0.05)
    assert result.idle.median_ms == 12.0 and result.loaded.median_ms == 12.0
    assert result.added_ms == 0.0 and "low" in result.verdict()


def test_verdicts():
    idle = LatencyStats.from_samples([10.0])
    assert "moderate" in BufferbloatResult(idle, LatencyStats.from_samples([70.0]), None, None).verdict()
    assert "high" in BufferbloatResult(idle, LatencyStats.from_samples([300.0]), None, None).verdict()
    assert "could not" in BufferbloatResult(idle, LatencyStats.from_samples([None]), None, None).verdict()


def test_failure_kinds_are_plain_words():
    assert failure_kind(socket.timeout()).startswith("timeout")
    assert failure_kind(socket.gaierror(11001, "getaddrinfo failed")).startswith("name lookup")
    assert failure_kind(ConnectionRefusedError()).startswith("refused")
    assert failure_kind(OSError(101, "Network is unreachable")).startswith("network/host unreachable")
    assert failure_kind(OSError(5, "weird")).startswith("other error")


def test_tcp_pinger_looks_the_name_up_only_once(server, monkeypatch):
    port = int(server.rsplit(":", 1)[1])
    lookups = []
    real = socket.getaddrinfo

    def counting(*args, **kwargs):
        lookups.append(args[0])
        return real(*args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", counting)
    pinger = TcpPinger("localhost", port)
    assert pinger.ping() is not None and pinger.ping() is not None
    assert lookups == ["localhost"]  # a slow DNS server can no longer inflate the latency
    assert pinger.address in ("127.0.0.1", "::1") and "localhost (" in pinger.description
    with pytest.raises(ValueError):
        TcpPinger("bad host", 443)


def test_dns_failure_is_a_lost_probe_not_a_crash(monkeypatch):
    def no_dns(*args, **kwargs):
        raise socket.gaierror(11001, "getaddrinfo failed")

    monkeypatch.setattr(socket, "getaddrinfo", no_dns)
    pinger = TcpPinger("www.example.org", 443)
    assert pinger.ping() is None
    assert list(pinger.failures) == ["name lookup failed (DNS)"]


def test_measure_latency_reports_outages_with_times():
    now = [0.0]
    answers = [True] * 4 + [False] * 10 + [True] * 6

    class Fake:
        description = "fake"

        def ping(self):
            now[0] += 0.01
            return 5.0 if (answers.pop(0) if answers else True) else None

    stats = measure_latency(
        Fake(), 4.0, 0.2, clock=lambda: now[0], sleep=lambda s: now.__setitem__(0, now[0] + s), wall=lambda: 1e9 + now[0]
    )
    assert stats.lost == 10 and len(stats.outages) == 1
    outage = stats.outages[0]
    assert outage.lost == 10 and outage.duration_s == pytest.approx(2.01, abs=0.02)
    lines = stats.describe_outages()
    assert "2.0 s in 1 outage(s)" in lines[0] and "(10 probes lost)" in lines[1]
    assert LatencyStats.from_samples([5.0]).describe_outages() == ["no outage (never 2 unanswered probes in a row)"]
