import socket
import time
import sys

import pytest

from roampredict.cli import main
from roampredict.topology.store import SwitchRecord, TopologyStore


@pytest.fixture
def config(tmp_path):
    path = tmp_path / "config.toml"
    data = tmp_path / "data"
    path.write_text(f'[paths]\ndata_dir = "{data.as_posix()}"\n[safety]\nallowed_ssids = ["eduroam"]\n', encoding="utf-8")
    return path, data


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "roampredict" in capsys.readouterr().out


def test_paths_kill_and_unkill(config, capsys):
    path, data = config
    assert main(["paths", "--config", str(path)]) == 0
    assert str(data) in capsys.readouterr().out
    assert main(["kill", "--config", str(path), "--reason", "test"]) == 0
    assert (data / "KILL").exists()
    main(["paths", "--config", str(path)])
    assert "(ACTIVE)" in capsys.readouterr().out
    assert main(["unkill", "--config", str(path)]) == 0
    assert not (data / "KILL").exists()


def test_active_mode_needs_an_allow_list(tmp_path, capsys):
    path = tmp_path / "c.toml"
    path.write_text(f'[paths]\ndata_dir = "{(tmp_path / "d").as_posix()}"\n', encoding="utf-8")
    assert main(["run", "--active", "--config", str(path)]) == 2
    assert "allow-listed" in capsys.readouterr().out


def test_active_mode_refuses_while_killed(config, capsys):
    path, data = config
    main(["kill", "--config", str(path)])
    assert main(["run", "--active", "--config", str(path)]) == 2
    assert "kill switch" in capsys.readouterr().out


@pytest.mark.skipif(sys.platform == "win32", reason="checks the non-Windows message")
def test_run_and_scan_explain_they_need_windows(config, capsys):
    path, _ = config
    assert main(["run", "--config", str(path)]) == 2
    assert main(["scan", "--config", str(path)]) == 2
    assert "needs Windows" in capsys.readouterr().out


def test_report(config, capsys):
    path, data = config
    assert main(["report", "--config", str(path)]) == 0
    assert "No data yet" in capsys.readouterr().out
    with TopologyStore(data / "roampredict.db") as store:
        for ms, cls in ((180, "recent"), (220, "recent"), (1400, "never")):
            store.record_switch(SwitchRecord(at=time.time(), initiator="roampredict", success=True, candidate_class=cls, total_ms=ms))
        store.record_switch(
            SwitchRecord(at=time.time(), initiator="windows", success=True, candidate_class="never", detail={"hit": True, "lead_s": 4.2})
        )
        store.record_transition("02:00:00:00:00:01", "02:00:00:00:00:02", 1.0)
    assert main(["report", "--config", str(path)]) == 0
    out = capsys.readouterr().out
    assert "recent" in out and "200 ms" in out and "1400 ms" in out
    assert "1/1 picked the same AP" in out
    assert "02:00:00:00:00:01 -> 02:00:00:00:00:02" in out


def test_forget_needs_confirmation(config, capsys):
    path, data = config
    with TopologyStore(data / "roampredict.db") as store:
        store.record_transition("02:00:00:00:00:01", "02:00:00:00:00:02", 1.0)
    assert main(["forget", "--config", str(path)]) == 2
    assert main(["forget", "--config", str(path), "--yes"]) == 0
    with TopologyStore(data / "roampredict.db") as store:
        assert store.all_transitions() == []


def test_doctor_command(config, capsys):
    path, _ = config
    code = main(["doctor", "--config", str(path)])
    out = capsys.readouterr().out
    assert "RoamPredict doctor" in out
    assert code == (1 if "FAIL" in out else 0)


def test_config_errors_are_readable(tmp_path, capsys):
    bad = tmp_path / "bad.toml"
    bad.write_text("[safety]\ndry_run = 3\n", encoding="utf-8")
    assert main(["paths", "--config", str(bad)]) == 2
    assert "Config error" in capsys.readouterr().err


def test_simulate_command(tmp_path, capsys):
    code = main(["simulate", "--seeds", "1", "--scenario", "walk_out", "--ft", "off", "--no-plot"])
    assert code == 0
    assert "RoamPredict (predictive)" in capsys.readouterr().out


def test_latency_command_with_tcp_target(capsys):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(64)
    port = listener.getsockname()[1]
    try:
        code = main(["latency", "--target", "127.0.0.1", "--tcp-port", str(port), "--seconds", "0.4"])
    finally:
        listener.close()
    assert code == 0
    assert "median" in capsys.readouterr().out


def test_latency_command_says_why_probes_were_lost(capsys):
    with socket.socket() as s:  # a port nobody listens on
        s.bind(("127.0.0.1", 0))
        closed_port = s.getsockname()[1]
    code = main(["latency", "--target", "127.0.0.1", "--tcp-port", str(closed_port), "--seconds", "0.3"])
    out = capsys.readouterr().out
    assert code == 0
    assert "all" in out and "probes lost" in out
    assert "why probes were lost" in out and "refused" in out
