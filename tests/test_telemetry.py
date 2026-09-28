import io
import json

from roampredict.telemetry import Telemetry, scrub


def test_scrub_removes_credential_like_fields():
    data = {
        "bssid": "02:00:00:00:00:01",
        "Password": "hunter2",
        "nested": {"user_identity": "alice@uni.it", "ok": 1, "list": [{"eap_username": "x"}]},
    }
    clean = scrub(data)
    assert clean["bssid"] == "02:00:00:00:00:01"
    assert clean["Password"] == "[removed]"
    assert clean["nested"]["user_identity"] == "[removed]"
    assert clean["nested"]["ok"] == 1
    assert clean["nested"]["list"][0]["eap_username"] == "[removed]"


def test_jsonl_and_ascii_console(tmp_path):
    out = io.StringIO()
    log = tmp_path / "logs" / "events.jsonl"
    tel = Telemetry(log, console=True, stream=out, keep_in_memory=True)
    tel.emit("state", "STABLE -> DEGRADING → café", rssi=-68.2, secret="x")
    tel.emit("sample", "not shown on the console")
    tel.close()
    lines = log.read_text(encoding="utf-8").splitlines()
    first = json.loads(lines[0])
    assert first["kind"] == "state" and first["rssi"] == -68.2 and first["secret"] == "[removed]"
    assert len(lines) == 2
    console = out.getvalue()
    console.encode("ascii")  # plain ASCII only
    assert "STATE" in console and "not shown" not in console
    assert tel.counters["state"] == 1
    assert [e["kind"] for e in tel.events()] == ["state", "sample"]
