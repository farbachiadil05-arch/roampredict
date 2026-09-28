import sys

import pytest

from roampredict.doctor import DoctorSettings, format_checks, run_doctor


@pytest.mark.skipif(sys.platform == "win32", reason="checks the non-Windows path")
def test_doctor_runs_without_windows(tmp_path):
    settings = DoctorSettings(data_dir=tmp_path / "data", kill_file=tmp_path / "data" / "KILL")
    checks = run_doctor(settings)
    by = {c.name: c for c in checks}
    assert by["Python"].status == "OK"
    assert by["Wi-Fi checks"].status == "SKIP"
    assert by["Data folder"].status == "OK"
    assert by["Kill switch"].status == "OK"
    text = format_checks(checks)
    text.encode("ascii")
    assert "0 problem(s)" in text


def test_doctor_reports_an_active_kill_switch(tmp_path):
    (tmp_path / "KILL").write_text("stopped", encoding="utf-8")
    checks = run_doctor(DoctorSettings(data_dir=tmp_path, kill_file=tmp_path / "KILL", dry_run=False))
    by = {c.name: c for c in checks}
    assert by["Kill switch"].status == "WARN" and "unkill" in by["Kill switch"].hint
    assert "ACTIVE" in by["Mode"].detail
