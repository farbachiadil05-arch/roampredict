from pathlib import Path

import pytest

from roampredict.config import AppConfig, ConfigError, load_config

EXAMPLE = Path(__file__).resolve().parent.parent / "config.example.toml"


def test_defaults_are_safe():
    cfg = load_config()
    assert isinstance(cfg, AppConfig)
    assert cfg.safety.dry_run is True
    assert cfg.safety.allowed_ssids == ()
    assert cfg.state.roam_threshold_dbm == -75.0
    assert cfg.executor.min_gain_db == 8.0
    assert cfg.predictor.recent_assoc_ttl_s == 12 * 3600


def test_example_file_loads_and_values_are_wired_through():
    cfg = load_config(EXAMPLE)
    assert cfg.safety.allowed_ssids == ("eduroam",)
    assert cfg.safety.dry_run is True
    assert cfg.predictor.min_gain_db == cfg.executor.min_gain_db == 8
    assert cfg.safety.min_roam_interval_s == cfg.state.cooldown_s == 20
    assert cfg.predictor.recent_assoc_ttl_s == 12 * 3600
    assert cfg.engine.defer_to_learned is True and cfg.engine.sample_hz == 4
    assert cfg.trend.window_s == 3.0 and cfg.filter.smoother == "ema"


def test_mapping_of_user_sections():
    cfg = load_config(
        data={
            "thresholds": {"roam_threshold_dbm": -72, "degrade_enter_dbm": -64, "degrade_exit_dbm": -60},
            "roam": {"min_gain_db": 10, "cooldown_s": 30, "wait_for_usual_next_ap": False},
            "ranking": {"recent_assoc_ttl_hours": 4, "w_learned": 0.5},
            "safety": {"allowed_ssids": ["eduroam", "Campus"], "deny_bssids": ["AA-BB-CC-DD-EE-02"]},
            "signal": {"smoother": "kalman", "sample_hz": 5},
            "adapter": {"interface": "AX211"},
        }
    )
    assert cfg.state.roam_threshold_dbm == -72
    assert cfg.executor.min_gain_db == cfg.predictor.min_gain_db == 10
    assert cfg.safety.min_roam_interval_s == 30
    assert cfg.predictor.recent_assoc_ttl_s == 4 * 3600
    assert cfg.predictor.weights.learned == 0.5
    assert cfg.safety.deny_bssids == ("aa:bb:cc:dd:ee:02",)
    assert cfg.engine.defer_to_learned is False and cfg.engine.sample_hz == 5
    assert cfg.filter.smoother == "kalman" and cfg.interface == "AX211"


@pytest.mark.parametrize(
    "data, message",
    [
        ({"sefety": {}}, "unknown section"),
        ({"safety": {"dryrun": True}}, "unknown key safety.dryrun"),
        ({"safety": {"dry_run": "no"}}, "must be a bool"),
        ({"roam": {"min_gain_db": True}}, "must be a float"),
        ({"safety": {"allowed_ssids": "eduroam"}}, "list of strings"),
        ({"signal": {"spike_confirm": 2.5}}, "must be a int"),
        ({"thresholds": {"degrade_exit_dbm": -70}}, "degrade_exit_dbm"),
        ({"safety": {"deny_bssids": ["ff:ff:ff:ff:ff:ff"]}}, "broadcast"),
        ({"signal": {"smoother": "median"}}, "smoother"),
        ({"roam": {"auth_stall_s": 30}}, "auth_stall_s"),
    ],
)
def test_invalid_configs_are_rejected_with_a_clear_message(data, message):
    with pytest.raises(ConfigError, match=message):
        load_config(data=data)


def test_file_errors(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "missing.toml")
    bad = tmp_path / "bad.toml"
    bad.write_text("[safety\ndry_run = true\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="bad.toml"):
        load_config(bad)


def test_overrides_and_paths(tmp_path, monkeypatch):
    monkeypatch.setenv("RP_TEST_DIR", str(tmp_path))
    cfg = load_config(data={"paths": {"data_dir": "$RP_TEST_DIR/rp"}})
    assert cfg.paths.data_dir == tmp_path / "rp"
    assert cfg.paths.db == tmp_path / "rp" / "roampredict.db"
    assert cfg.paths.kill_file.name == "KILL"
    assert cfg.with_active(True).safety.dry_run is False
    assert cfg.with_interface(None) is cfg
    assert cfg.with_interface("Intel").interface == "Intel"
