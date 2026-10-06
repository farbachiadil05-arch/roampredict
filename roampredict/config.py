"""Configuration: defaults, TOML loading and validation.

The file uses a few user-facing sections (see ``config.example.toml``) that
are mapped onto the internal component settings.  Unknown keys are errors, so
a typo cannot silently fall back to a default.  There is no place for a
password, user name or certificate - RoamPredict never needs one.

Default location: ``%LOCALAPPDATA%\\RoamPredict\\config.toml`` on Windows.
"""

from __future__ import annotations

import os
import sys
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from roampredict.engine import EngineConfig
from roampredict.roam.executor import ExecutorConfig
from roampredict.safety import SafetyConfig
from roampredict.signal.filter import FilterConfig
from roampredict.signal.trend import TrendConfig
from roampredict.state_machine import StateMachineConfig
from roampredict.topology.predictor import PredictorConfig, PredictorWeights
from roampredict.validate import ValidationError

__all__ = ["ConfigError", "Paths", "AppConfig", "default_data_dir", "load_config", "find_config", "SCHEMA"]


class ConfigError(ValueError):
    """The config file is invalid (the message says where)."""


def default_data_dir() -> Path:
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "RoamPredict"
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "roampredict"


@dataclass(frozen=True)
class Paths:
    data_dir: Path = field(default_factory=default_data_dir)

    @property
    def db(self) -> Path:
        return self.data_dir / "roampredict.db"

    @property
    def log(self) -> Path:
        return self.data_dir / "logs" / "roampredict.jsonl"

    @property
    def kill_file(self) -> Path:
        return self.data_dir / "KILL"

    @property
    def config(self) -> Path:
        return self.data_dir / "config.toml"


@dataclass(frozen=True)
class AppConfig:
    filter: FilterConfig = field(default_factory=FilterConfig)
    trend: TrendConfig = field(default_factory=TrendConfig)
    state: StateMachineConfig = field(default_factory=StateMachineConfig)
    predictor: PredictorConfig = field(default_factory=PredictorConfig)
    executor: ExecutorConfig = field(default_factory=ExecutorConfig)
    engine: EngineConfig = field(default_factory=EngineConfig)
    safety: SafetyConfig = field(default_factory=SafetyConfig)
    paths: Paths = field(default_factory=Paths)
    interface: str | None = None

    def with_active(self, active: bool) -> AppConfig:
        return replace(self, safety=replace(self.safety, dry_run=not active))

    def with_interface(self, interface: str | None) -> AppConfig:
        return self if interface is None else replace(self, interface=interface)


# section -> key -> expected type (float also accepts int)
SCHEMA: dict[str, dict[str, type]] = {
    "signal": {
        "sample_hz": float,
        "smoother": str,
        "ema_tau_s": float,
        "kalman_process_var": float,
        "kalman_meas_var": float,
        "spike_threshold_db": float,
        "spike_confirm": int,
        "trend_window_s": float,
        "trend_min_points": int,
    },
    "thresholds": {
        "roam_threshold_dbm": float,
        "degrade_enter_dbm": float,
        "degrade_exit_dbm": float,
        "falling_slope_dbm_s": float,
        "degrade_horizon_s": float,
        "imminent_lead_s": float,
        "imminent_exit_margin_db": float,
        "dwell_s": float,
        "recover_dwell_s": float,
        "slope_trigger_margin_db": float,
    },
    "roam": {
        "min_gain_db": float,
        "cooldown_s": float,
        "failure_cooldown_s": float,
        "fresh_scan_max_age_s": float,
        "scan_timeout_s": float,
        "degrading_scan_interval_s": float,
        "connect_timeout_s": float,
        "auth_stall_s": float,
        "fallback_wait_s": float,
        "l3_wait_s": float,
        "arp_flush": bool,
        "dhcp_renew": bool,
        "wait_for_usual_next_ap": bool,
        "probe_trigger": bool,
        "probe_trigger_max_dbm": float,
    },
    "ranking": {
        "w_learned": float,
        "w_rssi": float,
        "w_seen": float,
        "w_recently_connected": float,
        "recent_assoc_ttl_hours": float,
        "seen_tau_s": float,
        "recently_left_block_s": float,
        "min_dwell_learn_s": float,
        "band_2g_penalty_db": float,
    },
    "safety": {
        "dry_run": bool,
        "allowed_ssids": list,
        "allowed_profiles": list,
        "deny_bssids": list,
        "max_roams_per_window": int,
        "rate_window_s": float,
        "max_consecutive_failures": int,
    },
    "paths": {"data_dir": str},
    "adapter": {"interface": str},
}


def _type_ok(value: Any, expected: type) -> bool:
    if expected is bool:
        return isinstance(value, bool)
    if isinstance(value, bool):  # True/False are ints in Python, but not numbers here
        return False
    if expected is float:
        return isinstance(value, (int, float))
    if expected is list:
        return isinstance(value, list) and all(isinstance(v, str) for v in value)
    return isinstance(value, expected)


def _check(raw: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for section, values in raw.items():
        if section not in SCHEMA:
            raise ConfigError(f"unknown section [{section}] (known: {', '.join(SCHEMA)})")
        if not isinstance(values, dict):
            raise ConfigError(f"[{section}] must be a table")
        for key, value in values.items():
            expected = SCHEMA[section].get(key)
            if expected is None:
                raise ConfigError(f"unknown key {section}.{key}")
            if not _type_ok(value, expected):
                kind = "list of strings" if expected is list else expected.__name__
                raise ConfigError(f"{section}.{key} must be a {kind}, got {value!r}")
        out[section] = dict(values)
    return out


def _build(data: dict[str, dict[str, Any]]) -> AppConfig:
    sig = data.get("signal", {})
    thr = data.get("thresholds", {})
    roam = data.get("roam", {})
    rank = data.get("ranking", {})
    saf = data.get("safety", {})

    def pick(src: dict[str, Any], mapping: dict[str, str]) -> dict[str, Any]:
        return {dst: src[key] for key, dst in mapping.items() if key in src}

    filt = FilterConfig(
        **pick(sig, {k: k for k in ("smoother", "ema_tau_s", "kalman_process_var", "kalman_meas_var", "spike_threshold_db", "spike_confirm")})
    )
    trend = TrendConfig(**pick(sig, {"trend_window_s": "window_s", "trend_min_points": "min_points"}))
    state = StateMachineConfig(
        **pick(
            thr,
            {
                k: k
                for k in (
                    "roam_threshold_dbm",
                    "degrade_enter_dbm",
                    "degrade_exit_dbm",
                    "falling_slope_dbm_s",
                    "degrade_horizon_s",
                    "imminent_lead_s",
                    "imminent_exit_margin_db",
                    "dwell_s",
                    "recover_dwell_s",
                    "slope_trigger_margin_db",
                )
            },
        ),
        **pick(roam, {"cooldown_s": "cooldown_s", "failure_cooldown_s": "failure_cooldown_s"}),
    )
    weights = PredictorWeights(
        **pick(
            rank,
            {"w_learned": "learned", "w_rssi": "rssi", "w_seen": "seen_recency", "w_recently_connected": "recently_connected"},
        )
    )
    predictor_kw = pick(
        rank,
        {"seen_tau_s": "seen_tau_s", "recently_left_block_s": "recently_left_block_s", "band_2g_penalty_db": "band_2g_penalty_db"},
    )
    if "recent_assoc_ttl_hours" in rank:
        predictor_kw["recent_assoc_ttl_s"] = float(rank["recent_assoc_ttl_hours"]) * 3600.0
    predictor = PredictorConfig(weights=weights, **predictor_kw, **pick(roam, {"min_gain_db": "min_gain_db"}))
    executor = ExecutorConfig(
        **pick(
            roam,
            {
                k: k
                for k in (
                    "min_gain_db",
                    "fresh_scan_max_age_s",
                    "scan_timeout_s",
                    "connect_timeout_s",
                    "auth_stall_s",
                    "fallback_wait_s",
                    "l3_wait_s",
                    "arp_flush",
                    "dhcp_renew",
                )
            },
        )
    )
    engine_kw = pick(roam, {"probe_trigger_max_dbm": "probe_trigger_max_dbm"})
    if roam.get("probe_trigger") is False:
        engine_kw["probe_trigger_max_dbm"] = None
    engine = EngineConfig(
        **pick(sig, {"sample_hz": "sample_hz"}),
        **pick(roam, {"degrading_scan_interval_s": "degrading_scan_interval_s", "wait_for_usual_next_ap": "defer_to_learned"}),
        **pick(rank, {"min_dwell_learn_s": "min_dwell_learn_s"}),
        **engine_kw,
    )
    safety_kw = pick(
        saf,
        {
            "dry_run": "dry_run",
            "max_roams_per_window": "max_roams_per_window",
            "rate_window_s": "rate_window_s",
            "max_consecutive_failures": "max_consecutive_failures",
        },
    )
    for key in ("allowed_ssids", "allowed_profiles", "deny_bssids"):
        if key in saf:
            safety_kw[key] = tuple(saf[key])
    safety_kw["min_roam_interval_s"] = state.cooldown_s
    safety = SafetyConfig(**safety_kw)
    paths = Paths(Path(os.path.expandvars(data["paths"]["data_dir"])).expanduser()) if "data_dir" in data.get("paths", {}) else Paths()
    interface = data.get("adapter", {}).get("interface") or None
    return AppConfig(filt, trend, state, predictor, executor, engine, safety, paths, interface)


def load_config(path: Path | None = None, *, data: dict[str, Any] | None = None) -> AppConfig:
    """Load and validate a config file (or a dict); defaults for everything missing."""
    raw: dict[str, Any] = {}
    source = "defaults"
    if path is not None:
        source = str(path)
        try:
            with open(path, "rb") as fh:
                raw = tomllib.load(fh)
        except FileNotFoundError as exc:
            raise ConfigError(f"config file not found: {path}") from exc
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"{path}: {exc}") from exc
    elif data is not None:
        raw = data
    try:
        return _build(_check(raw))
    except ConfigError:
        raise
    except (ValueError, ValidationError, TypeError) as exc:
        raise ConfigError(f"{source}: {exc}") from exc


def find_config(explicit: str | None) -> Path | None:
    """``--config`` if given, else the default file if it exists, else None."""
    if explicit:
        return Path(explicit)
    default = Paths().config
    return default if default.exists() else None
