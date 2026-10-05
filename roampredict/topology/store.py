"""SQLite topology memory.

Tables:

* ``bss``           - every access point seen: SSID, channel, last/max RSSI,
                      first/last seen, advertised 802.11r/k/v support.
* ``associations``  - one row each time we were associated with a BSSID
                      (used for the "recently connected" / cached-key score).
* ``transitions``   - how often we went from BSSID A to BSSID B (learned
                      "usual next AP").
* ``switch_events`` - measured switch timings, ours and Windows' own.
* ``outages``       - every stretch without a Wi-Fi link (or, with the
                      internet probe, without an answer from the internet),
                      tagged with the mode RoamPredict ran in, so walks with
                      Windows alone can be compared with active walks.

All times are wall-clock UNIX seconds passed in by the caller (the simulator
passes virtual time).  No credentials of any kind are stored - there is no
column that could hold one.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from statistics import median
from typing import Any

from roampredict.validate import ValidationError, normalize_bssid

__all__ = [
    "Sighting",
    "BssRecord",
    "SwitchRecord",
    "SwitchStats",
    "OutageRecord",
    "OutageStats",
    "TopologyStore",
    "SCHEMA_VERSION",
]

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS bss (
    bssid      TEXT PRIMARY KEY,
    ssid       TEXT NOT NULL,
    channel    INTEGER,
    freq_mhz   INTEGER,
    band       TEXT,
    last_rssi  REAL,
    max_rssi   REAL,
    first_seen REAL NOT NULL,
    last_seen  REAL NOT NULL,
    seen_count INTEGER NOT NULL DEFAULT 0,
    ft         INTEGER,
    rrm        INTEGER,
    btm        INTEGER,
    preauth    INTEGER,
    mdid       TEXT
);
CREATE INDEX IF NOT EXISTS bss_ssid ON bss(ssid);
CREATE TABLE IF NOT EXISTS associations (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    bssid  TEXT NOT NULL,
    ssid   TEXT,
    at     REAL NOT NULL,
    source TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS assoc_bssid_at ON associations(bssid, at);
CREATE TABLE IF NOT EXISTS transitions (
    from_bssid TEXT NOT NULL,
    to_bssid   TEXT NOT NULL,
    count      INTEGER NOT NULL DEFAULT 0,
    last_at    REAL NOT NULL,
    PRIMARY KEY (from_bssid, to_bssid)
);
CREATE TABLE IF NOT EXISTS switch_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    at              REAL NOT NULL,
    initiator       TEXT NOT NULL,
    from_bssid      TEXT,
    to_bssid        TEXT,
    requested_bssid TEXT,
    candidate_class TEXT,
    success         INTEGER NOT NULL,
    honored         INTEGER,
    total_ms        REAL,
    assoc_ms        REAL,
    auth_ms         REAL,
    l3_ms           REAL,
    dhcp_ms         REAL,
    gateway_changed INTEGER,
    dry_run         INTEGER NOT NULL DEFAULT 0,
    reason          TEXT,
    detail          TEXT
);
CREATE INDEX IF NOT EXISTS switch_at ON switch_events(at);
CREATE TABLE IF NOT EXISTS outages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  REAL NOT NULL,
    duration_ms REAL NOT NULL,
    layer       TEXT NOT NULL,
    mode        TEXT NOT NULL,
    from_bssid  TEXT,
    to_bssid    TEXT,
    last_rssi   REAL,
    detail      TEXT
);
CREATE INDEX IF NOT EXISTS outage_at ON outages(started_at);
"""

_INITIATORS = frozenset({"roampredict", "windows"})
_CLASSES = frozenset({"recent", "expired", "never"})
_LAYERS = frozenset({"wifi", "internet"})  # no Wi-Fi link / no answer from the internet probe
_MODES = frozenset({"dry-run", "active"})


@dataclass(frozen=True)
class Sighting:
    bssid: str
    ssid: str
    rssi_dbm: float
    channel: int | None = None
    freq_mhz: int | None = None
    band: str | None = None
    ft: bool | None = None
    rrm: bool | None = None
    btm: bool | None = None
    preauth: bool | None = None
    mdid: str | None = None


@dataclass(frozen=True)
class BssRecord:
    bssid: str
    ssid: str
    channel: int | None
    freq_mhz: int | None
    band: str | None
    last_rssi: float | None
    max_rssi: float | None
    first_seen: float
    last_seen: float
    seen_count: int
    ft: bool | None
    rrm: bool | None
    btm: bool | None
    preauth: bool | None
    mdid: str | None


@dataclass(frozen=True)
class SwitchRecord:
    at: float
    initiator: str  # "roampredict" or "windows"
    success: bool
    from_bssid: str | None = None
    to_bssid: str | None = None
    requested_bssid: str | None = None
    candidate_class: str | None = None  # "recent" | "expired" | "never"
    honored: bool | None = None
    total_ms: float | None = None
    assoc_ms: float | None = None
    auth_ms: float | None = None
    l3_ms: float | None = None
    dhcp_ms: float | None = None
    gateway_changed: bool | None = None
    dry_run: bool = False
    reason: str = ""
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SwitchStats:
    initiator: str
    candidate_class: str
    n: int
    ok: int
    median_total_ms: float | None
    p90_total_ms: float | None
    median_auth_ms: float | None


@dataclass(frozen=True)
class OutageRecord:
    started_at: float  # wall clock, when the link (or the answers) stopped
    duration_ms: float
    layer: str  # "wifi" or "internet"
    mode: str  # "dry-run" (Windows alone decides) or "active" (RoamPredict may switch)
    from_bssid: str | None = None
    to_bssid: str | None = None
    last_rssi: float | None = None  # smoothed signal just before a Wi-Fi loss
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class OutageStats:
    layer: str
    mode: str
    n: int
    total_ms: float
    median_ms: float
    longest_ms: float


def _opt_bool(value: bool | None) -> int | None:
    return None if value is None else int(bool(value))


def _to_bool(value: Any) -> bool | None:
    return None if value is None else bool(value)


def _opt_bssid(value: str | None) -> str | None:
    return None if value is None else normalize_bssid(value)


def _percentile(values: Sequence[float], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    pos = (len(ordered) - 1) * q
    lo = int(pos)
    hi = min(lo + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (pos - lo)


class TopologyStore:
    """Thin, validated wrapper around one SQLite connection (single thread)."""

    def __init__(self, path: str | Path = ":memory:") -> None:
        target = str(path)
        if target != ":memory:":
            Path(target).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(target, timeout=5.0)
        self._conn.row_factory = sqlite3.Row
        if target != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        row = self._conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
        if row is None:
            with self._conn:
                self._conn.execute(
                    "INSERT INTO meta(key, value) VALUES('schema_version', ?)", (str(SCHEMA_VERSION),)
                )
        elif int(row["value"]) != SCHEMA_VERSION:
            raise RuntimeError(f"database schema {row['value']} is not supported (expected {SCHEMA_VERSION})")

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> TopologyStore:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- access points -------------------------------------------------------------

    def upsert_sightings(self, sightings: Iterable[Sighting], now: float) -> int:
        count = 0
        with self._conn:
            for s in sightings:
                bssid = normalize_bssid(s.bssid)
                self._conn.execute(
                    """
                    INSERT INTO bss(bssid, ssid, channel, freq_mhz, band, last_rssi, max_rssi,
                                    first_seen, last_seen, seen_count, ft, rrm, btm, preauth, mdid)
                    VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)
                    ON CONFLICT(bssid) DO UPDATE SET
                        ssid       = excluded.ssid,
                        channel    = COALESCE(excluded.channel, bss.channel),
                        freq_mhz   = COALESCE(excluded.freq_mhz, bss.freq_mhz),
                        band       = COALESCE(excluded.band, bss.band),
                        last_rssi  = excluded.last_rssi,
                        max_rssi   = MAX(COALESCE(bss.max_rssi, excluded.last_rssi), excluded.last_rssi),
                        last_seen  = MAX(bss.last_seen, excluded.last_seen),
                        seen_count = bss.seen_count + 1,
                        ft         = COALESCE(excluded.ft, bss.ft),
                        rrm        = COALESCE(excluded.rrm, bss.rrm),
                        btm        = COALESCE(excluded.btm, bss.btm),
                        preauth    = COALESCE(excluded.preauth, bss.preauth),
                        mdid       = COALESCE(excluded.mdid, bss.mdid)
                    """,
                    (
                        bssid,
                        s.ssid,
                        s.channel,
                        s.freq_mhz,
                        s.band,
                        float(s.rssi_dbm),
                        float(s.rssi_dbm),
                        now,
                        now,
                        _opt_bool(s.ft),
                        _opt_bool(s.rrm),
                        _opt_bool(s.btm),
                        _opt_bool(s.preauth),
                        s.mdid,
                    ),
                )
                count += 1
        return count

    def get_bss(self, bssid: str) -> BssRecord | None:
        row = self._conn.execute("SELECT * FROM bss WHERE bssid=?", (normalize_bssid(bssid),)).fetchone()
        return None if row is None else self._bss_row(row)

    def all_bss(self, ssid: str | None = None) -> list[BssRecord]:
        if ssid is None:
            rows = self._conn.execute("SELECT * FROM bss ORDER BY last_seen DESC").fetchall()
        else:
            rows = self._conn.execute("SELECT * FROM bss WHERE ssid=? ORDER BY last_seen DESC", (ssid,)).fetchall()
        return [self._bss_row(r) for r in rows]

    @staticmethod
    def _bss_row(row: sqlite3.Row) -> BssRecord:
        return BssRecord(
            bssid=row["bssid"],
            ssid=row["ssid"],
            channel=row["channel"],
            freq_mhz=row["freq_mhz"],
            band=row["band"],
            last_rssi=row["last_rssi"],
            max_rssi=row["max_rssi"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            seen_count=row["seen_count"],
            ft=_to_bool(row["ft"]),
            rrm=_to_bool(row["rrm"]),
            btm=_to_bool(row["btm"]),
            preauth=_to_bool(row["preauth"]),
            mdid=row["mdid"],
        )

    # -- associations ("recently connected") ------------------------------------------

    def record_association(self, bssid: str, ssid: str | None, now: float, source: str) -> None:
        if source not in ("roampredict", "windows", "startup"):
            raise ValidationError(f"unknown association source {source!r}")
        with self._conn:
            self._conn.execute(
                "INSERT INTO associations(bssid, ssid, at, source) VALUES(?, ?, ?, ?)",
                (normalize_bssid(bssid), ssid, now, source),
            )

    def last_association(self, bssid: str) -> float | None:
        row = self._conn.execute(
            "SELECT MAX(at) AS at FROM associations WHERE bssid=?", (normalize_bssid(bssid),)
        ).fetchone()
        return None if row is None else row["at"]

    def last_associations(self, bssids: Iterable[str]) -> dict[str, float]:
        keys = sorted({normalize_bssid(b) for b in bssids})
        if not keys:
            return {}
        marks = ",".join("?" * len(keys))
        rows = self._conn.execute(
            f"SELECT bssid, MAX(at) AS at FROM associations WHERE bssid IN ({marks}) GROUP BY bssid", keys
        ).fetchall()
        return {r["bssid"]: r["at"] for r in rows}

    def prune_associations(self, older_than: float) -> int:
        """Delete association rows older than ``older_than`` (keeps the table small)."""
        with self._conn:
            cur = self._conn.execute("DELETE FROM associations WHERE at < ?", (older_than,))
        return cur.rowcount

    # -- transitions (learned "usual next AP") ------------------------------------------

    def record_transition(self, from_bssid: str, to_bssid: str, now: float) -> None:
        a, b = normalize_bssid(from_bssid), normalize_bssid(to_bssid)
        if a == b:
            return
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO transitions(from_bssid, to_bssid, count, last_at) VALUES(?, ?, 1, ?)
                ON CONFLICT(from_bssid, to_bssid) DO UPDATE SET
                    count = transitions.count + 1,
                    last_at = MAX(transitions.last_at, excluded.last_at)
                """,
                (a, b, now),
            )

    def transition_counts(self, from_bssid: str) -> dict[str, int]:
        rows = self._conn.execute(
            "SELECT to_bssid, count FROM transitions WHERE from_bssid=?", (normalize_bssid(from_bssid),)
        ).fetchall()
        return {r["to_bssid"]: int(r["count"]) for r in rows}

    def all_transitions(self, limit: int = 50) -> list[tuple[str, str, int, float]]:
        rows = self._conn.execute(
            "SELECT from_bssid, to_bssid, count, last_at FROM transitions ORDER BY count DESC, last_at DESC LIMIT ?",
            (int(limit),),
        ).fetchall()
        return [(r["from_bssid"], r["to_bssid"], int(r["count"]), r["last_at"]) for r in rows]

    # -- measured switches ------------------------------------------------------------------

    def record_switch(self, rec: SwitchRecord) -> int:
        if rec.initiator not in _INITIATORS:
            raise ValidationError(f"unknown initiator {rec.initiator!r}")
        if rec.candidate_class is not None and rec.candidate_class not in _CLASSES:
            raise ValidationError(f"unknown candidate class {rec.candidate_class!r}")
        with self._conn:
            cur = self._conn.execute(
                """
                INSERT INTO switch_events(at, initiator, from_bssid, to_bssid, requested_bssid,
                    candidate_class, success, honored, total_ms, assoc_ms, auth_ms, l3_ms, dhcp_ms,
                    gateway_changed, dry_run, reason, detail)
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    rec.at,
                    rec.initiator,
                    _opt_bssid(rec.from_bssid),
                    _opt_bssid(rec.to_bssid),
                    _opt_bssid(rec.requested_bssid),
                    rec.candidate_class,
                    int(rec.success),
                    _opt_bool(rec.honored),
                    rec.total_ms,
                    rec.assoc_ms,
                    rec.auth_ms,
                    rec.l3_ms,
                    rec.dhcp_ms,
                    _opt_bool(rec.gateway_changed),
                    int(rec.dry_run),
                    rec.reason,
                    json.dumps(rec.detail, sort_keys=True, default=str),
                ),
            )
        return int(cur.lastrowid or 0)

    def switches(self, since: float | None = None, limit: int | None = None) -> list[SwitchRecord]:
        sql = "SELECT * FROM switch_events"
        args: list[Any] = []
        if since is not None:
            sql += " WHERE at >= ?"
            args.append(since)
        sql += " ORDER BY at DESC"
        if limit is not None:
            sql += " LIMIT ?"
            args.append(int(limit))
        out = []
        for r in self._conn.execute(sql, args).fetchall():
            out.append(
                SwitchRecord(
                    at=r["at"],
                    initiator=r["initiator"],
                    success=bool(r["success"]),
                    from_bssid=r["from_bssid"],
                    to_bssid=r["to_bssid"],
                    requested_bssid=r["requested_bssid"],
                    candidate_class=r["candidate_class"],
                    honored=_to_bool(r["honored"]),
                    total_ms=r["total_ms"],
                    assoc_ms=r["assoc_ms"],
                    auth_ms=r["auth_ms"],
                    l3_ms=r["l3_ms"],
                    dhcp_ms=r["dhcp_ms"],
                    gateway_changed=_to_bool(r["gateway_changed"]),
                    dry_run=bool(r["dry_run"]),
                    reason=r["reason"] or "",
                    detail=json.loads(r["detail"]) if r["detail"] else {},
                )
            )
        return out

    def switch_stats(self, since: float | None = None) -> list[SwitchStats]:
        """Median/p90 switch times grouped by initiator and candidate class.

        Only real (not dry-run) switches with a measured total time count.
        """
        groups: dict[tuple[str, str], list[SwitchRecord]] = {}
        for rec in self.switches(since=since):
            if rec.dry_run:
                continue
            key = (rec.initiator, rec.candidate_class or "unknown")
            groups.setdefault(key, []).append(rec)
        stats = []
        for (initiator, cls), recs in sorted(groups.items()):
            totals = [r.total_ms for r in recs if r.success and r.total_ms is not None]
            auths = [r.auth_ms for r in recs if r.success and r.auth_ms is not None]
            stats.append(
                SwitchStats(
                    initiator=initiator,
                    candidate_class=cls,
                    n=len(recs),
                    ok=sum(1 for r in recs if r.success),
                    median_total_ms=median(totals) if totals else None,
                    p90_total_ms=_percentile(totals, 0.9),
                    median_auth_ms=median(auths) if auths else None,
                )
            )
        return stats

    # -- outages ------------------------------------------------------------------------------

    def record_outage(self, rec: OutageRecord) -> int:
        if rec.layer not in _LAYERS:
            raise ValidationError(f"unknown outage layer {rec.layer!r}")
        if rec.mode not in _MODES:
            raise ValidationError(f"unknown mode {rec.mode!r}")
        if not rec.duration_ms >= 0:
            raise ValidationError("outage duration must be >= 0")
        with self._conn:
            cur = self._conn.execute(
                """
                INSERT INTO outages(started_at, duration_ms, layer, mode, from_bssid, to_bssid, last_rssi, detail)
                VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    rec.started_at,
                    rec.duration_ms,
                    rec.layer,
                    rec.mode,
                    _opt_bssid(rec.from_bssid),
                    _opt_bssid(rec.to_bssid),
                    rec.last_rssi,
                    json.dumps(rec.detail, sort_keys=True, default=str),
                ),
            )
        return int(cur.lastrowid or 0)

    def outages(self, since: float | None = None) -> list[OutageRecord]:
        sql = "SELECT * FROM outages"
        args: list[Any] = []
        if since is not None:
            sql += " WHERE started_at >= ?"
            args.append(since)
        sql += " ORDER BY started_at DESC"
        return [
            OutageRecord(
                started_at=r["started_at"],
                duration_ms=r["duration_ms"],
                layer=r["layer"],
                mode=r["mode"],
                from_bssid=r["from_bssid"],
                to_bssid=r["to_bssid"],
                last_rssi=r["last_rssi"],
                detail=json.loads(r["detail"]) if r["detail"] else {},
            )
            for r in self._conn.execute(sql, args).fetchall()
        ]

    def outage_stats(self, since: float | None = None) -> list[OutageStats]:
        """Count, total, median and longest outage per layer and mode."""
        groups: dict[tuple[str, str], list[float]] = {}
        for rec in self.outages(since=since):
            groups.setdefault((rec.layer, rec.mode), []).append(rec.duration_ms)
        return [
            OutageStats(layer, mode, len(values), sum(values), median(values), max(values))
            for (layer, mode), values in sorted(groups.items())
        ]

    def forget_all(self) -> None:
        """Delete everything RoamPredict has learned."""
        with self._conn:
            for table in ("bss", "associations", "transitions", "switch_events", "outages"):
                self._conn.execute(f"DELETE FROM {table}")  # noqa: S608 - fixed table names
