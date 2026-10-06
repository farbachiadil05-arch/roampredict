"""Candidate ranking.

Each visible AP of the current SSID gets a score in [0, 1]:

    total = ( w_learned * P(next = AP | current AP)      learned from past roams
            + w_rssi    * rssi_norm                       how strong it is now
            + w_seen    * exp(-age / seen_tau)            how recently it was heard
            + w_recent  * max(0, 1 - assoc_age / ttl) )   "recently connected"
            / sum(weights)

"Recently connected" matters on 802.1X networks: standard PMKSA caching is per
AP (per BSSID), so returning to an AP we used a short while ago may skip the
slow EAP exchange.  The TTL (default 12 h) is a GUESS - Windows' documented
default profile PMKCacheTTL is 720 minutes, but the campus APs/RADIUS may drop
keys sooner.  Measure it with ``roampredict report``.

Hard filters (an AP must pass all to be eligible):
  same SSID, not the current AP, not deny-listed, at least ``min_gain_db``
  stronger than the current AP, heard recently enough, and not an AP we just
  left (unless it is overwhelmingly better) - the last one prevents ping-pong.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from roampredict.topology.store import TopologyStore

__all__ = [
    "PredictorWeights",
    "PredictorConfig",
    "CandidateInput",
    "ScoreBreakdown",
    "Predictor",
    "classify_candidate",
]


@dataclass(frozen=True)
class PredictorWeights:
    learned: float = 0.35
    rssi: float = 0.35
    seen_recency: float = 0.10
    recently_connected: float = 0.20

    def __post_init__(self) -> None:
        values = (self.learned, self.rssi, self.seen_recency, self.recently_connected)
        if any(v < 0 for v in values):
            raise ValueError("weights must be >= 0")
        if sum(values) <= 0:
            raise ValueError("at least one weight must be > 0")

    @property
    def total(self) -> float:
        return self.learned + self.rssi + self.seen_recency + self.recently_connected


@dataclass(frozen=True)
class PredictorConfig:
    weights: PredictorWeights = field(default_factory=PredictorWeights)
    min_gain_db: float = 8.0
    rssi_floor_dbm: float = -90.0  # maps to rssi_norm 0
    rssi_ceiling_dbm: float = -45.0  # maps to rssi_norm 1
    seen_tau_s: float = 20.0
    max_candidate_age_s: float = 30.0  # older cache entries are not eligible
    recent_assoc_ttl_s: float = 12 * 3600.0  # GUESS - measure on your network
    laplace_alpha: float = 1.0
    recently_left_block_s: float = 45.0
    recently_left_override_gain_db: float = 12.0
    # 2.4 GHz always reads stronger (about 7 dB less path loss than 5 GHz) but
    # is slower and more crowded, so a 2.4 GHz AP counts this much weaker.
    band_2g_penalty_db: float = 7.0

    def __post_init__(self) -> None:
        if self.rssi_ceiling_dbm <= self.rssi_floor_dbm:
            raise ValueError("rssi_ceiling_dbm must be above rssi_floor_dbm")
        if self.band_2g_penalty_db < 0:
            raise ValueError("band_2g_penalty_db must be >= 0")
        for name in ("seen_tau_s", "max_candidate_age_s", "recent_assoc_ttl_s", "laplace_alpha"):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be > 0")
        if self.min_gain_db < 0 or self.recently_left_block_s < 0:
            raise ValueError("min_gain_db and recently_left_block_s must be >= 0")


@dataclass(frozen=True)
class CandidateInput:
    bssid: str
    ssid: str
    rssi_dbm: float
    age_s: float | None = None
    channel: int | None = None
    band: str | None = None


def effective_rssi(rssi_dbm: float, band: str | None, band_2g_penalty_db: float) -> float:
    """The RSSI used for comparisons: 2.4 GHz APs count ``band_2g_penalty_db`` weaker."""
    return rssi_dbm - band_2g_penalty_db if band == "2.4GHz" else rssi_dbm


@dataclass(frozen=True)
class ScoreBreakdown:
    bssid: str
    ssid: str
    rssi_dbm: float
    gain_db: float
    learned_p: float
    learned_term: float
    rssi_norm: float
    rssi_term: float
    seen_age_s: float | None
    seen_term: float
    assoc_age_s: float | None
    assoc_term: float
    candidate_class: str  # "recent" | "expired" | "never"
    total: float
    eligible: bool
    reject_reason: str | None = None
    channel: int | None = None
    band: str | None = None

    def as_dict(self) -> dict[str, Any]:
        def r(x: float | None, nd: int = 3) -> float | None:
            return None if x is None else round(x, nd)

        return {
            "bssid": self.bssid,
            "rssi_dbm": r(self.rssi_dbm, 1),
            "gain_db": r(self.gain_db, 1),
            "channel": self.channel,
            "learned_p": r(self.learned_p),
            "learned": r(self.learned_term),
            "rssi": r(self.rssi_term),
            "seen": r(self.seen_term),
            "recently_connected": r(self.assoc_term),
            "assoc_age_h": None if self.assoc_age_s is None else round(self.assoc_age_s / 3600, 2),
            "class": self.candidate_class,
            "total": r(self.total),
            "eligible": self.eligible,
            "reject": self.reject_reason,
        }


def classify_candidate(assoc_age_s: float | None, ttl_s: float) -> str:
    if assoc_age_s is None:
        return "never"
    return "recent" if 0 <= assoc_age_s <= ttl_s else "expired"


class Predictor:
    def __init__(self, store: TopologyStore, config: PredictorConfig | None = None) -> None:
        self.store = store
        self.config = config or PredictorConfig()

    def rank(
        self,
        *,
        current_bssid: str | None,
        current_rssi_dbm: float,
        ssid: str,
        candidates: Sequence[CandidateInput],
        now: float,
        recently_left: Mapping[str, float] | None = None,
        deny: frozenset[str] = frozenset(),
    ) -> list[ScoreBreakdown]:
        """Score every visible AP of ``ssid``; eligible ones first, best first.

        ``now`` and the ``recently_left`` timestamps are wall-clock seconds.
        """
        cfg = self.config
        w = cfg.weights
        recently_left = recently_left or {}

        pool: dict[str, CandidateInput] = {}
        for c in candidates:
            if c.ssid != ssid or c.bssid == current_bssid:
                continue
            if c.bssid not in pool or c.rssi_dbm > pool[c.bssid].rssi_dbm:
                pool[c.bssid] = c
        if not pool:
            return []

        counts = self.store.transition_counts(current_bssid) if current_bssid else {}
        alpha = cfg.laplace_alpha
        denominator = sum(counts.get(b, 0) for b in pool) + alpha * len(pool)
        last_assoc = self.store.last_associations(pool.keys())

        results = []
        for bssid, c in pool.items():
            learned_p = (counts.get(bssid, 0) + alpha) / denominator
            rssi = effective_rssi(c.rssi_dbm, c.band, cfg.band_2g_penalty_db)
            rssi_norm = min(1.0, max(0.0, (rssi - cfg.rssi_floor_dbm) / (cfg.rssi_ceiling_dbm - cfg.rssi_floor_dbm)))
            seen_raw = 0.5 if c.age_s is None else math.exp(-max(0.0, c.age_s) / cfg.seen_tau_s)
            assoc_age = None if bssid not in last_assoc else now - last_assoc[bssid]
            if assoc_age is not None and 0 <= assoc_age <= cfg.recent_assoc_ttl_s:
                assoc_raw = 1.0 - assoc_age / cfg.recent_assoc_ttl_s
            else:
                assoc_raw = 0.0
            learned_term = w.learned * learned_p / w.total
            rssi_term = w.rssi * rssi_norm / w.total
            seen_term = w.seen_recency * seen_raw / w.total
            assoc_term = w.recently_connected * assoc_raw / w.total
            total = learned_term + rssi_term + seen_term + assoc_term

            gain = rssi - current_rssi_dbm
            reason = None
            if bssid in deny:
                reason = "deny-listed"
            elif gain < cfg.min_gain_db:
                handicap = f" after the {cfg.band_2g_penalty_db:.0f} dB 2.4 GHz handicap" if rssi != c.rssi_dbm else ""
                reason = f"only {gain:+.1f} dB vs current{handicap} (needs +{cfg.min_gain_db:.0f})"
            elif c.age_s is not None and c.age_s > cfg.max_candidate_age_s:
                reason = f"last heard {c.age_s:.0f} s ago"
            elif (
                bssid in recently_left
                and now - recently_left[bssid] < cfg.recently_left_block_s
                and gain < cfg.recently_left_override_gain_db
            ):
                reason = f"left {now - recently_left[bssid]:.0f} s ago (ping-pong guard)"

            results.append(
                ScoreBreakdown(
                    bssid=bssid,
                    ssid=c.ssid,
                    rssi_dbm=c.rssi_dbm,
                    gain_db=gain,
                    learned_p=learned_p,
                    learned_term=learned_term,
                    rssi_norm=rssi_norm,
                    rssi_term=rssi_term,
                    seen_age_s=c.age_s,
                    seen_term=seen_term,
                    assoc_age_s=assoc_age,
                    assoc_term=assoc_term,
                    candidate_class=classify_candidate(assoc_age, cfg.recent_assoc_ttl_s),
                    total=total,
                    eligible=reason is None,
                    reject_reason=reason,
                    channel=c.channel,
                    band=c.band,
                )
            )
        results.sort(key=lambda s: (not s.eligible, -s.total, -s.rssi_dbm))
        return results

    @staticmethod
    def best(ranked: Sequence[ScoreBreakdown]) -> ScoreBreakdown | None:
        return ranked[0] if ranked and ranked[0].eligible else None
