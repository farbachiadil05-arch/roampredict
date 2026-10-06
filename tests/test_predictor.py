import pytest

from roampredict.topology.predictor import (
    CandidateInput,
    Predictor,
    PredictorConfig,
    PredictorWeights,
    classify_candidate,
)
from roampredict.topology.store import TopologyStore

CUR = "02:00:00:00:00:01"
B = "02:00:00:00:00:0b"
C = "02:00:00:00:00:0c"
D = "02:00:00:00:00:0d"
NOW = 1_000_000.0
TTL = 12 * 3600.0


@pytest.fixture
def store():
    s = TopologyStore(":memory:")
    yield s
    s.close()


def rank(predictor, candidates, current_rssi=-76.0, **kw):
    return predictor.rank(
        current_bssid=CUR,
        current_rssi_dbm=current_rssi,
        ssid="eduroam",
        candidates=candidates,
        now=NOW,
        **kw,
    )


def cand(bssid, rssi, age=1.0, ssid="eduroam"):
    return CandidateInput(bssid, ssid, rssi, age)


def test_learned_probability_uses_laplace_smoothing(store):
    for _ in range(3):
        store.record_transition(CUR, B, NOW - 100)
    ranked = rank(Predictor(store), [cand(B, -60), cand(C, -60)])
    p = {r.bssid: r.learned_p for r in ranked}
    assert p[B] == pytest.approx(4 / 5)
    assert p[C] == pytest.approx(1 / 5)


def test_no_history_means_uniform_prior(store):
    ranked = rank(Predictor(store), [cand(B, -60), cand(C, -61), cand(D, -62)])
    assert all(r.learned_p == pytest.approx(1 / 3) for r in ranked)
    assert [r.bssid for r in ranked] == [B, C, D]  # then RSSI decides


def test_learned_next_ap_beats_a_slightly_stronger_one(store):
    for _ in range(5):
        store.record_transition(CUR, C, NOW - 100)
    ranked = rank(Predictor(store), [cand(B, -58), cand(C, -61)])
    assert ranked[0].bssid == C
    assert ranked[0].learned_term > ranked[1].learned_term


def test_min_gain_filter(store):
    ranked = rank(Predictor(store), [cand(B, -71), cand(C, -60)], current_rssi=-76.0)
    by = {r.bssid: r for r in ranked}
    assert not by[B].eligible and "+8" in by[B].reject_reason
    assert by[C].eligible
    assert Predictor.best(ranked).bssid == C
    assert Predictor.best([by[B]]) is None


def test_recently_connected_score_decays_and_expires(store):
    store.record_association(B, "eduroam", NOW - 3 * 3600, "windows")  # 3 h ago
    store.record_association(C, "eduroam", NOW - 13 * 3600, "windows")  # expired
    ranked = rank(Predictor(store), [cand(B, -60), cand(C, -60), cand(D, -60)])
    by = {r.bssid: r for r in ranked}
    w = PredictorWeights()
    assert by[B].assoc_term == pytest.approx(w.recently_connected * (1 - 3 / 12) / w.total)
    assert by[C].assoc_term == 0.0 and by[D].assoc_term == 0.0
    assert (by[B].candidate_class, by[C].candidate_class, by[D].candidate_class) == ("recent", "expired", "never")
    assert ranked[0].bssid == B


def test_ping_pong_guard(store):
    predictor = Predictor(store)
    left = {B: NOW - 10}
    ranked = rank(predictor, [cand(B, -66)], recently_left=left)  # +10 dB, left 10 s ago
    assert not ranked[0].eligible and "ping-pong" in ranked[0].reject_reason
    ranked = rank(predictor, [cand(B, -64)], recently_left=left)  # +12 dB: overwhelming
    assert ranked[0].eligible
    ranked = rank(predictor, [cand(B, -66)], recently_left={B: NOW - 100})  # long ago
    assert ranked[0].eligible


def test_deny_list_stale_entries_other_ssids_and_current_ap(store):
    predictor = Predictor(store, PredictorConfig(max_candidate_age_s=30))
    ranked = rank(
        predictor,
        [cand(B, -50), cand(C, -50, age=60), cand(D, -50, ssid="other"), cand(CUR, -40)],
        deny=frozenset({B}),
    )
    by = {r.bssid: r for r in ranked}
    assert set(by) == {B, C}
    assert by[B].reject_reason == "deny-listed"
    assert "last heard" in by[C].reject_reason


def test_breakdown_is_consistent(store):
    store.record_transition(CUR, B, NOW)
    store.record_association(B, "eduroam", NOW - 3600, "windows")
    for r in rank(Predictor(store), [cand(B, -55, age=2), cand(C, -65, age=None)]):
        assert r.total == pytest.approx(r.learned_term + r.rssi_term + r.seen_term + r.assoc_term)
        assert 0.0 <= r.total <= 1.0
        d = r.as_dict()
        assert d["bssid"] == r.bssid and "recently_connected" in d


def test_empty_and_duplicates(store):
    predictor = Predictor(store)
    assert rank(predictor, []) == []
    ranked = rank(predictor, [cand(B, -70), cand(B, -60)])
    assert len(ranked) == 1 and ranked[0].rssi_dbm == -60


def test_classify_and_weights_validation():
    assert classify_candidate(None, TTL) == "never"
    assert classify_candidate(10.0, TTL) == "recent"
    assert classify_candidate(TTL + 1, TTL) == "expired"
    with pytest.raises(ValueError):
        PredictorWeights(learned=-1)
    with pytest.raises(ValueError):
        PredictorWeights(0, 0, 0, 0)
    with pytest.raises(ValueError):
        PredictorConfig(rssi_floor_dbm=-40, rssi_ceiling_dbm=-50)


def test_2g_aps_count_weaker_than_they_read(store):
    p = Predictor(store)
    ranked = {
        r.bssid: r
        for r in rank(
            p,
            [
                CandidateInput(B, "eduroam", -64.0, 1.0, 1, "2.4GHz"),  # reads +12 dB, counts +5
                CandidateInput(C, "eduroam", -67.0, 1.0, 36, "5GHz"),  # +9 dB
                CandidateInput(D, "eduroam", -59.0, 1.0, 6, "2.4GHz"),  # reads +17 dB, counts +10
            ],
        )
    }
    assert not ranked[B].eligible and "2.4 GHz handicap" in ranked[B].reject_reason
    assert ranked[B].gain_db == pytest.approx(5.0) and ranked[B].rssi_dbm == -64.0 and ranked[B].band == "2.4GHz"
    assert ranked[C].eligible and ranked[D].eligible and ranked[D].gain_db == pytest.approx(10.0)
    off = Predictor(store, PredictorConfig(band_2g_penalty_db=0.0))
    assert rank(off, [CandidateInput(B, "eduroam", -64.0, 1.0, 1, "2.4GHz")])[0].eligible
    with pytest.raises(ValueError):
        PredictorConfig(band_2g_penalty_db=-1)


def test_margin_override_and_strongest_pick(store):
    p = Predictor(store)
    store.record_association(C, "eduroam", NOW - 600, "windows")  # C gets the "recently connected" bonus
    ranked = rank(p, [cand(B, -73.0), cand(C, -74.0)], current_rssi=-77.0)
    assert Predictor.best(ranked) is None  # +4 and +3 do not meet the usual +8
    ranked = rank(p, [cand(B, -73.0), cand(C, -74.0)], current_rssi=-77.0, min_gain_db=3.0)
    assert {r.bssid for r in ranked if r.eligible} == {B, C}
    assert Predictor.best(ranked).bssid == C  # the score prefers the recently used AP...
    assert Predictor.strongest(ranked).bssid == B  # ...the dead-link pick takes the strongest
    assert Predictor.strongest([]) is None
