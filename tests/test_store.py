import pytest

from roampredict.topology.store import Sighting, SwitchRecord, TopologyStore
from roampredict.validate import ValidationError

A = "02:00:00:00:00:0a"
B = "02:00:00:00:00:0b"
C = "02:00:00:00:00:0c"


@pytest.fixture
def store():
    s = TopologyStore(":memory:")
    yield s
    s.close()


def test_sightings_insert_and_update(store):
    store.upsert_sightings([Sighting(A, "eduroam", -60, channel=36, freq_mhz=5180, band="5GHz", ft=True)], now=100.0)
    store.upsert_sightings([Sighting(A.upper(), "eduroam", -70, channel=None, ft=None, btm=True)], now=200.0)
    rec = store.get_bss(A)
    assert rec is not None
    assert rec.last_rssi == -70
    assert rec.max_rssi == -60
    assert rec.first_seen == 100.0 and rec.last_seen == 200.0
    assert rec.seen_count == 2
    assert rec.channel == 36  # unknown value does not erase a known one
    assert rec.ft is True and rec.btm is True and rec.rrm is None
    assert [r.bssid for r in store.all_bss("eduroam")] == [A]
    assert store.all_bss("other") == []


def test_bad_bssids_are_rejected(store):
    for bad in ("ff:ff:ff:ff:ff:ff", "not-a-mac", "00:00:00:00:00:00"):
        with pytest.raises(ValidationError):
            store.upsert_sightings([Sighting(bad, "x", -60)], now=1.0)
        with pytest.raises(ValidationError):
            store.record_association(bad, "x", 1.0, "windows")
        with pytest.raises(ValidationError):
            store.record_transition(A, bad, 1.0)


def test_associations(store):
    store.record_association(A, "eduroam", 10.0, "startup")
    store.record_association(A, "eduroam", 50.0, "windows")
    store.record_association(B, "eduroam", 30.0, "roampredict")
    assert store.last_association(A) == 50.0
    assert store.last_association(C) is None
    assert store.last_associations([A, B, C]) == {A: 50.0, B: 30.0}
    assert store.prune_associations(older_than=40.0) == 2
    assert store.last_associations([A, B]) == {A: 50.0}
    with pytest.raises(ValidationError):
        store.record_association(A, "eduroam", 1.0, "hacker")


def test_transitions(store):
    for _ in range(3):
        store.record_transition(A, B, 1.0)
    store.record_transition(A, C, 2.0)
    store.record_transition(A, A, 3.0)  # self-transition ignored
    assert store.transition_counts(A) == {B: 3, C: 1}
    assert store.transition_counts(B) == {}
    top = store.all_transitions()
    assert top[0][:3] == (A, B, 3)


def test_switch_records_round_trip(store):
    rec = SwitchRecord(
        at=100.0,
        initiator="roampredict",
        success=True,
        from_bssid=A,
        to_bssid=B,
        requested_bssid=B,
        candidate_class="recent",
        honored=True,
        total_ms=180.0,
        auth_ms=60.0,
        detail={"stage": "done", "events": [[0.0, "disconnecting"]]},
    )
    store.record_switch(rec)
    back = store.switches()[0]
    assert back.initiator == "roampredict" and back.success and back.honored
    assert back.detail["stage"] == "done"
    with pytest.raises(ValidationError):
        store.record_switch(SwitchRecord(at=1.0, initiator="someone", success=True))
    with pytest.raises(ValidationError):
        store.record_switch(SwitchRecord(at=1.0, initiator="windows", success=True, candidate_class="maybe"))


def test_switch_stats_group_by_class(store):
    for ms in (100, 200, 300):
        store.record_switch(SwitchRecord(at=1.0, initiator="roampredict", success=True, candidate_class="recent", total_ms=ms, auth_ms=ms / 2))
    for ms in (1000, 1500):
        store.record_switch(SwitchRecord(at=1.0, initiator="roampredict", success=True, candidate_class="never", total_ms=ms))
    store.record_switch(SwitchRecord(at=1.0, initiator="roampredict", success=False, candidate_class="never"))
    store.record_switch(SwitchRecord(at=1.0, initiator="roampredict", success=True, candidate_class="never", total_ms=5, dry_run=True))
    stats = {(s.initiator, s.candidate_class): s for s in store.switch_stats()}
    recent = stats[("roampredict", "recent")]
    never = stats[("roampredict", "never")]
    assert (recent.n, recent.ok, recent.median_total_ms, recent.median_auth_ms) == (3, 3, 200, 100)
    assert recent.p90_total_ms == pytest.approx(280.0)
    assert (never.n, never.ok, never.median_total_ms) == (3, 2, 1250)


def test_persistence_and_forget(tmp_path):
    path = tmp_path / "sub" / "roampredict.db"
    with TopologyStore(path) as s:
        s.record_transition(A, B, 1.0)
        s.record_association(A, "eduroam", 1.0, "windows")
    with TopologyStore(path) as s:
        assert s.transition_counts(A) == {B: 1}
        s.forget_all()
        assert s.transition_counts(A) == {}
        assert s.last_association(A) is None
