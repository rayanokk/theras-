"""Tests du suivi de contamination (police/policy/taint.py).

On utilise le vrai SQLiteStore de D sur une base temporaire : le TaintTracker
ne doit dependre que de l'interface Store (get_session / set_session).
"""

import pytest

from police.policy.taint import TaintTracker
from police.store.sqlite_store import SQLiteStore


@pytest.fixture
def store(tmp_path):
    s = SQLiteStore(str(tmp_path / "test.db"))
    yield s
    s.close()


def test_unknown_session_is_clean(store):
    tracker = TaintTracker(store)
    assert tracker.is_tainted("sess-unknown") is False
    assert tracker.taint_sources("sess-unknown") == []


def test_mark_taints_session_with_source(store):
    tracker = TaintTracker(store)
    tracker.mark("sess-1", "vendor_notes.txt")
    assert tracker.is_tainted("sess-1") is True
    assert tracker.taint_sources("sess-1") == ["vendor_notes.txt"]


def test_marking_same_resource_twice_keeps_one_source(store):
    tracker = TaintTracker(store)
    tracker.mark("sess-1", "vendor_notes.txt")
    tracker.mark("sess-1", "vendor_notes.txt")
    assert tracker.taint_sources("sess-1") == ["vendor_notes.txt"]


def test_two_different_resources_give_two_sources(store):
    tracker = TaintTracker(store)
    tracker.mark("sess-1", "vendor_notes.txt")
    tracker.mark("sess-1", "uploaded_cv.txt")
    assert tracker.taint_sources("sess-1") == ["vendor_notes.txt", "uploaded_cv.txt"]


def test_other_session_stays_clean(store):
    tracker = TaintTracker(store)
    tracker.mark("sess-1", "vendor_notes.txt")
    assert tracker.is_tainted("sess-2") is False
    assert tracker.taint_sources("sess-2") == []


def test_state_persists_across_trackers_on_same_db(tmp_path):
    db = str(tmp_path / "test.db")
    store_a = SQLiteStore(db)
    TaintTracker(store_a).mark("sess-1", "vendor_notes.txt")
    store_a.close()

    store_b = SQLiteStore(db)
    tracker_b = TaintTracker(store_b)
    assert tracker_b.is_tainted("sess-1") is True
    assert tracker_b.taint_sources("sess-1") == ["vendor_notes.txt"]
    store_b.close()
