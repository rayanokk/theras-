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


# --- Taint lie a l'identite reelle de l'agent (avec TTL) ----------------------

from datetime import datetime, timedelta, timezone

T0 = datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc)
TTL = 15


def test_mark_agent_then_tainted_within_ttl(store):
    tracker = TaintTracker(store)
    tracker.mark_agent("agent-assistant", "vendor_notes.txt", now=T0)
    # Juste apres, et encore a 14 minutes : contamine.
    assert tracker.is_agent_tainted("agent-assistant", TTL, now=T0) is True
    assert (
        tracker.is_agent_tainted(
            "agent-assistant", TTL, now=T0 + timedelta(minutes=14)
        )
        is True
    )
    assert tracker.agent_taint_sources("agent-assistant") == ["vendor_notes.txt"]


def test_agent_taint_expires_after_ttl(store):
    tracker = TaintTracker(store)
    tracker.mark_agent("agent-assistant", "vendor_notes.txt", now=T0)
    # A 16 minutes : expire.
    assert (
        tracker.is_agent_tainted(
            "agent-assistant", TTL, now=T0 + timedelta(minutes=16)
        )
        is False
    )


def test_new_mark_agent_pushes_ttl_forward(store):
    tracker = TaintTracker(store)
    tracker.mark_agent("agent-assistant", "vendor_notes.txt", now=T0)
    # Expire a 16 min...
    later = T0 + timedelta(minutes=16)
    assert tracker.is_agent_tainted("agent-assistant", TTL, now=later) is False
    # ... mais un nouveau marquage repousse tainted_at : de nouveau contamine.
    tracker.mark_agent("agent-assistant", "uploaded_cv.txt", now=later)
    assert tracker.is_agent_tainted("agent-assistant", TTL, now=later) is True
    assert tracker.agent_taint_sources("agent-assistant") == [
        "vendor_notes.txt",
        "uploaded_cv.txt",
    ]


def test_unknown_agent_is_not_tainted(store):
    tracker = TaintTracker(store)
    assert tracker.is_agent_tainted("agent-unknown", TTL, now=T0) is False
    assert tracker.agent_taint_sources("agent-unknown") == []
