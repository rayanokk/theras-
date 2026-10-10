"""Tests de l'implémentation SQLiteStore (contrat Store).

Chaque test utilise une base isolée dans tmp_path.
"""

import sqlite3

import pytest

from police.store.sqlite_store import SQLiteStore


@pytest.fixture
def store(tmp_path):
    s = SQLiteStore(str(tmp_path / "test.db"))
    yield s
    s.close()


def _action(action_id="PA-0001", status="EXECUTED", **extra):
    base = {
        "action_id": action_id,
        "agent_id": "agent-ops",
        "user_id": "user-claire",
        "session_id": "sess-1",
        "tool": "google_drive",
        "action": "read_file",
        "resource_id": "Team_Roadmap.md",
        "params": {},
        "params_hash": "abc123",
        "verdict": "ALLOW",
        "status": status,
        "rule_ids": ["R-ALLOW-01"],
        "risk": None,
        "created_at": "2026-10-10T00:00:00Z",
    }
    base.update(extra)
    return base


def test_put_and_get_action(store):
    action = _action()
    store.put_action(action)
    got = store.get_action("PA-0001")
    assert got == action


def test_put_action_upsert_updates_status_single_row(store):
    store.put_action(_action(status="PENDING_REVIEW"))
    store.put_action(_action(status="EXECUTED"))

    got = store.get_action("PA-0001")
    assert got["status"] == "EXECUTED"
    # Une seule ligne pour cet action_id.
    assert len(store.list_actions()) == 1


def test_list_actions_filters_by_status(store):
    store.put_action(_action(action_id="PA-0001", status="EXECUTED"))
    store.put_action(_action(action_id="PA-0002", status="DENIED"))
    store.put_action(_action(action_id="PA-0003", status="EXECUTED"))

    executed = store.list_actions(status="EXECUTED")
    assert {a["action_id"] for a in executed} == {"PA-0001", "PA-0003"}
    assert store.list_actions(status="DENIED")[0]["action_id"] == "PA-0002"
    assert len(store.list_actions()) == 3


def test_list_events_ordered_by_seq(store):
    for seq in (3, 1, 2):
        store.append_event({"seq": seq, "action_id": "PA-0001", "type": "DECIDED"})

    seqs = [e["seq"] for e in store.list_events()]
    assert seqs == [1, 2, 3]


def test_list_events_filters_by_action_id(store):
    store.append_event({"seq": 1, "action_id": "PA-0001", "type": "REQUESTED"})
    store.append_event({"seq": 2, "action_id": "PA-0002", "type": "REQUESTED"})
    store.append_event({"seq": 3, "action_id": "PA-0001", "type": "EXECUTED"})

    events = store.list_events(action_id="PA-0001")
    assert [e["seq"] for e in events] == [1, 3]


def test_duplicate_seq_raises(store):
    store.append_event({"seq": 1, "action_id": "PA-0001", "type": "REQUESTED"})
    with pytest.raises(sqlite3.IntegrityError):
        store.append_event({"seq": 1, "action_id": "PA-0002", "type": "DECIDED"})
    # L'événement d'origine est intact (pas écrasé).
    events = store.list_events()
    assert len(events) == 1
    assert events[0]["action_id"] == "PA-0001"


def test_session_round_trip(store):
    session = {
        "session_id": "sess-1",
        "tainted": True,
        "taint_sources": ["vendor_notes.txt"],
    }
    store.set_session(session)
    assert store.get_session("sess-1") == session

    # set_session met à jour une session existante.
    updated = {"session_id": "sess-1", "tainted": False, "taint_sources": []}
    store.set_session(updated)
    assert store.get_session("sess-1") == updated


def test_get_missing_returns_none(store):
    assert store.get_action("PA-9999") is None
    assert store.get_approval("AP-9999") is None
    assert store.get_session("sess-absent") is None


def test_approval_put_get_and_filter(store):
    approval = {
        "approval_id": "AP-0001",
        "action_id": "PA-0001",
        "params_hash": "abc123",
        "status": "pending",
        "expires_at": "2026-10-10T00:10:00Z",
        "approver_id": None,
        "decision": None,
        "justification": None,
        "decided_at": None,
    }
    store.put_approval(approval)
    assert store.get_approval("AP-0001") == approval
    assert len(store.list_approvals(status="pending")) == 1
    assert store.list_approvals(status="approved") == []


def test_data_persists_after_reopen(tmp_path):
    db_path = str(tmp_path / "persist.db")

    store = SQLiteStore(db_path)
    store.put_action(_action(action_id="PA-0001", status="EXECUTED"))
    store.append_event({"seq": 1, "action_id": "PA-0001", "type": "REQUESTED"})
    store.set_session({"session_id": "sess-1", "tainted": True, "taint_sources": []})
    store.close()

    reopened = SQLiteStore(db_path)
    try:
        assert reopened.get_action("PA-0001")["status"] == "EXECUTED"
        assert [e["seq"] for e in reopened.list_events()] == [1]
        assert reopened.get_session("sess-1")["tainted"] is True
    finally:
        reopened.close()
