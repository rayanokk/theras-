"""Tests du LocalClient de la console sur une base remplie par le script de démo."""

import pytest

from contracts.models import ApprovalRequest, Decision, Event
from console.client import LocalClient
from police.store.sqlite_store import SQLiteStore
from scripts.seed_demo_db import seed


@pytest.fixture
def seeded_db(tmp_path):
    db_path = str(tmp_path / "console.db")
    store = SQLiteStore(db_path)
    seed(store)
    store.close()
    return db_path


@pytest.fixture
def client(seeded_db):
    c = LocalClient(db_path=seeded_db)
    yield c
    c.close()


def test_list_actions_returns_six_decisions(client):
    actions = client.list_actions()
    assert len(actions) == 6
    assert all(isinstance(a, Decision) for a in actions)


def test_list_events_returns_valid_events(client):
    events = client.list_events()
    assert len(events) > 0
    assert all(isinstance(e, Event) for e in events)
    # Les seq se suivent à partir de 1.
    assert [e.seq for e in events] == list(range(1, len(events) + 1))


def test_verify_chain_is_valid(client):
    assert client.verify_chain() == {"valid": True, "broken_at": None}


def test_one_pending_approval(client):
    pending = client.list_pending_approvals()
    assert len(pending) == 1
    assert isinstance(pending[0], ApprovalRequest)
    assert pending[0].approval_id == "AP-0001"
    assert pending[0].status.value == "pending"


def test_decide_raises_not_implemented(client):
    with pytest.raises(NotImplementedError):
        client.decide("AP-0001", "approve", "justification suffisante")


def test_export_jsonl_lines_match_event_count(client):
    export = client.export_jsonl()
    lines = export.split("\n")
    assert len(lines) == len(client.list_events())


def test_list_action_rows_carry_display_fields(client):
    rows = client.list_action_rows()
    assert len(rows) == 6
    row = next(r for r in rows if r["action_id"] == "PA-0001")
    assert row["agent_id"] == "agent-research"
    assert row["tool"] == "google_drive"
    assert row["action"] == "read_file"
    assert row["resource_id"] == "Team_Roadmap.md"
    assert row["verdict"] == "ALLOW"
