"""Tests du LocalClient de la console sur une base remplie par le script de démo."""

import httpx
import pytest

from contracts.models import ApprovalRequest, Decision, Event
from console.client import DecideError, HttpClient, LocalClient, _action_to_row
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


def test_list_actions_returns_seven_decisions(client):
    actions = client.list_actions()
    assert len(actions) == 7
    assert all(isinstance(a, Decision) for a in actions)


def test_list_events_returns_valid_events(client):
    events = client.list_events()
    assert len(events) > 0
    assert all(isinstance(e, Event) for e in events)
    # Les seq se suivent à partir de 1.
    assert [e.seq for e in events] == list(range(1, len(events) + 1))


def test_verify_chain_is_valid(client):
    assert client.verify_chain() == {"valid": True, "broken_at": None}


def test_pending_approvals(client):
    pending = client.list_pending_approvals()
    assert all(isinstance(a, ApprovalRequest) for a in pending)
    ids = {a.approval_id for a in pending}
    assert ids == {"AP-0001", "AP-0003"}
    assert all(a.status.value == "pending" for a in pending)


def test_decide_raises_not_implemented(client):
    with pytest.raises(NotImplementedError):
        client.decide("AP-0001", "approve", "justification suffisante")


def test_export_jsonl_lines_match_event_count(client):
    export = client.export_jsonl()
    lines = export.split("\n")
    assert len(lines) == len(client.list_events())


def test_list_action_rows_carry_display_fields(client):
    rows = client.list_action_rows()
    assert len(rows) == 7
    # PA-0001 : read_file, lu depuis le `request` imbriqué.
    row1 = next(r for r in rows if r["action_id"] == "PA-0001")
    assert row1["agent_id"] == "agent-research"
    assert row1["tool"] == "google_drive"
    assert row1["action"] == "read_file"
    assert row1["resource_id"] == "Team_Roadmap.md"
    assert row1["user_id"] == "user-claire"
    assert row1["reason"]  # non vide
    assert row1["recipient"] is None  # pas de destinataire pour read_file
    assert row1["verdict"] == "ALLOW"

    # PA-0003 : share_file avec destinataire et session contaminée.
    row3 = next(r for r in rows if r["action_id"] == "PA-0003")
    assert row3["recipient"] == "audit@external.example"
    assert row3["taint_sources"] == ["vendor_notes.txt"]


def test_list_action_rows_reads_nested_gateway_format():
    """_action_to_row lit outil/action/ressource/destinataire/reason depuis `request`."""
    action = {
        "action_id": "PA-9001",
        "verdict": "REVIEW",
        "status": "PENDING_REVIEW",
        "rule_ids": ["R-REV-01"],
        "agent_id": "agent-assistant",
        "declared_agent_id": "agent-assistant",
        "taint_sources": ["vendor_notes.txt"],
        "request": {
            "agent_id": "agent-assistant",
            "user_id": "user-claire",
            "tool": "mail",
            "action": "send_email",
            "resource_id": "Q3_Financials.xlsx",
            "parameters": {"to": "x@external.example", "subject": "s", "body": "b"},
            "reason": "Envoi externe du T3.",
            "session_id": "sess-x",
            "task_id": "task-x",
        },
    }
    row = _action_to_row(action)
    assert row["tool"] == "mail"
    assert row["action"] == "send_email"
    assert row["resource_id"] == "Q3_Financials.xlsx"
    assert row["user_id"] == "user-claire"
    assert row["reason"] == "Envoi externe du T3."
    assert row["recipient"] == "x@external.example"  # lu depuis parameters.to
    assert row["taint_sources"] == ["vendor_notes.txt"]


def test_list_action_rows_reads_legacy_flat_format():
    """Repli : l'ancien format à plat reste lisible."""
    action = {
        "action_id": "PA-9002",
        "agent_id": "agent-ops",
        "tool": "google_drive",
        "action": "share_file",
        "resource_id": "Team_Roadmap.md",
        "user_id": "user-david",
        "reason": "Partage interne.",
        "params": {"recipient": "a@acme.example", "role": "reader"},
        "verdict": "ALLOW",
        "status": "EXECUTED",
        "rule_ids": ["R-ALLOW-04"],
    }
    row = _action_to_row(action)
    assert row["tool"] == "google_drive"
    assert row["action"] == "share_file"
    assert row["resource_id"] == "Team_Roadmap.md"
    assert row["user_id"] == "user-david"
    assert row["reason"] == "Partage interne."
    assert row["recipient"] == "a@acme.example"  # lu depuis params.recipient


def test_http_decide_409_gives_clear_error():
    """Une réponse 409 de /decide doit lever un DecideError lisible, sans vrai serveur."""

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/approvals/AP-0001/decide"
        return httpx.Response(409, json={"detail": "already decided"})

    client = HttpClient(
        base_url="http://gateway.test",
        api_key="dev-approver-alice-key",
        transport=httpx.MockTransport(handler),
    )
    try:
        with pytest.raises(DecideError) as excinfo:
            client.decide("AP-0001", "approve", "justification suffisante")
        assert "déjà" in str(excinfo.value).lower()
    finally:
        client.close()
