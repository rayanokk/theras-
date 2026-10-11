"""Tests du LocalClient de la console sur une base remplie par le script de démo."""

import httpx
import pytest

from contracts.models import ActionRecord, ApprovalView, Event
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


def test_list_actions_returns_seven_records(client):
    actions = client.list_actions()
    assert len(actions) == 7
    assert all(isinstance(a, ActionRecord) for a in actions)


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
    assert all(isinstance(a, ApprovalView) for a in pending)
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


def test_action_to_row_reads_nested_gateway_record():
    """_action_to_row lit outil/action/ressource/destinataire/reason depuis request."""
    record = ActionRecord.model_validate(
        {
            "action_id": "PA-9001",
            "verdict": "REVIEW",
            "status": "PENDING_REVIEW",
            "rule_ids": ["R-REV-01"],
            "params_hash": "h",
            "policy_version": "v1",
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
    )
    row = _action_to_row(record)
    assert row["tool"] == "mail"
    assert row["action"] == "send_email"
    assert row["resource_id"] == "Q3_Financials.xlsx"
    assert row["user_id"] == "user-claire"
    assert row["reason"] == "Envoi externe du T3."
    assert row["recipient"] == "x@external.example"  # lu depuis parameters.to
    assert row["taint_sources"] == ["vendor_notes.txt"]
    assert row["declared_agent_id"] == "agent-assistant"


def test_action_to_row_without_request_is_graceful():
    """Un ActionRecord sans `request` ne casse pas : champs de requête à None."""
    record = ActionRecord.model_validate(
        {
            "action_id": "PA-9002",
            "verdict": "ALLOW",
            "status": "EXECUTED",
            "rule_ids": ["R-ALLOW-01"],
            "params_hash": "h",
            "policy_version": "v1",
            "agent_id": "agent-ops",
        }
    )
    row = _action_to_row(record)
    assert row["action_id"] == "PA-9002"
    assert row["agent_id"] == "agent-ops"
    assert row["tool"] is None
    assert row["action"] is None
    assert row["recipient"] is None
    assert row["taint_sources"] == []
    assert row["verdict"] == "ALLOW"


def test_http_client_converts_real_gateway_records():
    """HttpClient convertit un ActionRecord et une ApprovalView réels (MockTransport)."""
    action_record = {
        "action_id": "PA-0006",
        "verdict": "REVIEW",
        "status": "PENDING_REVIEW",
        "rule_ids": ["R-REV-01"],
        "reasons": ["Fichier confidentiel partagé ou envoyé hors de l'entreprise"],
        "risk": None,
        "params_hash": "483fda77d418793320f3fcb2743de5b1b1401cdbe1e56fd54b8a00a0a982c549",
        "policy_version": "2026-10-10.1",
        "approval_id": None,
        "result": None,
        "agent_id": "agent-assistant",
        "declared_agent_id": "agent-assistant",
        "request": {
            "agent_id": "agent-assistant",
            "user_id": "user-claire",
            "tool": "google_drive",
            "action": "share_file",
            "resource_id": "Customer_List.csv",
            "parameters": {"recipient": "x@external.example", "role": "reader"},
            "reason": "Partage du fichier Customer_List.csv avec un utilisateur externe en lecture seule",
            "session_id": "sess-a61177e5",
            "task_id": "task-a86eec1d",
        },
        "session_id": "sess-a61177e5",
        "created_at": "2026-10-10T18:56:13.191922+00:00",
        "taint_sources": [],
    }
    approval_view = {
        "approval_id": "AP-0003",
        "action_id": "PA-0006",
        "params_hash": action_record["params_hash"],
        "status": "pending",
        "created_at": "2026-10-10T18:56:13.191922+00:00",
        "expires_at": "2026-10-10T19:06:13.191922+00:00",
        "approver_id": None,
        "decision": None,
        "justification": None,
        "decided_at": None,
        "agent_id": "agent-assistant",
        "user_id": "user-claire",
        "tool": "google_drive",
        "action": "share_file",
        "resource_id": "Customer_List.csv",
        "reason": "Partage externe en lecture seule",
        "action_status": "PENDING_REVIEW",
        "parameters": {"recipient": "x@external.example", "role": "reader"},
        "rule_ids": ["R-REV-01"],
        "reasons": ["Fichier confidentiel partagé ou envoyé hors de l'entreprise"],
        "taint_sources": [],
        "risk": None,
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/actions":
            return httpx.Response(200, json=[action_record])
        if request.url.path == "/v1/approvals":
            return httpx.Response(200, json=[approval_view])
        return httpx.Response(404)

    client = HttpClient(
        base_url="http://gateway.test",
        api_key="dev-approver-alice-key",
        transport=httpx.MockTransport(handler),
    )
    try:
        actions = client.list_actions()
        assert len(actions) == 1
        assert isinstance(actions[0], ActionRecord)
        assert actions[0].declared_agent_id == "agent-assistant"
        assert actions[0].request["resource_id"] == "Customer_List.csv"

        rows = client.list_action_rows()
        assert rows[0]["recipient"] == "x@external.example"
        assert rows[0]["tool"] == "google_drive"
        assert rows[0]["action"] == "share_file"

        approvals = client.list_pending_approvals()
        assert len(approvals) == 1
        assert isinstance(approvals[0], ApprovalView)
        assert approvals[0].approval_id == "AP-0003"
        assert approvals[0].resource_id == "Customer_List.csv"
    finally:
        client.close()


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


def test_labels_action_and_rule():
    from console.labels import action_label, rule_label

    assert action_label("share_file") == "partager"
    assert action_label("send_email") == "envoyer par mail"
    assert action_label("delete_file") == "supprimer"
    assert action_label("read_file") == "lire"
    # Règle connue : « explication (R-XXX) ».
    label = rule_label("R-REV-01")
    assert label.endswith("(R-REV-01)")
    assert "confidentiel" in label.lower()
    # Toutes les règles du contrat ont un libellé.
    from console.labels import RULE_LABELS

    expected_ids = (
        [f"R-DENY-0{i}" for i in range(1, 7)]
        + [f"R-REV-0{i}" for i in range(1, 6)]
        + [f"R-ALLOW-0{i}" for i in range(1, 5)]
    )
    for rid in expected_ids:
        assert rid in RULE_LABELS
