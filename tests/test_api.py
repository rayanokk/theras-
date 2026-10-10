"""Tests de l'API FastAPI (police/gateway/api.py) via TestClient.

On construit un vrai pipeline sur une base temporaire, avec les cles d'agent et
d'approbateur posees par monkeypatch. On verifie surtout qu'une requete invalide
devient un DENY (403) et jamais un 422.
"""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from police.approvals.service import ApprovalService
from police.connectors.drive_mock import DriveMock
from police.connectors.mail_mock import MailMock
from police.evidence.vault import EvidenceVault
from police.gateway.api import create_app
from police.gateway.pipeline import Pipeline
from police.identity import IdentityRegistry
from police.policy.engine import load_policy
from police.policy.taint import TaintTracker
from police.store.sqlite_store import SQLiteStore

REPO = Path(__file__).resolve().parents[1]
POLICIES = REPO / "policies" / "policies.yaml"
IDENTITIES = REPO / "data" / "identities.json"

KEY_RESEARCH = "k-research"
KEY_ASSISTANT = "k-assistant"
KEY_ALICE = "k-alice"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_KEY_RESEARCH", KEY_RESEARCH)
    monkeypatch.setenv("AGENT_KEY_OPS", "k-ops")
    monkeypatch.setenv("AGENT_KEY_ASSISTANT", "k-assistant")
    monkeypatch.setenv("APPROVER_KEY_ALICE", KEY_ALICE)
    monkeypatch.setenv("APPROVER_KEY_BOB", "k-bob")

    store = SQLiteStore(str(tmp_path / "test.db"))
    drive = DriveMock()
    mail = MailMock(drive)
    vault = EvidenceVault(store)
    policy = load_policy(POLICIES)
    identities = IdentityRegistry(IDENTITIES)
    taint = TaintTracker(store)
    pipeline = Pipeline(
        policy=policy,
        identities=identities,
        connectors={"google_drive": drive, "mail": mail},
        store=store,
        vault=vault,
        taint=taint,
        risk_scorer=None,
    )
    approvals = ApprovalService(store, vault, pipeline, identities)
    app = create_app(pipeline, store, vault, identities, approvals)
    with TestClient(app) as c:
        yield c
    store.close()


def _read_body(resource_id="Company_Brochure.pdf"):
    return {
        "agent_id": "agent-research",
        "tool": "google_drive",
        "action": "read_file",
        "resource_id": resource_id,
        "parameters": {},
        "session_id": "sess-1",
        "task_id": "task-1",
    }


def test_valid_read_returns_200(client):
    resp = client.post(
        "/v1/actions", json=_read_body(), headers={"X-API-Key": KEY_RESEARCH}
    )
    assert resp.status_code == 200
    assert resp.json()["verdict"] == "ALLOW"


def test_unknown_field_returns_403_r_deny_06_not_422(client):
    body = _read_body()
    body["unexpected"] = "boom"
    resp = client.post(
        "/v1/actions", json=body, headers={"X-API-Key": KEY_RESEARCH}
    )
    assert resp.status_code == 403
    data = resp.json()
    assert data["verdict"] == "DENY"
    assert "R-DENY-06" in data["rule_ids"]


def test_non_object_json_body_returns_403(client):
    # Un corps qui n'est pas un objet JSON (ici une chaine brute non-JSON).
    resp = client.post(
        "/v1/actions",
        content="pas du json",
        headers={"X-API-Key": KEY_RESEARCH, "Content-Type": "application/json"},
    )
    assert resp.status_code == 403
    assert resp.json()["verdict"] == "DENY"


def test_unknown_key_returns_403_r_deny_01(client):
    resp = client.post(
        "/v1/actions", json=_read_body(), headers={"X-API-Key": "wrong-key"}
    )
    assert resp.status_code == 403
    assert "R-DENY-01" in resp.json()["rule_ids"]


def test_get_existing_action_returns_200(client):
    post = client.post(
        "/v1/actions", json=_read_body(), headers={"X-API-Key": KEY_RESEARCH}
    )
    action_id = post.json()["action_id"]
    resp = client.get(
        f"/v1/actions/{action_id}", headers={"X-API-Key": KEY_RESEARCH}
    )
    assert resp.status_code == 200
    assert resp.json()["action_id"] == action_id


def test_list_actions_with_agent_key_is_403(client):
    resp = client.get("/v1/actions", headers={"X-API-Key": KEY_ASSISTANT})
    assert resp.status_code == 403


def test_list_actions_with_approver_key_is_200(client):
    resp = client.get("/v1/actions", headers={"X-API-Key": KEY_ALICE})
    assert resp.status_code == 200


def test_evidence_without_key_returns_401(client):
    resp = client.get("/v1/evidence")
    assert resp.status_code == 401


def test_evidence_with_agent_key_returns_403(client):
    resp = client.get("/v1/evidence", headers={"X-API-Key": KEY_RESEARCH})
    assert resp.status_code == 403


def test_verify_with_approver_key_is_valid(client):
    # Une action d'abord, pour avoir des evenements chaines.
    client.post("/v1/actions", json=_read_body(), headers={"X-API-Key": KEY_RESEARCH})
    resp = client.get("/v1/evidence/verify", headers={"X-API-Key": KEY_ALICE})
    assert resp.status_code == 200
    assert resp.json()["valid"] is True


def test_health_returns_200_without_key(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


# --- Approbations via HTTP ----------------------------------------------------


def _read_vendor():
    return {
        "agent_id": "agent-assistant",
        "tool": "google_drive",
        "action": "read_file",
        "resource_id": "vendor_notes.txt",
        "parameters": {},
        "session_id": "sess-1",
        "task_id": "task-1",
    }


def _share_confidential():
    return {
        "agent_id": "agent-assistant",
        "tool": "google_drive",
        "action": "share_file",
        "resource_id": "Confidential_Audit_Report.pdf",
        "parameters": {"recipient": "audit@external.example", "role": "reader"},
        "session_id": "sess-1",
        "task_id": "task-1",
    }


def _trigger_review(client):
    """Rejoue la demo phare via HTTP et renvoie l'action_id et l'approval_id."""
    client.post("/v1/actions", json=_read_vendor(), headers={"X-API-Key": KEY_ASSISTANT})
    resp = client.post(
        "/v1/actions", json=_share_confidential(), headers={"X-API-Key": KEY_ASSISTANT}
    )
    assert resp.status_code == 202
    data = resp.json()
    assert data["approval_id"] is not None
    return data["action_id"], data["approval_id"]


def test_full_review_reject_flow(client):
    action_id, approval_id = _trigger_review(client)

    # L'approbateur voit l'approbation en attente, enrichie.
    pending = client.get(
        "/v1/approvals?status=pending", headers={"X-API-Key": KEY_ALICE}
    )
    assert pending.status_code == 200
    items = pending.json()
    assert len(items) == 1
    assert items[0]["approval_id"] == approval_id
    assert items[0]["taint_sources"] == ["vendor_notes.txt"]

    # Decision reject avec justification valide.
    decide = client.post(
        f"/v1/approvals/{approval_id}/decide",
        json={"decision": "reject", "justification": "trop risqué, refusé"},
        headers={"X-API-Key": KEY_ALICE},
    )
    assert decide.status_code == 200
    assert decide.json()["action_status"] == "DENIED"

    # L'agent relit son action : DENIED.
    got = client.get(
        f"/v1/actions/{action_id}", headers={"X-API-Key": KEY_ASSISTANT}
    )
    assert got.status_code == 200
    assert got.json()["status"] == "DENIED"

    # Second decide -> 409.
    again = client.post(
        f"/v1/approvals/{approval_id}/decide",
        json={"decision": "reject", "justification": "deuxième tentative"},
        headers={"X-API-Key": KEY_ALICE},
    )
    assert again.status_code == 409

    # La chaine de preuves reste valide.
    verify = client.get("/v1/evidence/verify", headers={"X-API-Key": KEY_ALICE})
    assert verify.status_code == 200
    assert verify.json()["valid"] is True


def test_list_approvals_with_agent_key_is_403(client):
    resp = client.get("/v1/approvals", headers={"X-API-Key": KEY_RESEARCH})
    assert resp.status_code == 403


def test_list_approvals_without_key_is_401(client):
    resp = client.get("/v1/approvals")
    assert resp.status_code == 401


def test_decide_with_agent_key_is_403(client):
    _, approval_id = _trigger_review(client)
    resp = client.post(
        f"/v1/approvals/{approval_id}/decide",
        json={"decision": "reject", "justification": "justification valable"},
        headers={"X-API-Key": KEY_RESEARCH},
    )
    assert resp.status_code == 403


def test_decide_unknown_approval_is_404(client):
    resp = client.post(
        "/v1/approvals/AP-9999/decide",
        json={"decision": "reject", "justification": "justification valable"},
        headers={"X-API-Key": KEY_ALICE},
    )
    assert resp.status_code == 404


def test_decide_short_justification_is_422(client):
    _, approval_id = _trigger_review(client)
    resp = client.post(
        f"/v1/approvals/{approval_id}/decide",
        json={"decision": "reject", "justification": "court"},  # 5 caracteres
        headers={"X-API-Key": KEY_ALICE},
    )
    assert resp.status_code == 422


def test_agent_cannot_read_another_agents_action(client):
    # Action creee par agent-assistant.
    post = client.post(
        "/v1/actions", json=_read_vendor(), headers={"X-API-Key": KEY_ASSISTANT}
    )
    action_id = post.json()["action_id"]
    # agent-research tente de la lire -> 404 (masquee).
    resp = client.get(
        f"/v1/actions/{action_id}", headers={"X-API-Key": KEY_RESEARCH}
    )
    assert resp.status_code == 404
