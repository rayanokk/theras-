"""Tests du service d'approbation (etape 3.1) et de la branche REVIEW du pipeline.

Test 1 : la fonction pure new_approval.
Test 2 : integration via le pipeline sur la demo phare, avec les vrais modules
de D (SQLiteStore, DriveMock, MailMock, EvidenceVault).
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from police.approvals.service import APPROVAL_TTL, new_approval
from police.connectors.drive_mock import DriveMock
from police.connectors.mail_mock import MailMock
from police.evidence.vault import EvidenceVault
from police.gateway.pipeline import Pipeline
from police.identity import IdentityRegistry
from police.policy.engine import load_policy
from police.policy.taint import TaintTracker
from police.store.sqlite_store import SQLiteStore

REPO = Path(__file__).resolve().parents[1]
POLICIES = REPO / "policies" / "policies.yaml"
IDENTITIES = REPO / "data" / "identities.json"

KEY_ASSISTANT = "k-assistant"


# --- Test 1 : new_approval ----------------------------------------------------


def test_new_approval_is_pending_and_expires_in_ten_minutes():
    now = datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc)
    approval = new_approval("AP-0001", "PA-0001", "deadbeef", now)

    assert approval.status.value == "pending"
    assert approval.created_at == now.isoformat()
    assert approval.expires_at == (now + timedelta(minutes=10)).isoformat()
    assert APPROVAL_TTL == timedelta(minutes=10)
    # Champs non encore decides.
    assert approval.approver_id is None
    assert approval.decision is None
    assert approval.justification is None
    assert approval.decided_at is None


# --- Test 2 : branche REVIEW du pipeline (demo phare) -------------------------


@pytest.fixture
def ctx(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_KEY_RESEARCH", "k-research")
    monkeypatch.setenv("AGENT_KEY_OPS", "k-ops")
    monkeypatch.setenv("AGENT_KEY_ASSISTANT", KEY_ASSISTANT)
    monkeypatch.setenv("APPROVER_KEY_ALICE", "k-alice")
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

    class Ctx:
        pass

    c = Ctx()
    c.store = store
    c.pipeline = pipeline
    c.drive = drive
    yield c
    store.close()


def _read(resource_id, agent_id, session="sess-1"):
    return {
        "agent_id": agent_id,
        "tool": "google_drive",
        "action": "read_file",
        "resource_id": resource_id,
        "parameters": {},
        "session_id": session,
        "task_id": "task-1",
    }


def _share(agent_id, resource_id, recipient, session="sess-1"):
    return {
        "agent_id": agent_id,
        "tool": "google_drive",
        "action": "share_file",
        "resource_id": resource_id,
        "parameters": {"recipient": recipient, "role": "reader"},
        "session_id": session,
        "task_id": "task-1",
    }


def test_flagship_demo_review_creates_pending_approval(ctx):
    # 1. Lecture d'un document non fiable -> session contaminee.
    ctx.pipeline.handle(
        _read("vendor_notes.txt", "agent-assistant"), KEY_ASSISTANT
    )
    # 2. Partage d'un confidentiel vers l'externe -> REVIEW (R-REV-01 + R-REV-02).
    decision = ctx.pipeline.handle(
        _share(
            "agent-assistant",
            "Confidential_Audit_Report.pdf",
            "audit@external.example",
        ),
        KEY_ASSISTANT,
    )

    assert decision.verdict == "REVIEW"
    assert decision.approval_id is not None

    approval = ctx.store.get_approval(decision.approval_id)
    assert approval is not None
    assert approval["status"] == "pending"
    assert approval["params_hash"] == decision.params_hash
    assert approval["action_id"] == decision.action_id


# --- revalidate et execute_approved -------------------------------------------


def _flagship_review(ctx):
    """Rejoue la demo phare et renvoie (decision, action stockee, approbation)."""
    ctx.pipeline.handle(_read("vendor_notes.txt", "agent-assistant"), KEY_ASSISTANT)
    decision = ctx.pipeline.handle(
        _share(
            "agent-assistant",
            "Confidential_Audit_Report.pdf",
            "audit@external.example",
        ),
        KEY_ASSISTANT,
    )
    assert decision.verdict == "REVIEW"
    action = ctx.store.get_action(decision.action_id)
    approval = ctx.store.get_approval(decision.approval_id)
    return decision, action, approval


def _approval_obj(ctx, approval_id):
    """Recharge l'approbation comme ApprovalRequest (params_hash en attribut)."""
    from contracts.models import ApprovalRequest

    return ApprovalRequest.model_validate(ctx.store.get_approval(approval_id))


def test_revalidate_ok_right_after_review(ctx):
    decision, action, _ = _flagship_review(ctx)
    approval = _approval_obj(ctx, decision.approval_id)
    ok, rule_ids, reasons = ctx.pipeline.revalidate(action, approval)
    assert ok is True
    assert rule_ids == []
    assert reasons == []


def test_revalidate_detects_changed_recipient(ctx):
    decision, action, _ = _flagship_review(ctx)
    approval = _approval_obj(ctx, decision.approval_id)
    # On modifie le destinataire dans la demande stockee : le hash ne colle plus.
    action["request"]["parameters"]["recipient"] = "someone-else@external.example"
    ok, rule_ids, reasons = ctx.pipeline.revalidate(action, approval)
    assert ok is False
    assert rule_ids == ["PARAMS_CHANGED"]


def test_revalidate_denies_when_file_removed_from_acl(ctx):
    decision, action, _ = _flagship_review(ctx)
    approval = _approval_obj(ctx, decision.approval_id)
    # L'agent est retire de l'ACL du fichier apres la REVIEW (etat DriveMock).
    ctx.drive._files["Confidential_Audit_Report.pdf"]["acl"] = ["agent-ops"]
    ok, rule_ids, _ = ctx.pipeline.revalidate(action, approval)
    assert ok is False
    assert "R-DENY-03" in rule_ids


def test_execute_approved_shares_file_in_drive(ctx):
    decision, action, _ = _flagship_review(ctx)
    status, result = ctx.pipeline.execute_approved(action)
    assert status == "EXECUTED"
    assert result == {"shared_with": "audit@external.example", "role": "reader"}
    # Le partage est bien enregistre dans l'etat du DriveMock.
    shares = ctx.drive._shares["Confidential_Audit_Report.pdf"]
    assert {"recipient": "audit@external.example", "role": "reader"} in shares


def test_revalidate_fails_closed_on_unreadable_request(ctx):
    decision, action, _ = _flagship_review(ctx)
    approval = _approval_obj(ctx, decision.approval_id)
    # La requete stockee devient illisible (tool inconnu, champs manquants).
    action["request"] = {"tool": "inconnu"}
    ok, rule_ids, reasons = ctx.pipeline.revalidate(action, approval)
    assert ok is False
    assert rule_ids == ["INVALID_REQUEST"]
    assert reasons == ["Requête stockée illisible"]


def test_review_action_record_includes_approval_id(ctx):
    decision, action, _ = _flagship_review(ctx)
    stored = ctx.store.get_action(decision.action_id)
    assert stored["approval_id"] == decision.approval_id
