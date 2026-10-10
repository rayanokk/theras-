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
