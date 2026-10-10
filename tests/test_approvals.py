"""Tests du service d'approbation (etape 3.1) et de la branche REVIEW du pipeline.

Test 1 : la fonction pure new_approval.
Test 2 : integration via le pipeline sur la demo phare, avec les vrais modules
de D (SQLiteStore, DriveMock, MailMock, EvidenceVault).
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from contracts.models import ApprovalDecisionIn
from police.approvals.service import (
    APPROVAL_TTL,
    ApprovalError,
    ApprovalService,
    _ttl_from_env,
    new_approval,
)
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
KEY_ALICE = "k-alice"
KEY_RESEARCH = "k-research"


# --- TTL reglable mais plafonne ------------------------------------------------


def test_ttl_from_env_bounds():
    assert _ttl_from_env(None) == timedelta(seconds=600)
    assert _ttl_from_env("5") == timedelta(seconds=5)
    assert _ttl_from_env("3600") == timedelta(seconds=600)  # plafonne
    assert _ttl_from_env("abc") == timedelta(seconds=600)  # invalide
    assert _ttl_from_env("0") == timedelta(seconds=600)  # <= 0


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


# --- Service de decision (etape 3.2) ------------------------------------------


class FakeClock:
    """Horloge factice injectable : avance a la demande."""

    def __init__(self, start: datetime) -> None:
        self.current = start

    def __call__(self) -> datetime:
        return self.current

    def advance(self, delta: timedelta) -> None:
        self.current += delta


@pytest.fixture
def svc(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_KEY_RESEARCH", KEY_RESEARCH)
    monkeypatch.setenv("AGENT_KEY_OPS", "k-ops")
    monkeypatch.setenv("AGENT_KEY_ASSISTANT", KEY_ASSISTANT)
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
    clock = FakeClock(datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc))
    service = ApprovalService(store, vault, pipeline, identities, now=clock)

    class Ctx:
        pass

    c = Ctx()
    c.store = store
    c.drive = drive
    c.vault = vault
    c.pipeline = pipeline
    c.service = service
    c.clock = clock
    yield c
    store.close()


def _make_review(c):
    """Rejoue la demo phare et renvoie la Decision REVIEW (approval_id non nul)."""
    c.pipeline.handle(_read("vendor_notes.txt", "agent-assistant"), KEY_ASSISTANT)
    decision = c.pipeline.handle(
        _share(
            "agent-assistant",
            "Confidential_Audit_Report.pdf",
            "audit@external.example",
        ),
        KEY_ASSISTANT,
    )
    assert decision.verdict == "REVIEW"
    return decision


def _decision_in(decision="approve", justification="justification valable"):
    return ApprovalDecisionIn(decision=decision, justification=justification)


def _event_types(c, action_id):
    return [e["type"] for e in c.store.list_events(action_id)]


def test_decide_approve_executes_and_chains_events(svc):
    decision = _make_review(svc)
    out = svc.service.decide(decision.approval_id, KEY_ALICE, _decision_in("approve"))
    assert out["action_status"] == "EXECUTED"
    assert out["result"] == {
        "shared_with": "audit@external.example",
        "role": "reader",
    }
    assert _event_types(svc, decision.action_id) == [
        "REQUESTED",
        "DECIDED",
        "APPROVAL_DECIDED",
        "EXECUTED",
    ]
    assert svc.vault.verify()["valid"] is True


def test_decide_reject_denies_with_blocked(svc):
    decision = _make_review(svc)
    out = svc.service.decide(decision.approval_id, KEY_ALICE, _decision_in("reject"))
    assert out["action_status"] == "DENIED"
    types = _event_types(svc, decision.action_id)
    assert types[-2:] == ["APPROVAL_DECIDED", "BLOCKED"]
    # Rien n'a ete partage.
    assert "Confidential_Audit_Report.pdf" not in svc.drive._shares


def test_request_info_then_approve_executes(svc):
    decision = _make_review(svc)
    out1 = svc.service.decide(
        decision.approval_id, KEY_ALICE, _decision_in("request_info")
    )
    assert out1["approval"]["status"] == "info_requested"
    assert out1["action_status"] == "PENDING_REVIEW"
    out2 = svc.service.decide(decision.approval_id, KEY_ALICE, _decision_in("approve"))
    assert out2["action_status"] == "EXECUTED"


def test_decide_unknown_key_is_401(svc):
    decision = _make_review(svc)
    with pytest.raises(ApprovalError) as exc:
        svc.service.decide(decision.approval_id, "wrong-key", _decision_in())
    assert exc.value.code == 401


def test_decide_agent_key_self_approval_is_403(svc):
    decision = _make_review(svc)
    with pytest.raises(ApprovalError) as exc:
        svc.service.decide(decision.approval_id, KEY_ASSISTANT, _decision_in())
    assert exc.value.code == 403


def test_decide_unknown_approval_is_404(svc):
    _make_review(svc)
    with pytest.raises(ApprovalError) as exc:
        svc.service.decide("AP-9999", KEY_ALICE, _decision_in())
    assert exc.value.code == 404


def test_second_decide_is_409(svc):
    decision = _make_review(svc)
    svc.service.decide(decision.approval_id, KEY_ALICE, _decision_in("approve"))
    with pytest.raises(ApprovalError) as exc:
        svc.service.decide(decision.approval_id, KEY_ALICE, _decision_in("approve"))
    assert exc.value.code == 409


def test_expired_approval_is_410_and_action_expired(svc):
    decision = _make_review(svc)
    # L'approbation a ete creee avec l'horloge reelle du pipeline ; on cale
    # l'horloge factice du service juste apres son expires_at (+1 min).
    approval = svc.store.get_approval(decision.approval_id)
    expires_at = datetime.fromisoformat(approval["expires_at"])
    svc.clock.current = expires_at + timedelta(minutes=1)
    with pytest.raises(ApprovalError) as exc:
        svc.service.decide(decision.approval_id, KEY_ALICE, _decision_in("approve"))
    assert exc.value.code == 410
    assert svc.store.get_action(decision.action_id)["status"] == "EXPIRED"
    assert "EXPIRED" in _event_types(svc, decision.action_id)


def test_approve_with_changed_params_is_denied_and_not_shared(svc):
    decision = _make_review(svc)
    # On altere le destinataire dans la requete stockee apres la REVIEW.
    action = svc.store.get_action(decision.action_id)
    action["request"]["parameters"]["recipient"] = "someone-else@external.example"
    svc.store.put_action(action)

    out = svc.service.decide(decision.approval_id, KEY_ALICE, _decision_in("approve"))
    assert out["action_status"] == "DENIED"
    # revalidation_failed journalisee avec PARAMS_CHANGED.
    blocked = [
        e
        for e in svc.store.list_events(decision.action_id)
        if e["type"] == "BLOCKED"
    ]
    assert any(
        e["payload"].get("rule_ids") == ["PARAMS_CHANGED"] for e in blocked
    )
    assert "Confidential_Audit_Report.pdf" not in svc.drive._shares


def test_concurrent_approve_executes_once(svc):
    import threading

    decision = _make_review(svc)
    results: list = []
    errors: list = []

    def worker():
        try:
            out = svc.service.decide(
                decision.approval_id, KEY_ALICE, _decision_in("approve")
            )
            results.append(out)
        except ApprovalError as e:
            errors.append(e)

    t1 = threading.Thread(target=worker)
    t2 = threading.Thread(target=worker)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    # Une seule execution, l'autre recoit 409.
    assert len(results) == 1
    assert len(errors) == 1
    assert errors[0].code == 409
    # Un seul partage enregistre.
    assert len(svc.drive._shares["Confidential_Audit_Report.pdf"]) == 1


def test_approve_with_missing_action_is_404_and_no_event(svc):
    decision = _make_review(svc)
    # L'action liee disparait : on repointe l'approbation vers une action absente.
    approval = svc.store.get_approval(decision.approval_id)
    approval["action_id"] = "PA-9999"
    svc.store.put_approval(approval)

    with pytest.raises(ApprovalError) as exc:
        svc.service.decide(decision.approval_id, KEY_ALICE, _decision_in("approve"))
    assert exc.value.code == 404
    # Aucun APPROVAL_DECIDED n'a ete ecrit pour l'action absente.
    assert "APPROVAL_DECIDED" not in _event_types(svc, "PA-9999")


def test_approve_internal_error_is_fail_closed(svc):
    decision = _make_review(svc)

    def boom(action, approval):
        raise RuntimeError("revalidate down")

    # On remplace revalidate du pipeline par une fonction qui plante.
    svc.pipeline.revalidate = boom

    out = svc.service.decide(decision.approval_id, KEY_ALICE, _decision_in("approve"))
    assert out["action_status"] == "DENIED"
    # BLOCKED avec reason internal_error.
    blocked = [
        e
        for e in svc.store.list_events(decision.action_id)
        if e["type"] == "BLOCKED"
    ]
    assert any(e["payload"].get("reason") == "internal_error" for e in blocked)
    # L'approbation "approved" est tout de meme sauvegardee (fail closed).
    approval = svc.store.get_approval(decision.approval_id)
    assert approval["status"] == "approved"


def test_expiration_writes_single_event_across_two_list_calls(svc):
    decision = _make_review(svc)
    approval = svc.store.get_approval(decision.approval_id)
    expires_at = datetime.fromisoformat(approval["expires_at"])
    svc.clock.current = expires_at + timedelta(minutes=1)

    svc.service.list()
    svc.service.list()

    expired_events = [
        e
        for e in svc.store.list_events(decision.action_id)
        if e["type"] == "EXPIRED"
    ]
    assert len(expired_events) == 1


def test_list_pending_is_enriched(svc):
    _make_review(svc)
    pending = svc.service.list("pending")
    assert len(pending) == 1
    item = pending[0]
    assert item["tool"] == "google_drive"
    assert item["resource_id"] == "Confidential_Audit_Report.pdf"
    assert item["parameters"] == {
        "recipient": "audit@external.example",
        "role": "reader",
    }
    assert item["taint_sources"] == ["vendor_notes.txt"]
