"""Tests du contrat 1 (ActionRequest + params par action), 3 (ResourceInfo),
5 (ApprovalDecisionIn) et 7 (params_hash), ecrits avant l'implementation.

Ces tests importent depuis contracts.models, qui n'existe pas encore :
ils doivent echouer a la collecte tant que le module n'est pas ecrit.
"""

import pytest
from pydantic import ValidationError

from contracts.models import (
    ACTION_TOOL,
    PARAMS_MODELS,
    ActionRecord,
    ActionRequest,
    ApprovalDecisionIn,
    ApprovalView,
    ResourceInfo,
    ShareFileParams,
    params_hash,
)


# --- Contrat 1 : ActionRequest -------------------------------------------------


def _valid_share_request() -> dict:
    return {
        "agent_id": "agent-ops",
        "user_id": "user-claire",
        "tool": "google_drive",
        "action": "share_file",
        "resource_id": "Company_Brochure.pdf",
        "parameters": {"recipient": "colleague@acme.example", "role": "reader"},
        "reason": "partage interne",
        "session_id": "sess-1",
        "task_id": "task-1",
    }


def test_valid_share_action_request_is_accepted():
    req = ActionRequest.model_validate(_valid_share_request())
    assert req.tool == "google_drive"
    assert req.action == "share_file"
    assert req.resource_id == "Company_Brochure.pdf"
    assert req.parameters == {"recipient": "colleague@acme.example", "role": "reader"}


def test_unknown_field_in_action_request_is_rejected():
    payload = _valid_share_request()
    payload["unexpected"] = "boom"
    with pytest.raises(ValidationError):
        ActionRequest.model_validate(payload)


def test_resource_id_with_path_traversal_is_rejected():
    payload = _valid_share_request()
    payload["resource_id"] = "../secret"
    with pytest.raises(ValidationError):
        ActionRequest.model_validate(payload)


def test_list_files_request_with_resource_id_root_is_accepted():
    req = ActionRequest.model_validate(
        {
            "agent_id": "agent-ops",
            "tool": "google_drive",
            "action": "list_files",
            "resource_id": "root",
            "parameters": {},
            "session_id": "sess-1",
            "task_id": "task-1",
        }
    )
    assert req.resource_id == "root"


def test_send_email_request_with_resource_id_none_is_accepted():
    req = ActionRequest.model_validate(
        {
            "agent_id": "agent-assistant",
            "tool": "mail",
            "action": "send_email",
            "resource_id": "none",
            "parameters": {
                "to": "colleague@acme.example",
                "subject": "hello",
                "body": "contenu",
            },
            "session_id": "sess-1",
            "task_id": "task-1",
        }
    )
    assert req.resource_id == "none"


# --- Contrat 1 : ShareFileParams ----------------------------------------------


def test_share_file_params_valid_is_accepted():
    params = ShareFileParams.model_validate(
        {"recipient": "colleague@acme.example", "role": "reader"}
    )
    assert params.recipient == "colleague@acme.example"
    assert params.role == "reader"


def test_share_file_params_rejects_missing_recipient():
    with pytest.raises(ValidationError):
        ShareFileParams.model_validate({"role": "reader"})


def test_share_file_params_rejects_role_owner():
    with pytest.raises(ValidationError):
        ShareFileParams.model_validate(
            {"recipient": "colleague@acme.example", "role": "owner"}
        )


def test_share_file_params_rejects_invalid_email():
    with pytest.raises(ValidationError):
        ShareFileParams.model_validate(
            {"recipient": "not-an-email", "role": "reader"}
        )


# --- Contrat 7 : params_hash ---------------------------------------------------


def test_params_hash_is_stable_across_parameter_key_order():
    a = ActionRequest.model_validate(_valid_share_request())
    reordered = _valid_share_request()
    reordered["parameters"] = {"role": "reader", "recipient": "colleague@acme.example"}
    b = ActionRequest.model_validate(reordered)
    assert params_hash(a) == params_hash(b)


def test_params_hash_ignores_reason():
    a = ActionRequest.model_validate(_valid_share_request())
    other = _valid_share_request()
    other["reason"] = "une raison totalement differente"
    b = ActionRequest.model_validate(other)
    assert params_hash(a) == params_hash(b)


def test_params_hash_changes_with_recipient():
    a = ActionRequest.model_validate(_valid_share_request())
    other = _valid_share_request()
    other["parameters"]["recipient"] = "someone-else@acme.example"
    b = ActionRequest.model_validate(other)
    assert params_hash(a) != params_hash(b)


def test_params_hash_native_request_is_frozen():
    # Valeur figee : le passage de tool/action en str (support MCP) ne doit PAS
    # changer le hash d'une requete native. Si ce test casse, la compatibilite
    # des approbations deja emises est rompue.
    req = ActionRequest.model_validate(
        {
            "tool": "google_drive",
            "action": "share_file",
            "resource_id": "Company_Brochure.pdf",
            "parameters": {"recipient": "colleague@acme.example", "role": "reader"},
            "session_id": "sess-1",
            "task_id": "task-1",
        }
    )
    assert (
        params_hash(req)
        == "c3eea050d1e9f7d2d707bcb471a9f7c5a705cc59843af25247ccd3169986f2e7"
    )


# --- Contrat 5 : ApprovalDecisionIn -------------------------------------------


def test_approval_decision_rejects_short_justification():
    with pytest.raises(ValidationError):
        ApprovalDecisionIn.model_validate(
            {"decision": "approve", "justification": "123456789"}  # 9 caracteres
        )


def test_approval_decision_accepts_ten_char_justification():
    dec = ApprovalDecisionIn.model_validate(
        {"decision": "approve", "justification": "1234567890"}  # 10 caracteres
    )
    assert dec.decision == "approve"


# --- Contrat 3 : ResourceInfo -------------------------------------------------


def test_resource_info_accepts_classification_none():
    info = ResourceInfo.model_validate(
        {
            "exists": True,
            "classification": "none",
            "owner": None,
            "acl": [],
            "trusted": True,
            "recipient_email": None,
            "recipient_domain": None,
        }
    )
    assert info.classification == "none"


def test_resource_info_rejects_unknown_classification():
    with pytest.raises(ValidationError):
        ResourceInfo.model_validate(
            {
                "exists": True,
                "classification": "secret",
                "owner": None,
                "acl": [],
                "trusted": True,
                "recipient_email": None,
                "recipient_domain": None,
            }
        )


# --- Registres : PARAMS_MODELS et ACTION_TOOL ---------------------------------


def test_each_action_has_a_params_model_and_a_tool():
    actions = {
        "read_file",
        "list_files",
        "share_file",
        "delete_file",
        "send_email",
    }
    assert actions <= set(PARAMS_MODELS)
    assert actions <= set(ACTION_TOOL)
    for action in actions:
        assert ACTION_TOOL[action] in {"google_drive", "mail"}


# --- Vues enrichies renvoyees a la console (ActionRecord, ApprovalView) --------
# On construit la vraie pile (pipeline + service) pour produire des reponses API
# authentiques, puis on verifie qu'elles valident contre les modeles de vue.

from pathlib import Path

from police.approvals.service import ApprovalService
from police.connectors.drive_mock import DriveMock
from police.connectors.mail_mock import MailMock
from police.evidence.vault import EvidenceVault
from police.gateway.pipeline import Pipeline
from police.identity import IdentityRegistry
from police.policy.engine import load_policy
from police.policy.taint import TaintTracker
from police.store.sqlite_store import SQLiteStore

_REPO = Path(__file__).resolve().parents[1]
_KEY_ASSISTANT = "k-assistant"


@pytest.fixture
def api_ctx(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_KEY_RESEARCH", "k-research")
    monkeypatch.setenv("AGENT_KEY_OPS", "k-ops")
    monkeypatch.setenv("AGENT_KEY_ASSISTANT", _KEY_ASSISTANT)
    monkeypatch.setenv("APPROVER_KEY_ALICE", "k-alice")
    monkeypatch.setenv("APPROVER_KEY_BOB", "k-bob")

    store = SQLiteStore(str(tmp_path / "test.db"))
    drive = DriveMock()
    mail = MailMock(drive)
    vault = EvidenceVault(store)
    policy = load_policy(_REPO / "policies" / "policies.yaml")
    identities = IdentityRegistry(_REPO / "data" / "identities.json")
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
    service = ApprovalService(store, vault, pipeline, identities)

    class Ctx:
        pass

    c = Ctx()
    c.store = store
    c.pipeline = pipeline
    c.service = service
    yield c
    store.close()


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


def test_action_record_validates_real_review_action(api_ctx):
    api_ctx.pipeline.handle(_read_vendor(), _KEY_ASSISTANT)
    decision = api_ctx.pipeline.handle(_share_confidential(), _KEY_ASSISTANT)
    assert decision.verdict == "REVIEW"

    stored = api_ctx.store.get_action(decision.action_id)
    record = ActionRecord.model_validate(stored)
    assert record.action_id == decision.action_id
    assert record.agent_id == "agent-assistant"
    assert record.taint_sources == ["vendor_notes.txt"]
    assert record.request is not None
    assert record.approval_id == decision.approval_id


def test_approval_view_validates_real_pending_approval(api_ctx):
    api_ctx.pipeline.handle(_read_vendor(), _KEY_ASSISTANT)
    api_ctx.pipeline.handle(_share_confidential(), _KEY_ASSISTANT)

    pending = api_ctx.service.list("pending")
    assert len(pending) == 1
    view = ApprovalView.model_validate(pending[0])
    assert view.status.value == "pending"
    assert view.tool == "google_drive"
    assert view.resource_id == "Confidential_Audit_Report.pdf"
    assert view.parameters == {
        "recipient": "audit@external.example",
        "role": "reader",
    }
    assert view.taint_sources == ["vendor_notes.txt"]
