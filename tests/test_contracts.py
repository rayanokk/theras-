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
    ActionRequest,
    ApprovalDecisionIn,
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
