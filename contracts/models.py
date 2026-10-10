"""Theras : modeles Pydantic et helpers de hash (contrats 1, 2, 3, 4, 5, 7).

Fichier fige (`contracts.md`) : la decision ne vient jamais d'ici. Ces modeles
decrivent la forme des donnees echangees ; la validation metier (ACL, politique,
coherence outil/action) est faite par le pipeline, qui transforme toute
`ValidationError` en DENY R-DENY-06. C'est pourquoi la route FastAPI recoit un
dict brut et appelle `ActionRequest.model_validate` elle-meme (pas de 422 auto).
"""

from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


# --- Enums (toutes heritent de str pour une serialisation JSON transparente) ---


class Tool(str, Enum):
    GOOGLE_DRIVE = "google_drive"
    MAIL = "mail"


class Action(str, Enum):
    READ_FILE = "read_file"
    LIST_FILES = "list_files"
    SHARE_FILE = "share_file"
    DELETE_FILE = "delete_file"
    SEND_EMAIL = "send_email"


class Role(str, Enum):
    READER = "reader"
    WRITER = "writer"


class Classification(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    NONE = "none"


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    DENY = "DENY"


class ActionStatus(str, Enum):
    PENDING_REVIEW = "PENDING_REVIEW"
    EXECUTED = "EXECUTED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"
    FAILED = "FAILED"


class RiskSource(str, Enum):
    HEURISTICS = "heuristics"
    LLM = "llm"
    LLM_UNAVAILABLE = "llm_unavailable"


class EventType(str, Enum):
    REQUESTED = "REQUESTED"
    DECIDED = "DECIDED"
    APPROVAL_DECIDED = "APPROVAL_DECIDED"
    EXECUTED = "EXECUTED"
    BLOCKED = "BLOCKED"
    EXPIRED = "EXPIRED"


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    INFO_REQUESTED = "info_requested"
    EXPIRED = "expired"


class ApprovalDecision(str, Enum):
    APPROVE = "approve"
    REJECT = "reject"
    REQUEST_INFO = "request_info"


# --- Contraintes partagees -----------------------------------------------------

# resource_id : nom de fichier, ou les valeurs reservees "root" / "none" qui
# respectent elles aussi la regex (aucun cas special dans les modeles).
RESOURCE_ID_PATTERN = r"^[a-zA-Z0-9_.-]+$"
# Email simple, aligne sur contracts.md : local@domaine.tld, sans espace.
EMAIL_PATTERN = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"


# --- Contrat 1 : parametres stricts par action --------------------------------


class ReadFileParams(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ListFilesParams(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ShareFileParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    recipient: str = Field(pattern=EMAIL_PATTERN)
    role: Role


class DeleteFileParams(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SendEmailParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    to: str = Field(pattern=EMAIL_PATTERN)
    subject: str
    body: str


# Chaque action -> son modele de parametres strict.
PARAMS_MODELS: dict[str, type[BaseModel]] = {
    Action.READ_FILE.value: ReadFileParams,
    Action.LIST_FILES.value: ListFilesParams,
    Action.SHARE_FILE.value: ShareFileParams,
    Action.DELETE_FILE.value: DeleteFileParams,
    Action.SEND_EMAIL.value: SendEmailParams,
}

# Chaque action -> son outil (sert au pipeline a verifier la coherence).
ACTION_TOOL: dict[str, str] = {
    Action.READ_FILE.value: Tool.GOOGLE_DRIVE.value,
    Action.LIST_FILES.value: Tool.GOOGLE_DRIVE.value,
    Action.SHARE_FILE.value: Tool.GOOGLE_DRIVE.value,
    Action.DELETE_FILE.value: Tool.GOOGLE_DRIVE.value,
    Action.SEND_EMAIL.value: Tool.MAIL.value,
}


# --- Contrat 1 : ActionRequest ------------------------------------------------


class ActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: str | None = None
    user_id: str | None = None
    tool: Tool
    action: Action
    resource_id: str = Field(max_length=128, pattern=RESOURCE_ID_PATTERN)
    parameters: dict[str, Any]
    reason: str | None = Field(default=None, max_length=500)
    session_id: str
    task_id: str


# --- Contrat 7 : hash canonique -----------------------------------------------


def canonical_json(obj: Any) -> str:
    """Serialisation canonique : cles triees, pas d'espaces, UTF-8 conserve.

    Une seule implementation pour tout le projet (hash reproductible).
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def params_hash(req: ActionRequest) -> str:
    """SHA-256 sur {tool, action, resource_id, parameters} uniquement.

    `reason`, `session_id` et `task_id` n'entrent pas dans le hash. On passe par
    model_dump(mode="json") pour que les enums deviennent des chaines, puis
    canonical_json garantit un ordre stable des cles.
    """
    data = req.model_dump(mode="json")
    payload = {
        "tool": data["tool"],
        "action": data["action"],
        "resource_id": data["resource_id"],
        "parameters": data["parameters"],
    }
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


# --- Contrat 2 : RiskSignal et Decision ---------------------------------------


class RiskSignal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    score: float | None = None
    signals: list[str] = Field(default_factory=list)
    source: RiskSource
    summary: str | None = None
    latency_ms: int


class Decision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_id: str
    verdict: Verdict
    status: ActionStatus
    rule_ids: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    risk: RiskSignal | None = None
    params_hash: str
    policy_version: str
    approval_id: str | None = None
    result: dict[str, Any] | None = None


# --- Contrat 3 : ResourceInfo -------------------------------------------------


class ResourceInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    exists: bool
    classification: Classification
    owner: str | None = None
    acl: list[str] = Field(default_factory=list)
    trusted: bool
    recipient_email: str | None = None
    recipient_domain: str | None = None


# --- Contrat 4 : Event (Evidence Vault) ---------------------------------------


class Event(BaseModel):
    model_config = ConfigDict(extra="forbid")

    seq: int
    ts: str
    type: EventType
    action_id: str
    payload: dict[str, Any]
    policy_version: str
    prev_hash: str
    hash: str


# --- Contrat 5 : approbations -------------------------------------------------


class ApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approval_id: str
    action_id: str
    params_hash: str
    status: ApprovalStatus
    created_at: str
    expires_at: str
    approver_id: str | None = None
    decision: ApprovalDecision | None = None
    justification: str | None = None
    decided_at: str | None = None


class ApprovalDecisionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: ApprovalDecision
    justification: str = Field(min_length=10)
