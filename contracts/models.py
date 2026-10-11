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
import re
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


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

# Outils natifs du Gateway (enum Tool) : valides exactement comme avant. Un outil
# MCP (serveur amont declare par un manifeste) suit des contraintes de forme plus
# larges ; son existence reelle est verifiee par le pipeline, pas ici.
_NATIVE_TOOLS = {t.value for t in Tool}
_NATIVE_ACTIONS = {a.value for a in Action}
MCP_TOOL_PATTERN = r"^[a-z][a-z0-9_]{1,30}$"
MCP_ACTION_PATTERN = r"^[A-Za-z0-9_.-]{1,64}$"
MCP_RESOURCE_MAX_LEN = 512
MCP_PARAMS_MAX_KEYS = 20
MCP_PARAMS_MAX_JSON = 10_000
_MCP_TOOL_RE = re.compile(MCP_TOOL_PATTERN)
_MCP_ACTION_RE = re.compile(MCP_ACTION_PATTERN)
_RESOURCE_ID_RE = re.compile(RESOURCE_ID_PATTERN)


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


def _has_control_char(value: str) -> bool:
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in value)


class ActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: str | None = None
    user_id: str | None = None
    # tool/action sont des str : les outils natifs portent une valeur de l'enum
    # Tool/Action, un outil MCP porte un nom libre (serveur/outil amont).
    tool: str
    action: str
    resource_id: str
    parameters: dict[str, Any]
    reason: str | None = Field(default=None, max_length=500)
    session_id: str
    task_id: str

    @model_validator(mode="after")
    def _validate_tool_action(self) -> "ActionRequest":
        if self.tool in _NATIVE_TOOLS:
            self._validate_native()
        else:
            self._validate_mcp()
        return self

    def _validate_native(self) -> None:
        """Validations des outils natifs : EXACTEMENT comme avant (aucun assouplissement)."""
        # action dans l'enum Action.
        if self.action not in _NATIVE_ACTIONS:
            raise ValueError(f"action '{self.action}' inconnue")
        # coherence outil/action.
        if ACTION_TOOL.get(self.action) != self.tool:
            raise ValueError(
                f"action '{self.action}' incohérente avec l'outil '{self.tool}'"
            )
        # resource_id : regex native + 128 caracteres max.
        if len(self.resource_id) > 128 or not _RESOURCE_ID_RE.match(self.resource_id):
            raise ValueError(f"resource_id '{self.resource_id}' invalide")
        # parametres stricts par action.
        model = PARAMS_MODELS[self.action]
        model.model_validate(self.parameters)

    def _validate_mcp(self) -> None:
        """Validations de forme d'un outil MCP ; l'existence est vérifiée par le pipeline."""
        if not _MCP_TOOL_RE.match(self.tool):
            raise ValueError(f"nom de serveur MCP '{self.tool}' invalide")
        if not _MCP_ACTION_RE.match(self.action):
            raise ValueError(f"nom d'outil MCP '{self.action}' invalide")
        if not (1 <= len(self.resource_id) <= MCP_RESOURCE_MAX_LEN):
            raise ValueError("resource_id MCP de longueur invalide")
        if _has_control_char(self.resource_id):
            raise ValueError("resource_id MCP contient un caractère de contrôle")
        if len(self.parameters) > MCP_PARAMS_MAX_KEYS:
            raise ValueError("parameters MCP : trop de clés")
        if len(canonical_json(self.parameters)) > MCP_PARAMS_MAX_JSON:
            raise ValueError("parameters MCP : sérialisation trop longue")


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


# --- Vues enrichies renvoyees a la console ------------------------------------
# Ces modeles decrivent ce que l'API renvoie REELLEMENT (Decision/ApprovalRequest
# enrichis par le pipeline et le service). extra="ignore" : la console tolere un
# champ ajoute plus tard sans casser.


class ActionRecord(Decision):
    """Action stockee, renvoyee par GET /v1/actions et GET /v1/actions/{id}."""

    model_config = ConfigDict(extra="ignore")

    agent_id: str | None = None
    declared_agent_id: str | None = None
    request: dict[str, Any] | None = None
    session_id: str | None = None
    created_at: str | None = None
    taint_sources: list[str] = Field(default_factory=list)


class ApprovalView(ApprovalRequest):
    """Approbation enrichie, renvoyee par GET /v1/approvals et /v1/approvals/{id}."""

    model_config = ConfigDict(extra="ignore")

    agent_id: str | None = None
    user_id: str | None = None
    tool: str | None = None
    action: str | None = None
    resource_id: str | None = None
    reason: str | None = None
    action_status: str | None = None
    parameters: dict[str, Any] | None = None
    rule_ids: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    taint_sources: list[str] = Field(default_factory=list)
    risk: dict[str, Any] | None = None
