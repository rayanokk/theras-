"""Client de la console Police Agents.

Deux implémentations derrière un même Protocol :
- LocalClient : lit directement la base (SQLiteStore + EvidenceVault) et convertit
  en modèles figés de contracts/models.py. `decide` est interdit en local : une
  décision doit passer par l'API pour être revalidée (contrat 5).
- HttpClient : appelle les routes du Gateway (contrat) avec httpx et X-API-Key.

get_client() choisit selon CONSOLE_MODE ("local" par défaut, ou "http").
Les pages Streamlit ne connaissent que ce module, jamais SQLiteStore.
"""

import os
from typing import Protocol

from contracts.models import ApprovalRequest, Decision, Event

# Variables d'environnement (cf. .env.example).
ENV_DB_PATH = "POLICE_DB_PATH"
ENV_GATEWAY_URL = "GATEWAY_URL"
ENV_CONSOLE_MODE = "CONSOLE_MODE"
ENV_APPROVER_KEY = "APPROVER_KEY_ALICE"  # clé d'approbateur par défaut de la console

DEFAULT_DB_PATH = "police.db"
DEFAULT_GATEWAY_URL = "http://localhost:8000"


class DecideError(Exception):
    """Erreur de décision, avec un message clair prêt à afficher."""


# Traduction des codes d'erreur du contrat 5 en messages lisibles.
_DECIDE_HTTP_MESSAGES = {
    401: "Clé inconnue.",
    403: "Cette clé n'a pas le rôle d'approbateur.",
    409: "Décision déjà prise pour cette approbation.",
    410: "Approbation expirée.",
    422: "Justification invalide (10 caractères minimum).",
}


def _decide_message_for_status(status_code: int) -> str:
    """Message clair pour un code HTTP de /decide."""
    return _DECIDE_HTTP_MESSAGES.get(
        status_code, f"Erreur du Gateway (HTTP {status_code})."
    )


class ConsoleClient(Protocol):
    """Interface de lecture/décision pour la console."""

    def list_actions(self, status: str | None = None) -> list[Decision]: ...

    def list_action_rows(self, status: str | None = None) -> list[dict]: ...

    def list_events(self, action_id: str | None = None) -> list[Event]: ...

    def verify_chain(self) -> dict: ...

    def export_jsonl(self) -> str: ...

    def list_pending_approvals(self) -> list[ApprovalRequest]: ...

    def decide(self, approval_id: str, decision: str, justification: str) -> dict: ...


def _recipient_from_params(parameters: dict) -> str | None:
    """Destinataire : recipient (partage) ou to (mail), None sinon."""
    if not isinstance(parameters, dict):
        return None
    return parameters.get("recipient") or parameters.get("to")


def _action_to_row(action: dict) -> dict:
    """Ligne d'affichage pour le tableau.

    Lit tool/action/resource_id/user_id/reason/recipient depuis `request`
    (format Gateway), avec repli sur l'ancien format à plat. Expose aussi
    reason et taint_sources."""
    request = action.get("request")
    if isinstance(request, dict):
        tool = request.get("tool")
        act = request.get("action")
        resource_id = request.get("resource_id")
        user_id = request.get("user_id")
        reason = request.get("reason")
        recipient = _recipient_from_params(request.get("parameters", {}))
    else:
        # Repli : ancien format à plat.
        tool = action.get("tool")
        act = action.get("action")
        resource_id = action.get("resource_id")
        user_id = action.get("user_id")
        reason = action.get("reason")
        recipient = _recipient_from_params(action.get("params", {}))

    return {
        "action_id": action.get("action_id"),
        "agent_id": action.get("agent_id"),
        "tool": tool,
        "action": act,
        "resource_id": resource_id,
        "user_id": user_id,
        "reason": reason,
        "recipient": recipient,
        "verdict": action.get("verdict"),
        "status": action.get("status"),
        "rule_ids": ", ".join(action.get("rule_ids", [])),
        "taint_sources": action.get("taint_sources", []),
    }


def _action_to_decision(action: dict) -> Decision:
    """Convertit un dict action stocké en Decision (sous-ensemble du contrat 2)."""
    return Decision.model_validate(
        {
            "action_id": action["action_id"],
            "verdict": action["verdict"],
            "status": action["status"],
            "rule_ids": action.get("rule_ids", []),
            "reasons": action.get("reasons", []),
            "risk": action.get("risk"),
            "params_hash": action.get("params_hash", ""),
            "policy_version": action.get("policy_version", ""),
            "approval_id": action.get("approval_id"),
            "result": action.get("result"),
        }
    )


class LocalClient:
    """Lit la base locale et convertit en modèles du contrat. Lecture seule."""

    def __init__(self, db_path: str | None = None) -> None:
        # Import local pour que l'import du module ne tire pas SQLite si inutile.
        from police.evidence.vault import EvidenceVault
        from police.store.sqlite_store import SQLiteStore

        self._db_path = db_path or os.environ.get(ENV_DB_PATH, DEFAULT_DB_PATH)
        self._store = SQLiteStore(self._db_path)
        self._vault = EvidenceVault(self._store)

    def list_actions(self, status: str | None = None) -> list[Decision]:
        return [_action_to_decision(a) for a in self._store.list_actions(status)]

    def list_action_rows(self, status: str | None = None) -> list[dict]:
        return [_action_to_row(a) for a in self._store.list_actions(status)]

    def list_events(self, action_id: str | None = None) -> list[Event]:
        return [Event.model_validate(e) for e in self._store.list_events(action_id)]

    def verify_chain(self) -> dict:
        return self._vault.verify()

    def export_jsonl(self) -> str:
        return self._vault.export_jsonl()

    def list_pending_approvals(self) -> list[ApprovalRequest]:
        return [
            ApprovalRequest.model_validate(a)
            for a in self._store.list_approvals(status="pending")
        ]

    def decide(self, approval_id: str, decision: str, justification: str) -> dict:
        raise NotImplementedError(
            "Une décision doit passer par l'API (revalidation). "
            "Utilise CONSOLE_MODE=http."
        )

    def close(self) -> None:
        self._store.close()


class HttpClient:
    """Appelle les routes du Gateway avec httpx et le header X-API-Key."""

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        transport=None,
    ) -> None:
        import httpx

        self._base_url = (
            base_url or os.environ.get(ENV_GATEWAY_URL, DEFAULT_GATEWAY_URL)
        ).rstrip("/")
        self._api_key = api_key or os.environ.get(ENV_APPROVER_KEY, "")
        # transport injectable (ex. httpx.MockTransport) pour les tests.
        self._client = httpx.Client(
            base_url=self._base_url,
            headers={"X-API-Key": self._api_key},
            timeout=10.0,
            transport=transport,
        )

    def list_actions(self, status: str | None = None) -> list[Decision]:
        params = {"status": status} if status else None
        resp = self._client.get("/v1/actions", params=params)
        resp.raise_for_status()
        return [Decision.model_validate(item) for item in resp.json()]

    def list_action_rows(self, status: str | None = None) -> list[dict]:
        # L'API renvoie les actions au format Gateway (request imbriqué) ;
        # _action_to_row sait en extraire outil/action/ressource/destinataire.
        params = {"status": status} if status else None
        resp = self._client.get("/v1/actions", params=params)
        resp.raise_for_status()
        return [_action_to_row(item) for item in resp.json()]

    def list_events(self, action_id: str | None = None) -> list[Event]:
        params = {"action_id": action_id} if action_id else None
        resp = self._client.get("/v1/evidence", params=params)
        resp.raise_for_status()
        return [Event.model_validate(item) for item in resp.json()]

    def verify_chain(self) -> dict:
        resp = self._client.get("/v1/evidence/verify")
        resp.raise_for_status()
        return resp.json()

    def export_jsonl(self) -> str:
        resp = self._client.get("/v1/evidence/export")
        resp.raise_for_status()
        return resp.text

    def list_pending_approvals(self) -> list[ApprovalRequest]:
        resp = self._client.get("/v1/approvals", params={"status": "pending"})
        resp.raise_for_status()
        return [ApprovalRequest.model_validate(item) for item in resp.json()]

    def decide(self, approval_id: str, decision: str, justification: str) -> dict:
        resp = self._client.post(
            f"/v1/approvals/{approval_id}/decide",
            json={"decision": decision, "justification": justification},
        )
        if resp.status_code >= 400:
            raise DecideError(_decide_message_for_status(resp.status_code))
        return resp.json()

    def close(self) -> None:
        self._client.close()


def get_client() -> ConsoleClient:
    """Choisit l'implémentation selon CONSOLE_MODE (local par défaut, ou http)."""
    mode = os.environ.get(ENV_CONSOLE_MODE, "local").strip().lower()
    if mode == "http":
        return HttpClient()
    return LocalClient()
