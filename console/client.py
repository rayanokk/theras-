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

from contracts.models import ActionRecord, ApprovalView, Event

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

    def list_actions(self, status: str | None = None) -> list[ActionRecord]: ...

    def list_action_rows(self, status: str | None = None) -> list[dict]: ...

    def list_events(self, action_id: str | None = None) -> list[Event]: ...

    def verify_chain(self) -> dict: ...

    def export_jsonl(self) -> str: ...

    def list_pending_approvals(self) -> list[ApprovalView]: ...

    def decide(self, approval_id: str, decision: str, justification: str) -> dict: ...


def _recipient_from_params(parameters: dict) -> str | None:
    """Destinataire : recipient (partage) ou to (mail), None sinon."""
    if not isinstance(parameters, dict):
        return None
    return parameters.get("recipient") or parameters.get("to")


def _action_to_row(record: ActionRecord) -> dict:
    """Ligne d'affichage pour le tableau, à partir d'un ActionRecord.

    Lit tool/action/resource_id/user_id/reason/recipient depuis `record.request`
    (format Gateway), avec repli sur d'éventuels attributs à plat. Expose aussi
    reason et taint_sources."""
    request = record.request if isinstance(record.request, dict) else {}
    tool = request.get("tool")
    act = request.get("action")
    resource_id = request.get("resource_id")
    user_id = request.get("user_id")
    reason = request.get("reason")
    recipient = _recipient_from_params(request.get("parameters", {}))

    return {
        "action_id": record.action_id,
        "agent_id": record.agent_id,
        "declared_agent_id": record.declared_agent_id,
        "tool": tool,
        "action": act,
        "resource_id": resource_id,
        "user_id": user_id,
        "reason": reason,
        "recipient": recipient,
        "verdict": record.verdict.value,
        "status": record.status.value,
        "rule_ids": ", ".join(record.rule_ids),
        "taint_sources": list(record.taint_sources),
    }


class LocalClient:
    """Lit la base locale et convertit en modèles du contrat. Lecture seule."""

    def __init__(self, db_path: str | None = None) -> None:
        # Import local pour que l'import du module ne tire pas SQLite si inutile.
        from police.evidence.vault import EvidenceVault
        from police.store.sqlite_store import SQLiteStore

        self._db_path = db_path or os.environ.get(ENV_DB_PATH, DEFAULT_DB_PATH)
        self._store = SQLiteStore(self._db_path)
        self._vault = EvidenceVault(self._store)

    def list_actions(self, status: str | None = None) -> list[ActionRecord]:
        return [
            ActionRecord.model_validate(a) for a in self._store.list_actions(status)
        ]

    def list_action_rows(self, status: str | None = None) -> list[dict]:
        return [_action_to_row(r) for r in self.list_actions(status)]

    def list_events(self, action_id: str | None = None) -> list[Event]:
        return [Event.model_validate(e) for e in self._store.list_events(action_id)]

    def verify_chain(self) -> dict:
        return self._vault.verify()

    def export_jsonl(self) -> str:
        return self._vault.export_jsonl()

    def list_pending_approvals(self) -> list[ApprovalView]:
        return [
            ApprovalView.model_validate(a)
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

    def list_actions(self, status: str | None = None) -> list[ActionRecord]:
        params = {"status": status} if status else None
        resp = self._client.get("/v1/actions", params=params)
        resp.raise_for_status()
        return [ActionRecord.model_validate(item) for item in resp.json()]

    def list_action_rows(self, status: str | None = None) -> list[dict]:
        # L'API renvoie des ActionRecord (request imbriqué) ; _action_to_row
        # en extrait outil/action/ressource/destinataire.
        return [_action_to_row(r) for r in self.list_actions(status)]

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

    def list_pending_approvals(self) -> list[ApprovalView]:
        resp = self._client.get("/v1/approvals", params={"status": "pending"})
        resp.raise_for_status()
        return [ApprovalView.model_validate(item) for item in resp.json()]

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
