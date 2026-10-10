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


class ConsoleClient(Protocol):
    """Interface de lecture/décision pour la console."""

    def list_actions(self, status: str | None = None) -> list[Decision]: ...

    def list_action_rows(self, status: str | None = None) -> list[dict]: ...

    def list_events(self, action_id: str | None = None) -> list[Event]: ...

    def verify_chain(self) -> dict: ...

    def export_jsonl(self) -> str: ...

    def list_pending_approvals(self) -> list[ApprovalRequest]: ...

    def decide(self, approval_id: str, decision: str, justification: str) -> dict: ...


_ROW_FIELDS = (
    "action_id",
    "agent_id",
    "tool",
    "action",
    "resource_id",
    "verdict",
    "status",
    "rule_ids",
)


def _action_to_row(action: dict) -> dict:
    """Ligne d'affichage pour le tableau (champs non portés par Decision)."""
    row = {k: action.get(k) for k in _ROW_FIELDS}
    row["rule_ids"] = ", ".join(action.get("rule_ids", []))
    return row


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
        self, base_url: str | None = None, api_key: str | None = None
    ) -> None:
        import httpx

        self._base_url = (
            base_url or os.environ.get(ENV_GATEWAY_URL, DEFAULT_GATEWAY_URL)
        ).rstrip("/")
        self._api_key = api_key or os.environ.get(ENV_APPROVER_KEY, "")
        self._client = httpx.Client(
            base_url=self._base_url,
            headers={"X-API-Key": self._api_key},
            timeout=10.0,
        )

    def list_actions(self, status: str | None = None) -> list[Decision]:
        params = {"status": status} if status else None
        resp = self._client.get("/v1/actions", params=params)
        resp.raise_for_status()
        return [Decision.model_validate(item) for item in resp.json()]

    def list_action_rows(self, status: str | None = None) -> list[dict]:
        # L'API renvoie des Decision ; agent/outil/action/ressource ne sont pas
        # dans le contrat 2, donc indisponibles en mode http.
        params = {"status": status} if status else None
        resp = self._client.get("/v1/actions", params=params)
        resp.raise_for_status()
        rows = []
        for item in resp.json():
            rows.append(
                {
                    "action_id": item.get("action_id"),
                    "agent_id": None,
                    "tool": None,
                    "action": None,
                    "resource_id": None,
                    "verdict": item.get("verdict"),
                    "status": item.get("status"),
                    "rule_ids": ", ".join(item.get("rule_ids", [])),
                }
            )
        return rows

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
        resp.raise_for_status()
        return resp.json()

    def close(self) -> None:
        self._client.close()


def get_client() -> ConsoleClient:
    """Choisit l'implémentation selon CONSOLE_MODE (local par défaut, ou http)."""
    mode = os.environ.get(ENV_CONSOLE_MODE, "local").strip().lower()
    if mode == "http":
        return HttpClient()
    return LocalClient()
