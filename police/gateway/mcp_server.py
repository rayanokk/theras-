"""Serveur MCP de Theras : une PRISE, pas un controle.

Ce module expose les outils de Theras a n'importe quel client MCP (Claude
Desktop, un IDE, un autre agent...). Il ne prend AUCUNE decision et n'importe ni
les connecteurs, ni le store, ni le pipeline : exactement comme l'agent de A, il
parle au Gateway uniquement par HTTP. Toute la securite reste dans le Gateway.

Fail closed : si le Gateway est injoignable, l'outil renvoie une erreur lisible
et n'execute jamais rien en direct.

Lancement :
    THERAS_AGENT_KEY=... python -m police.gateway.mcp_server

Configuration (variables d'environnement) :
    GATEWAY_URL                 defaut http://127.0.0.1:8000
    THERAS_AGENT_KEY            obligatoire (cle API de l'agent)
    THERAS_REVIEW_WAIT_SECONDS  defaut 60 (attente max d'une decision humaine)
"""

from __future__ import annotations

import os
import time
import uuid

import httpx

# --- Configuration ------------------------------------------------------------

GATEWAY_URL = os.getenv("GATEWAY_URL", "http://127.0.0.1:8000").rstrip("/")
REVIEW_WAIT_SECONDS = int(os.getenv("THERAS_REVIEW_WAIT_SECONDS", "60"))
POLL_INTERVAL_SECONDS = 2

# Une session par lancement du serveur.
_SHORT = uuid.uuid4().hex[:8]
SESSION_ID = "sess-mcp-" + _SHORT
TASK_ID = "task-mcp-" + _SHORT

_FINAL_STATUSES = {"EXECUTED", "DENIED", "EXPIRED", "FAILED"}

# Client HTTP partage. Injectable dans les tests via set_client().
_client: httpx.Client | None = None


def _agent_key() -> str:
    """Cle API de l'agent, obligatoire. Erreur claire si absente."""
    key = os.getenv("THERAS_AGENT_KEY")
    if not key:
        raise RuntimeError(
            "THERAS_AGENT_KEY manquante : definissez la cle API de l'agent "
            "avant de lancer le serveur MCP de Theras."
        )
    return key


def set_client(client: httpx.Client | None) -> None:
    """Remplace le client HTTP (tests : MockTransport ou TestClient)."""
    global _client
    _client = client


def _get_client() -> httpx.Client:
    global _client
    if _client is None:
        _client = httpx.Client(base_url=GATEWAY_URL, timeout=10.0)
    return _client


def _headers() -> dict:
    return {"X-API-Key": _agent_key()}


# --- Rendu des reponses pour le LLM client ------------------------------------


def _render_result(action: str, result: dict | None) -> str:
    """Formate le resultat d'une action executee en texte court et lisible."""
    if not isinstance(result, dict):
        return "Action exécutée."
    if action == "read_file":
        return result.get("content", "")
    if action == "list_files":
        files = result.get("files", [])
        return "Fichiers : " + ", ".join(files) if files else "Aucun fichier."
    if action == "share_file":
        return f"Partagé avec {result.get('shared_with')} ({result.get('role')})."
    if action == "delete_file":
        return "Fichier supprimé." if result.get("deleted") else "Suppression non confirmée."
    if action == "send_email":
        attach = result.get("attachment")
        suffix = f" (pièce jointe : {attach})" if attach else ""
        return f"Email envoyé à {result.get('sent_to')}{suffix}."
    return "Action exécutée."


def _render_deny(decision: dict) -> str:
    rules = ", ".join(decision.get("rule_ids") or []) or "aucune règle"
    reasons = " ; ".join(decision.get("reasons") or [])
    return f"Refusé par Theras : {rules} — {reasons}. Ne pas réessayer."


def _poll_review(action: str, action_id: str, approval_id) -> str:
    """Interroge GET /v1/actions/{id} jusqu'a un statut final ou le timeout."""
    client = _get_client()
    deadline = time.monotonic() + REVIEW_WAIT_SECONDS
    while True:
        try:
            resp = client.get(f"/v1/actions/{action_id}", headers=_headers())
        except httpx.HTTPError:
            return "Theras injoignable : action non exécutée"
        record = resp.json()
        status = record.get("status")
        if status == "EXECUTED":
            return _render_result(action, record.get("result"))
        if status in ("DENIED", "EXPIRED", "FAILED"):
            return "Refusé après revue humaine"
        if time.monotonic() >= deadline:
            return (
                "En attente d'approbation humaine "
                f"(approval_id {approval_id}). "
                "Rappelle get_action_status plus tard."
            )
        time.sleep(POLL_INTERVAL_SECONDS)


def _submit(tool: str, action: str, resource_id: str, parameters: dict) -> str:
    """Construit l'ActionRequest, POST /v1/actions, et rend la reponse."""
    body = {
        "tool": tool,
        "action": action,
        "resource_id": resource_id,
        "parameters": parameters,
        "session_id": SESSION_ID,
        "task_id": TASK_ID,
    }
    client = _get_client()
    try:
        resp = client.post("/v1/actions", json=body, headers=_headers())
    except httpx.HTTPError:
        return "Theras injoignable : action non exécutée"

    decision = resp.json()
    if resp.status_code == 200:
        return _render_result(action, decision.get("result"))
    if resp.status_code == 403:
        return _render_deny(decision)
    if resp.status_code == 202:
        return _poll_review(action, decision.get("action_id"), decision.get("approval_id"))
    # Statut inattendu : fail closed, on ne tente rien d'autre.
    return f"Theras : réponse inattendue ({resp.status_code}), action non exécutée"


# --- Logique des outils (fonctions pures, testables sans la couche MCP) --------


def do_read_file(resource_id: str) -> str:
    return _submit("google_drive", "read_file", resource_id, {})


def do_list_files() -> str:
    return _submit("google_drive", "list_files", "root", {})


def do_share_file(resource_id: str, recipient: str, role: str = "reader") -> str:
    return _submit(
        "google_drive",
        "share_file",
        resource_id,
        {"recipient": recipient, "role": role},
    )


def do_delete_file(resource_id: str) -> str:
    return _submit("google_drive", "delete_file", resource_id, {})


def do_send_email(
    to: str, subject: str, body: str, attachment: str = "none"
) -> str:
    return _submit(
        "mail",
        "send_email",
        attachment,
        {"to": to, "subject": subject, "body": body},
    )


def do_get_action_status(action_id: str) -> str:
    client = _get_client()
    try:
        resp = client.get(f"/v1/actions/{action_id}", headers=_headers())
    except httpx.HTTPError:
        return "Theras injoignable : action non exécutée"
    if resp.status_code == 404:
        return f"Action {action_id} introuvable."
    record = resp.json()
    status = record.get("status")
    result = record.get("result")
    if status == "EXECUTED":
        return f"EXECUTED — {_render_result(record.get('request', {}).get('action'), result)}"
    return f"Statut : {status}"


# --- Serveur MCP (prefere FastMCP ; retombe sur MCPServer pour mcp 2.x) --------


def _make_server():
    try:  # mcp < 2
        from mcp.server.fastmcp import FastMCP

        return FastMCP("theras")
    except ModuleNotFoundError:  # mcp >= 2 : FastMCP renomme MCPServer
        from mcp.server.mcpserver import MCPServer

        return MCPServer("theras")


mcp = _make_server()


@mcp.tool()
def read_file(resource_id: str) -> str:
    """Lit le contenu d'un fichier du Drive. L'accès est contrôlé par Theras
    (ACL de l'agent). Renvoie le contenu, ou un refus explicite."""
    return do_read_file(resource_id)


@mcp.tool()
def list_files() -> str:
    """Liste les fichiers du Drive visibles par l'agent."""
    return do_list_files()


@mcp.tool()
def share_file(resource_id: str, recipient: str, role: str = "reader") -> str:
    """Partage un fichier avec un destinataire (email). role = "reader" ou
    "writer". Theras peut refuser, ou exiger une approbation humaine (l'outil
    attend alors la décision)."""
    return do_share_file(resource_id, recipient, role)


@mcp.tool()
def delete_file(resource_id: str) -> str:
    """Supprime un fichier du Drive. Action sensible : Theras exige en général
    une approbation humaine."""
    return do_delete_file(resource_id)


@mcp.tool()
def send_email(to: str, subject: str, body: str, attachment: str = "none") -> str:
    """Envoie un email. attachment = resource_id d'une pièce jointe, ou "none".
    Theras contrôle le destinataire et la classification de la pièce jointe."""
    return do_send_email(to, subject, body, attachment)


@mcp.tool()
def get_action_status(action_id: str) -> str:
    """Renvoie le statut (et le résultat si disponible) d'une action précédente,
    par exemple une action encore en attente d'approbation humaine."""
    return do_get_action_status(action_id)


if __name__ == "__main__":
    mcp.run()
