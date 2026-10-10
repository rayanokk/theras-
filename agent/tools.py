"""Outils exposés au modèle + traduction en ActionRequest (contrat 1) + appel au Gateway.

L'agent ne connaît QUE l'URL du Gateway et sa clé. Il n'importe jamais police/ :
toute exécution passe par POST /v1/actions.
"""
import os
import time

import httpx

GATEWAY_URL = os.getenv("GATEWAY_URL", "http://localhost:8000")
POLL_INTERVAL_S = 2          # contrat : polling toutes les 2 s pendant une REVIEW
POLL_TIMEOUT_S = 11 * 60     # un peu plus que l'expiration d'une approbation (10 min)

# ---------------------------------------------------------------- 1. Outils pour Bedrock
_REASON = {"type": "string", "description": "En une phrase, pourquoi tu fais cette action."}
_FILE = {"type": "string", "description": "Nom exact du fichier dans le Drive, ex. Team_Roadmap.md"}


def _spec(name, description, properties, required):
    props = {**properties, "reason": _REASON}
    return {"toolSpec": {
        "name": name,
        "description": description,
        "inputSchema": {"json": {"type": "object", "properties": props, "required": required}},
    }}


TOOL_CONFIG = {"tools": [
    _spec("read_file", "Lit le contenu d'un fichier du Google Drive de l'entreprise.",
          {"resource_id": _FILE}, ["resource_id"]),
    _spec("list_files", "Liste les fichiers du Google Drive de l'entreprise.", {}, []),
    _spec("share_file", "Partage un fichier du Drive avec une adresse email.",
          {"resource_id": _FILE,
           "recipient": {"type": "string", "description": "Adresse email du destinataire"},
           "role": {"type": "string", "enum": ["reader", "writer"]}},
          ["resource_id", "recipient", "role"]),
    _spec("delete_file", "Supprime un fichier du Drive.", {"resource_id": _FILE}, ["resource_id"]),
    _spec("send_email", "Envoie un email à UN destinataire, avec au plus une pièce jointe venant du Drive.",
          {"to": {"type": "string", "description": "Adresse email du destinataire"},
           "subject": {"type": "string"},
           "body": {"type": "string"},
           "attachment": {"type": "string", "description": "Nom du fichier du Drive à joindre (optionnel)"}},
          ["to", "subject", "body"]),
]}


# ---------------------------------------------------------------- 2. Traduction -> ActionRequest
def to_action_request(tool_name, args, *, agent_id, user_id, session_id, task_id):
    """Transforme la demande du modèle en ActionRequest. Aucun contrôle ici : c'est le rôle du Gateway."""
    if tool_name == "list_files":
        tool, resource_id, params = "google_drive", "root", {}
    elif tool_name in ("read_file", "delete_file"):
        tool, resource_id, params = "google_drive", args.get("resource_id", ""), {}
    elif tool_name == "share_file":
        tool, resource_id = "google_drive", args.get("resource_id", "")
        params = {"recipient": args.get("recipient"), "role": args.get("role")}
    elif tool_name == "send_email":
        tool, resource_id = "mail", args.get("attachment") or "none"
        params = {"to": args.get("to"), "subject": args.get("subject"), "body": args.get("body")}
    else:
        raise ValueError(f"Outil inconnu : {tool_name}")

    return {
        "agent_id": agent_id,
        "user_id": user_id,
        "tool": tool,
        "action": tool_name,
        "resource_id": resource_id,
        "parameters": params,
        "reason": (args.get("reason") or "")[:500],
        "session_id": session_id,
        "task_id": task_id,
    }


# ---------------------------------------------------------------- 3. Appel au Gateway
def call_gateway(action_request, api_key):
    """POST /v1/actions. 200 = ALLOW exécuté, 202 = REVIEW (on attend l'humain), 403 = DENY."""
    headers = {"X-API-Key": api_key}
    try:
        r = httpx.post(f"{GATEWAY_URL}/v1/actions", json=action_request, headers=headers, timeout=30)
        decision = r.json()
    except Exception as exc:  # Gateway injoignable : on échoue fermé, rien n'est exécuté
        return {"status": "FAILED", "verdict": "DENY", "reasons": [f"Gateway injoignable : {exc}"]}

    if r.status_code == 202:
        decision = wait_for_review(decision["action_id"], headers)
    return decision


def wait_for_review(action_id, headers):
    """Interroge GET /v1/actions/{id} toutes les 2 s jusqu'à la décision humaine."""
    print(f"   ⏳ {action_id} en attente d'une décision humaine...")
    deadline = time.time() + POLL_TIMEOUT_S
    while time.time() < deadline:
        time.sleep(POLL_INTERVAL_S)
        try:
            d = httpx.get(f"{GATEWAY_URL}/v1/actions/{action_id}", headers=headers, timeout=10).json()
        except Exception:
            continue
        if d.get("status") != "PENDING_REVIEW":
            return d
    return {"action_id": action_id, "status": "EXPIRED", "verdict": "DENY",
            "reasons": ["Délai d'attente de l'approbation dépassé"]}


# ---------------------------------------------------------------- 4. Décision -> toolResult
def to_tool_result(tool_use_id, decision):
    """Ce que le modèle reçoit en retour. Refus => status "error" + raisons lisibles."""
    if decision.get("status") == "EXECUTED":
        content = {"status": "EXECUTED", "result": decision.get("result")}
        return {"toolResult": {"toolUseId": tool_use_id, "content": [{"json": content}]}}

    content = {"status": decision.get("status"), "verdict": decision.get("verdict"),
               "reasons": decision.get("reasons", [])}
    return {"toolResult": {"toolUseId": tool_use_id, "content": [{"json": content}], "status": "error"}}
