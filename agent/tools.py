"""Outils de l'agent, construits DEPUIS les schémas de L (contracts/schemas/).

Un outil Bedrock par action (conseil de L) : le LLM remplit mieux un formulaire précis.
Les paramètres de chaque outil viennent de <action>.params.schema.json, donc agent et
Gateway partagent une seule source de vérité. tools.py reconstruit ensuite l'ActionRequest
complète (contrat 1) avant l'appel HTTP.
"""
import copy
import json
import os
import time

import httpx

GATEWAY_URL = os.getenv("GATEWAY_URL", "http://localhost:8000")
SCHEMA_DIR = os.getenv("SCHEMA_DIR", "contracts/schemas")
POLL_INTERVAL_S = 2
POLL_TIMEOUT_S = 11 * 60

# tool Bedrock -> (tool du contrat, action, resource_id implicite ou None si fourni par le modèle)
_ROUTING = {
    "read_file":   ("google_drive", "read_file", None),
    "list_files":  ("google_drive", "list_files", "root"),
    "share_file":  ("google_drive", "share_file", None),
    "delete_file": ("google_drive", "delete_file", None),
    "send_email":  ("mail", "send_email", None),  # resource_id = pièce jointe, géré à part
}
_DESCRIPTIONS = {
    "read_file": "Lit le contenu d'un fichier du Google Drive de l'entreprise.",
    "list_files": "Liste les fichiers du Google Drive de l'entreprise.",
    "share_file": "Partage un fichier du Drive avec une adresse email.",
    "delete_file": "Supprime un fichier du Drive.",
    "send_email": "Envoie un email à un destinataire, avec une pièce jointe optionnelle.",
}
# Actions dont le modèle doit fournir le nom de fichier visé
_NEEDS_RESOURCE = {"read_file", "share_file", "delete_file"}


def _resolve_refs(schema):
    """Aplatit $ref/$defs en place : Bedrock refuse les références internes (#/$defs/...)."""
    schema = copy.deepcopy(schema)
    defs = schema.get("$defs", {})

    def walk(node):
        if isinstance(node, dict):
            ref = node.get("$ref")
            if isinstance(ref, str) and ref.startswith("#/$defs/"):
                target = defs.get(ref.split("/")[-1], {})
                merged = {**walk(copy.deepcopy(target)), **{k: v for k, v in node.items() if k != "$ref"}}
                return merged
            return {k: walk(v) for k, v in node.items()}
        if isinstance(node, list):
            return [walk(x) for x in node]
        return node

    flat = walk(schema)
    flat.pop("$defs", None)
    flat.pop("$schema", None)
    return flat


def _load_params(action):
    path = os.path.join(SCHEMA_DIR, f"{action}.params.schema.json")
    if os.path.isfile(path):
        return _resolve_refs(json.load(open(path, encoding="utf-8")))
    return {"type": "object", "properties": {}}


def _build_tool_config():
    tools = []
    for action in _ROUTING:
        params = _load_params(action)
        props = dict(params.get("properties", {}))
        required = list(params.get("required", []))
        # champs que le modèle fournit EN PLUS des parameters :
        if action in _NEEDS_RESOURCE:
            props["resource_id"] = {"type": "string", "description": "Nom exact du fichier, ex. Team_Roadmap.md"}
            required = ["resource_id"] + required
        if action == "send_email":
            props["attachment"] = {"type": "string", "description": "Nom du fichier du Drive à joindre (optionnel)"}
        props["reason"] = {"type": "string", "description": "En une phrase, pourquoi tu fais cette action."}
        tools.append({"toolSpec": {
            "name": action,
            "description": _DESCRIPTIONS.get(action, action),
            "inputSchema": {"json": {"type": "object", "properties": props, "required": required}},
        }})
    return {"tools": tools}


TOOL_CONFIG = _build_tool_config()


def to_action_request(tool_name, args, *, agent_id, user_id, session_id, task_id):
    """Reconstruit l'ActionRequest complète (contrat 1) à partir des champs du modèle."""
    tool, action, fixed_resource = _ROUTING[tool_name]
    args = dict(args)
    reason = (args.pop("reason", "") or "")[:500]

    if action == "send_email":
        resource_id = args.pop("attachment", None) or "none"
        params = {k: args.get(k) for k in ("to", "subject", "body")}
    else:
        if fixed_resource is not None:
            resource_id = fixed_resource
        else:
            resource_id = args.pop("resource_id", "")
        args.pop("resource_id", None)
        params = args  # ce qui reste = les parameters du contrat (recipient/role, ou rien)

    return {"agent_id": agent_id, "user_id": user_id, "tool": tool, "action": action,
            "resource_id": resource_id, "parameters": params, "reason": reason,
            "session_id": session_id, "task_id": task_id}


def call_gateway(action_request, api_key):
    headers = {"X-API-Key": api_key}
    try:
        r = httpx.post(f"{GATEWAY_URL}/v1/actions", json=action_request, headers=headers, timeout=30)
        decision = r.json()
    except Exception as exc:
        return {"status": "FAILED", "verdict": "DENY", "reasons": [f"Gateway injoignable : {exc}"]}
    if r.status_code == 202:
        decision = wait_for_review(decision["action_id"], headers)
    return decision


def wait_for_review(action_id, headers):
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
            "reasons": ["Délai d'attente dépassé"]}


def to_tool_result(tool_use_id, decision):
    if decision.get("status") == "EXECUTED":
        content = {"status": "EXECUTED", "result": decision.get("result")}
        return {"toolResult": {"toolUseId": tool_use_id, "content": [{"json": content}]}}
    content = {"status": decision.get("status"), "verdict": decision.get("verdict"),
               "reasons": decision.get("reasons", [])}
    return {"toolResult": {"toolUseId": tool_use_id, "content": [{"json": content}], "status": "error"}}
