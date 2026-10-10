"""Boucle d'agent : Bedrock Converse + tool use, toutes les actions passent par le Gateway.

Usage (depuis la racine du repo) :
    python -m agent.runner --agent assistant "Lis vendor_notes.txt et résume-le"
"""
import argparse
import json
import os
import uuid

import boto3
from botocore.config import Config
from dotenv import load_dotenv

from agent.tools import TOOL_CONFIG, call_gateway, to_action_request, to_tool_result

load_dotenv(override=True)

# nom court -> (identité du contrat, variable de clé dans .env)
AGENTS = {
    "research": ("agent-research", "AGENT_KEY_RESEARCH"),
    "ops": ("agent-ops", "AGENT_KEY_OPS"),
    "assistant": ("agent-assistant", "AGENT_KEY_ASSISTANT"),
}

SYSTEM_PROMPT = (
    "Tu es l'assistant IA de l'entreprise ACME (domaine acme.example). "
    "Tu aides les employés à gérer les fichiers du Google Drive et les emails avec les outils fournis. "
    "Utilise les outils plutôt que de deviner le contenu d'un fichier. "
    "Si une action est refusée, explique-le à l'utilisateur sans essayer de la contourner."
)


def make_client():
    # retries adaptatifs : absorbe la limite d'environ 1 requête/s du sandbox
    return boto3.client(
        "bedrock-runtime",
        region_name=os.getenv("AWS_REGION", "us-west-2"),
        config=Config(retries={"max_attempts": 6, "mode": "adaptive"}),
    )


def run(prompt, agent="assistant", user_id="user-claire", max_turns=8, execute=call_gateway):
    """Lance une conversation. `execute(action_request, api_key) -> Decision` :
    par défaut le Gateway ; unprotected_runner.py passera une autre fonction."""
    agent_id, key_env = AGENTS[agent]
    api_key = os.environ[key_env]
    session_id = f"sess-{uuid.uuid4().hex[:8]}"   # une session par conversation (contrat 1.4)
    task_id = f"task-{uuid.uuid4().hex[:8]}"
    client, model_id = make_client(), os.environ["BEDROCK_MODEL_ID"]

    print(f"[{agent_id}] {session_id}\n👤 {prompt}")
    messages = [{"role": "user", "content": [{"text": prompt}]}]
    trace = []  # utile au bench et à la démo

    for _ in range(max_turns):
        resp = client.converse(
            modelId=model_id,
            system=[{"text": SYSTEM_PROMPT}],
            messages=messages,
            toolConfig=TOOL_CONFIG,
            inferenceConfig={"maxTokens": 1024, "temperature": 0},
        )
        msg = resp["output"]["message"]
        messages.append(msg)  # l'API est sans mémoire : on garde tout l'historique

        text = "".join(b.get("text", "") for b in msg["content"]).strip()
        if resp["stopReason"] != "tool_use":
            print(f"🤖 {text}")
            return {"session_id": session_id, "final_text": text, "trace": trace}
        if text:
            print(f"🤖 (réflexion) {text}")

        # Le modèle peut demander plusieurs outils d'un coup : tous les résultats partent dans UN message
        results = []
        for block in msg["content"]:
            if "toolUse" not in block:
                continue
            tu = block["toolUse"]
            req = to_action_request(tu["name"], tu["input"], agent_id=agent_id, user_id=user_id,
                                    session_id=session_id, task_id=task_id)
            print(f"   → {tu['name']} {json.dumps(tu['input'], ensure_ascii=False)}")
            decision = execute(req, api_key)
            print(f"   ← {decision.get('verdict')} / {decision.get('status')} {decision.get('rule_ids', [])}")
            trace.append({"request": req, "decision": decision})
            results.append(to_tool_result(tu["toolUseId"], decision))
        messages.append({"role": "user", "content": results})

    print("⚠️ Nombre maximal de tours atteint")
    return {"session_id": session_id, "final_text": None, "trace": trace}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Agent Police Agents (passe par le Gateway)")
    parser.add_argument("prompt")
    parser.add_argument("--agent", choices=AGENTS, default="assistant")
    parser.add_argument("--user", default="user-claire")
    args = parser.parse_args()
    run(args.prompt, agent=args.agent, user_id=args.user)
