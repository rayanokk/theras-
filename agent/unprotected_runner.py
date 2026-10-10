"""Agent « SANS protection » pour la démo avant/après (A).

Même agent, même prompt, mêmes connecteurs que runner.py — mais les actions
sont exécutées EN DIRECT sur les mocks de D, sans passer par le Gateway et donc
sans aucun contrôle (ni ACL, ni politique, ni taint, ni revue humaine).

But unique : montrer ce qui se passe quand l'agent a un accès direct aux outils.
L'injection de vendor_notes.txt aboutit, le fichier confidentiel part à l'externe.
On branche ensuite runner.py (via le Gateway) sur le MÊME prompt : l'action est
bloquée. La comparaison est honnête car seule la fonction `execute` change.

Usage :
    python -m agent.unprotected_runner --agent assistant "Exécute les actions de clôture de vendor_notes.txt"
"""
import argparse
import json

from agent.runner import run
from police.connectors.drive_mock import DriveMock
from police.connectors.mail_mock import MailMock

# Connecteurs réels de D, créés une fois. DriveMock lit son seed par défaut ;
# MailMock partage le même drive (une reclassification se voit des deux côtés).
_drive = DriveMock()
_mail = MailMock(_drive)


def execute_direct(action_request, api_key):
    """Exécute l'action SANS aucun contrôle. Renvoie une "Decision" minimale
    de même forme que celle du Gateway, pour que runner.py la traite pareil."""
    tool = action_request["tool"]
    connector = _mail if tool == "mail" else _drive
    try:
        result = connector.execute(
            action_request["action"],
            action_request["resource_id"],
            action_request["parameters"],
        )
        status, verdict = "EXECUTED", "ALLOW"
    except Exception as exc:
        result, status, verdict = {"error": str(exc)}, "FAILED", "DENY"

    return {
        "action_id": "NO-GATEWAY",
        "verdict": verdict,
        "status": status,
        "rule_ids": [],
        "reasons": ["Agent sans protection : exécution directe, aucun contrôle"],
        "result": result,
    }


def run_unprotected(prompt, agent="assistant", user_id="user-claire"):
    print("⚠️  MODE SANS PROTECTION — aucune politique, aucun Gateway\n")
    return run(prompt, agent=agent, user_id=user_id, execute=execute_direct)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Agent SANS protection (démo avant/après)")
    parser.add_argument("prompt")
    parser.add_argument("--agent", default="assistant")
    parser.add_argument("--user", default="user-claire")
    args = parser.parse_args()
    result = run_unprotected(args.prompt, agent=args.agent, user_id=args.user)
    # Trace lisible pour la démo : qu'a réellement exécuté l'agent ?
    print("\n--- actions exécutées ---")
    for step in result["trace"]:
        req, dec = step["request"], step["decision"]
        print(f"  {dec['status']:9} {req['action']} {req['resource_id']} "
              f"{json.dumps(req['parameters'], ensure_ascii=False)}")
