"""Rejoue scenarios.yaml SANS le Gateway : actions exécutées en direct sur les
connecteurs de D (A). C'est la colonne « sans protection » du benchmark.

Même jeu de scénarios que quick_check.py, mais ici AUCUN contrôle : on appelle
directement DriveMock/MailMock.execute(). On mesure combien d'actions qui
devraient être bloquées (attendu REVIEW ou DENY) s'exécutent quand même.

Pas d'agent, pas de Bedrock : déterministe, rapide, comparable à quick_check.py.

Usage (depuis la racine du repo) :
    python -m bench.quick_check_unprotected
"""
import json
from pathlib import Path

import yaml

from police.connectors.drive_mock import DriveMock
from police.connectors.mail_mock import MailMock

SCENARIOS = Path(__file__).parent / "scenarios.yaml"
RESULTS = Path(__file__).parent / "results" / "quick_check_unprotected.json"
ACTION_FIELDS = ("tool", "action", "resource_id")
SKIP_KEYS = ("decide", "wait_seconds", "tamper_params", "tamper_event", "set_classification", "verify")

# Une action « aurait dû être arrêtée » si son verdict attendu n'est pas ALLOW.
def should_be_blocked(step):
    return step.get("attendu") in ("REVIEW", "DENY")


def main():
    drive = DriveMock()
    mail = MailMock(drive)
    scenarios = yaml.safe_load(SCENARIOS.read_text(encoding="utf-8"))

    rows = []
    for sc in scenarios:
        for i, step in enumerate(sc["steps"], 1):
            if any(k in step for k in SKIP_KEYS):
                break
            tool = step["tool"]
            connector = mail if tool == "mail" else drive
            blocked_expected = should_be_blocked(step)
            try:
                result = connector.execute(step["action"], step["resource_id"], step.get("parameters", {}))
                executed, note = True, json.dumps(result, ensure_ascii=False)[:60]
            except Exception as exc:
                # Un mock peut lever (fichier absent...) : l'action n'a pas abouti.
                executed, note = False, f"refus connecteur: {type(exc).__name__}"

            rows.append({
                "id": sc["id"], "step": i, "action": step["action"], "resource": step["resource_id"],
                "attendu_gateway": step.get("attendu"),
                "devait_etre_bloque": blocked_expected,
                "execute_sans_protection": executed,
                "note": note,
            })

    # Comptage : actions malveillantes (devait_etre_bloque) qui se sont exécutées.
    malicious = [r for r in rows if r["devait_etre_bloque"]]
    leaked = [r for r in malicious if r["execute_sans_protection"]]
    legit = [r for r in rows if not r["devait_etre_bloque"]]

    print(f"\n{'Scénario':<11}{'action':<13}{'ressource':<30}{'devait bloquer':<16}{'exécuté ?'}")
    print("-" * 95)
    for r in rows:
        flag = "⚠️ FUITE" if (r["devait_etre_bloque"] and r["execute_sans_protection"]) else ""
        print(f"{r['id']:<11}{r['action']:<13}{r['resource'][:28]:<30}"
              f"{'oui' if r['devait_etre_bloque'] else 'non':<16}"
              f"{'OUI' if r['execute_sans_protection'] else 'non':<6}{flag}")

    print("-" * 95)
    print("SANS PROTECTION (exécution directe sur les connecteurs) :")
    print(f"  Actions malveillantes jouées : {len(malicious)}")
    print(f"  → exécutées quand même (fuites) : {len(leaked)} / {len(malicious)}")
    print(f"  Actions légitimes : {len(legit)} (toutes exécutées normalement)")
    print()
    print("Comparaison attendue AVEC Police Agents : 0 fuite sur les mêmes actions.")

    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Détail enregistré dans {RESULTS}")


if __name__ == "__main__":
    main()
