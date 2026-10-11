"""Critère de fin du bloc 1 : l'oracle reproduit les verdicts des 30 scénarios manuels.

Charge bench/scenarios.yaml, rejoue chaque ÉTAPE d'action à travers l'oracle en
suivant le taint, et compare verdict + règles à l'attendu du scénario.

Si l'oracle diverge, c'est l'ORACLE qu'on corrige, jamais les scénarios.
"""
import os
from pathlib import Path

import pytest
import yaml

from datagen.oracle import Oracle, domain_of
from datagen import faits

SCENARIOS = Path(os.getenv("SCENARIOS_PATH", "bench/scenarios.yaml"))
# étapes non gérées par l'oracle (approbations, falsification, état interne)
SKIP = ("decide", "wait_seconds", "tamper_params", "tamper_event", "set_classification", "verify")


def _load():
    return yaml.safe_load(SCENARIOS.read_text(encoding="utf-8"))


def _recipient(step):
    p = step.get("parameters", {})
    return domain_of(p.get("recipient") or p.get("to"))


@pytest.mark.parametrize("use_risk", [False, True], ids=["no-risk", "risk"])
def test_oracle_reproduit_les_scenarios(use_risk):
    oracle = Oracle(use_risk=use_risk)
    scenarios = _load()
    erreurs = []

    for sc in scenarios:
        agent = sc.get("agent")
        session_tainted = False
        agent_tainted = False
        for i, step in enumerate(sc["steps"], 1):
            if any(k in step for k in SKIP) or "action" not in step:
                continue
            action = step["action"]
            resource = step["resource_id"]

            # usurpation : agent_id déclaré != agent réel, ou clé inconnue
            identity_ok = not (step.get("agent_id") and step["agent_id"] != agent) \
                          and not sc.get("api_key")
            # paramètres invalides : champ en trop, ou resource_id hors regex (contournement)
            params_valid = "parameters" not in step or "skip_policy" not in step.get("parameters", {})
            if any(c in str(resource) for c in ("/", "..")):
                params_valid = False

            v, rules = oracle.verdict(
                agent=agent, action=action, resource_id=resource,
                recipient_domain=_recipient(step),
                session_tainted=session_tainted, agent_tainted=agent_tainted,
                params_valid=params_valid, identity_ok=identity_ok)

            # attendus du scénario
            exp_v = step.get("attendu")
            exp_rules = list(step.get("regles", []))
            # regles_no_llm (R-REV-04) = durcissement heuristique : présent seulement
            # quand l'oracle calcule le score, c.-à-d. en mode use_risk.
            if use_risk:
                exp_rules += step.get("regles_no_llm", [])
            # en no-risk, l'oracle ne produit jamais R-REV-04 ; on le retire des deux côtés.
            cmp_rules = rules if use_risk else [r for r in rules if r != "R-REV-04"]
            exp_cmp = exp_rules if use_risk else [r for r in exp_rules if r != "R-REV-04"]

            if exp_v and v != exp_v:
                erreurs.append(f"{sc['id']} ét.{i}: verdict {v}≠{exp_v}")
            if exp_cmp and sorted(cmp_rules) != sorted(exp_cmp):
                erreurs.append(f"{sc['id']} ét.{i}: règles {sorted(cmp_rules)}≠{sorted(exp_cmp)}")

            # mise à jour du taint : lecture d'un fichier non fiable -> session ET agent tainted
            f = faits.fichier(resource)
            if action == "read_file" and f and not f["trusted"]:
                session_tainted = True
                agent_tainted = True

    assert not erreurs, "Divergences oracle vs scénarios :\n" + "\n".join(erreurs)
