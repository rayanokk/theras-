"""Critère de fin du bloc 1 : l'oracle reproduit les verdicts DÉTERMINISTES des 30 scénarios.

Charge bench/scenarios.yaml, rejoue chaque étape d'action à travers l'oracle en
suivant le taint, et compare verdict + règles à l'attendu.

IMPORTANT — R-REV-04 n'est PAS vérifié ici. C'est un durcissement issu du score de
risque (heuristiques + Haiku), par nature probabiliste : l'oracle ne peut pas le
prédire de façon fiable, et le vrai Gateway ne le déclenche pas toujours là où les
heuristiques seules le feraient. L'oracle garantit donc les verdicts déterministes
(DENY, REVIEW par règle, ALLOW, taint) ; R-REV-04 est exclu de la comparaison.

Si l'oracle diverge sur le reste, c'est l'ORACLE qu'on corrige, jamais les scénarios.
"""
import os
from pathlib import Path

import yaml

from datagen.oracle import Oracle, domain_of
from datagen import faits

SCENARIOS = Path(os.getenv("SCENARIOS_PATH", "bench/scenarios.yaml"))
SKIP = ("decide", "wait_seconds", "tamper_params", "tamper_event", "set_classification", "verify")


def _load():
    return yaml.safe_load(SCENARIOS.read_text(encoding="utf-8"))


def _recipient(step):
    p = step.get("parameters", {})
    return domain_of(p.get("recipient") or p.get("to"))


def test_oracle_reproduit_les_scenarios():
    # Oracle en mode déterministe : pas de score de risque, donc pas de R-REV-04.
    oracle = Oracle(use_risk=False)
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

            identity_ok = not (step.get("agent_id") and step["agent_id"] != agent) \
                          and not sc.get("api_key")
            params_valid = "parameters" not in step or "skip_policy" not in step.get("parameters", {})
            if any(c in str(resource) for c in ("/", "..")):
                params_valid = False

            v, rules_base, _rules_no_llm = oracle.verdict(
                agent=agent, action=action, resource_id=resource,
                recipient_domain=_recipient(step),
                session_tainted=session_tainted, agent_tainted=agent_tainted,
                params_valid=params_valid, identity_ok=identity_ok)

            # On compare les verdicts déterministes, R-REV-04 exclu des deux côtés.
            exp_v = step.get("attendu")
            exp = sorted(r for r in step.get("regles", []) if r != "R-REV-04")
            got = sorted(r for r in rules_base if r != "R-REV-04")

            if exp_v and v != exp_v:
                erreurs.append(f"{sc['id']} ét.{i}: verdict {v}≠{exp_v}")
            if exp and got != exp:
                erreurs.append(f"{sc['id']} ét.{i}: règles {got}≠{exp}")

            f = faits.fichier(resource)
            if action == "read_file" and f and not f["trusted"]:
                session_tainted = True
                agent_tainted = True

    assert not erreurs, "Divergences oracle vs scénarios :\n" + "\n".join(erreurs)