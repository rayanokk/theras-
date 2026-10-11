"""Oracle déterministe (Forge — A) : calcule le verdict attendu d'un cas, SANS LLM.

Principe : l'oracle ne réimplémente PAS la logique de décision. Il calcule les
FAITS que le moteur attend (à partir de datagen/faits.py), puis appelle le vrai
moteur de L (police.policy.engine.evaluate). L'oracle et le Gateway donnent donc
toujours le même verdict — c'est ce qui rend le benchmark généré crédible.

Le LLM n'intervient jamais ici. L'oracle est la source de vérité des verdicts
attendus ; le LLM ne fait qu'habiller le contenu (autre module).

Usage :
    o = Oracle()                      # charge policies.yaml + heuristiques
    verdict, rules = o.verdict(agent="agent-assistant", action="share_file",
                               resource_id="Customer_List.csv",
                               recipient_domain="external.example",
                               session_tainted=False, agent_tainted=False)
"""
from __future__ import annotations

import os

from police.policy.engine import evaluate, load_policy, recipient_facts

from datagen import faits


class Oracle:
    def __init__(self, policies_path: str | None = None, use_risk: bool = False):
        self.policy = load_policy(policies_path or os.getenv("POLICIES_PATH", "policies/policies.yaml"))
        self.use_risk = use_risk   # True = calcule risk_score via heuristiques (mode LLM/risk)

    # -------------------------------------------------- calcul des faits d'un cas
    def _facts(self, *, agent, action, resource_id, recipient_domain,
               session_tainted, agent_tainted, params_valid=True,
               identity_ok=True) -> dict:
        tool = faits.ACTION_TOOL.get(action)
        f = faits.fichier(resource_id)

        # resource_ok : le fichier existe ET l'agent est dans son ACL.
        # Cas particuliers : "root" (list_files) et "none" (mail sans PJ) sont OK.
        if resource_id in ("root", "none"):
            resource_ok = True
            classification = "none"
        elif f is None:
            resource_ok = False
            classification = "none"
        else:
            resource_ok = agent in f["acl"]
            classification = f["classification"]

        sensitive = action in faits.SENSITIVE_ACTIONS
        has_recipient = action in ("share_file", "send_email") and recipient_domain is not None
        rf = recipient_facts(recipient_domain, self.policy) if has_recipient else {
            "recipient_internal": False, "recipient_partner": False, "recipient_blocked": False}

        # Faits toujours présents (identité, validité des paramètres).
        facts = {
            "identity_ok": identity_ok,
            "params_valid": params_valid,
            "action": action,
            "sensitive": sensitive,
            "session_tainted": session_tainted,
            "agent_tainted": agent_tainted,
        }
        # Comme le Gateway (correction de L) : si l'identité est invalide ou les paramètres
        # malformés, on NE calcule PAS les faits en aval. Absents = règles R-DENY-02/03 non
        # déclenchées (un fait absent rend la condition fausse). Évite les règles parasites.
        if identity_ok and params_valid:
            facts.update({
                "action_allowed": faits.agent_peut(agent, tool, action) if tool else False,
                "resource_ok": resource_ok,
                "classification": classification,
                "has_recipient": has_recipient,
                **rf,
            })

        # Risque (R-REV-04) : seulement en mode use_risk, via les heuristiques.
        if self.use_risk:
            facts.update(self._risk_facts(facts, resource_id, recipient_domain))
        return facts

    def _risk_facts(self, facts, resource_id, recipient_domain) -> dict:
        """Score heuristique, pour reproduire R-REV-04. Réutilise le scoreur du projet."""
        try:
            from contracts.models import ActionRequest, ResourceInfo
            from police.risk.heuristics import score_action
            req = ActionRequest(
                tool=faits.ACTION_TOOL.get(facts["action"], "google_drive"),
                action=facts["action"], resource_id=resource_id,
                parameters={}, session_id="oracle", task_id="oracle")
            res = ResourceInfo(exists=True, classification=facts["classification"],
                               trusted=True, recipient_domain=recipient_domain)
            sig = score_action(req, res, facts["session_tainted"] or facts["agent_tainted"])
            return {"risk_score": sig.score or 0.0, "risk_unavailable": False}
        except Exception:
            # Si le scoreur échoue, on reste fail-safe : pas de score, pas de R-REV-04 par score.
            return {"risk_unavailable": False}

    # ------------------------------------------------------------------- verdict
    def verdict(self, *, agent, action, resource_id="none", recipient_domain=None,
            session_tainted=False, agent_tainted=False, params_valid=True,
            identity_ok=True) -> tuple[str, list[str], list[str]]:
        """Calcule le verdict. Renvoie (verdict, rule_ids, regles_no_llm)."""
        facts = self._facts(
            agent=agent, action=action, resource_id=resource_id,
            recipient_domain=recipient_domain, session_tainted=session_tainted,
            agent_tainted=agent_tainted, params_valid=params_valid,
            identity_ok=identity_ok
        )
        verdict, rule_ids, _reasons = evaluate(facts, self.policy)
        
        # R-REV-04 est un durcissement heuristique (stage: harden dans policies.yaml)
        # On le sépare dans regles_no_llm pour le benchmark --mode no-llm
        regles_base = [r for r in rule_ids if r != "R-REV-04"]
        regles_no_llm = ["R-REV-04"] if "R-REV-04" in rule_ids else []
        
        return verdict, regles_base, regles_no_llm


def domain_of(email_or_domain: str | None) -> str | None:
    """Extrait le domaine d'un email ('x@a.b' -> 'a.b'), ou renvoie tel quel si déjà un domaine."""
    if not email_or_domain:
        return None
    return email_or_domain.split("@")[-1].lower()
