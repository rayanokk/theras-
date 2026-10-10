"""Moteur de politique : lit policies/policies.yaml et decide a partir de faits.

Aucun LLM ici, aucun acces reseau, base ou connecteur : des fonctions pures.
La decision suit l'ordre de contracts.md (partie 3) et le commentaire en tete de
policies.yaml :

    1. stage: deny    -> une regle vraie suffit : DENY
    2. stage: review  -> une regle vraie suffit : REVIEW
    3. stage: allow   -> une regle vraie suffit : ALLOW ; aucune : DEFAULT-DENY
    4. stage: harden  -> seulement si le verdict n'est pas DENY ; un ALLOW devient
                         REVIEW, un REVIEW reste REVIEW avec la raison ajoutee.

Dans chaque etape, TOUTES les regles vraies sont listees dans rule_ids / reasons.

Formes de condition dans `when` :
    fait: valeur          egalite exacte
    fait_in: [liste]      le fait est dans la liste
    fait_gte: nombre      le fait est >= au nombre
    any_of: [ {...}, ...] au moins un groupe de conditions est vrai
Un fait absent ou None rend la condition fausse, sans exception.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

VERDICT_DENY = "DENY"
VERDICT_REVIEW = "REVIEW"
VERDICT_ALLOW = "ALLOW"
DEFAULT_DENY_ID = "DEFAULT-DENY"


@dataclass
class Policy:
    version: str
    internal_domains: list[str]
    partner_domains: list[str]
    blocked_domains: list[str]
    rules: list[dict[str, Any]] = field(default_factory=list)


def load_policy(path: str | Path) -> Policy:
    """Charge policies.yaml (yaml.safe_load uniquement) en objet Policy."""
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return Policy(
        version=raw.get("policy_version", ""),
        internal_domains=[d.lower() for d in raw.get("internal_domains", [])],
        partner_domains=[d.lower() for d in raw.get("partner_domains", [])],
        blocked_domains=[d.lower() for d in raw.get("blocked_domains", [])],
        rules=raw.get("rules", []),
    )


def _condition_true(key: str, expected: Any, facts: dict[str, Any]) -> bool:
    """Evalue une condition unique. Fait absent ou None -> faux."""
    if key == "any_of":
        # expected est une liste de groupes de conditions ; un groupe vrai suffit.
        return any(matches(group, facts) for group in (expected or []))

    if key.endswith("_in"):
        fact = key[: -len("_in")]
        value = facts.get(fact)
        return value is not None and value in (expected or [])

    if key.endswith("_gte"):
        fact = key[: -len("_gte")]
        value = facts.get(fact)
        if value is None:
            return False
        try:
            return value >= expected
        except TypeError:
            return False

    # Egalite exacte. Un fait absent (None) ne vaut jamais la valeur attendue.
    value = facts.get(key)
    if value is None:
        return False
    return value == expected


def matches(when: dict[str, Any], facts: dict[str, Any]) -> bool:
    """Vrai si TOUTES les conditions de `when` sont vraies."""
    if not when:
        return True
    return all(_condition_true(key, expected, facts) for key, expected in when.items())


def _rules_for_stage(policy: Policy, stage: str) -> list[dict[str, Any]]:
    return [r for r in policy.rules if r.get("stage") == stage]


def _matching(policy: Policy, stage: str, facts: dict[str, Any]):
    """Renvoie (rule_ids, reasons) des regles vraies de l'etape."""
    ids: list[str] = []
    reasons: list[str] = []
    for rule in _rules_for_stage(policy, stage):
        if matches(rule.get("when", {}), facts):
            ids.append(rule["id"])
            reasons.append(rule.get("reason", ""))
    return ids, reasons


def evaluate(
    facts: dict[str, Any], policy: Policy
) -> tuple[str, list[str], list[str]]:
    """Decide le verdict final et renvoie (verdict, rule_ids, reasons)."""
    # 1. DENY : une regle vraie suffit, on s'arrete (les durcisseurs ne jouent pas).
    deny_ids, deny_reasons = _matching(policy, "deny", facts)
    if deny_ids:
        return VERDICT_DENY, deny_ids, deny_reasons

    # 2. REVIEW, puis 3. ALLOW ; aucune ALLOW -> DEFAULT-DENY.
    review_ids, review_reasons = _matching(policy, "review", facts)
    allow_ids, allow_reasons = _matching(policy, "allow", facts)

    if review_ids:
        verdict = VERDICT_REVIEW
        rule_ids = list(review_ids)
        reasons = list(review_reasons)
    elif allow_ids:
        verdict = VERDICT_ALLOW
        rule_ids = list(allow_ids)
        reasons = list(allow_reasons)
    else:
        return VERDICT_DENY, [DEFAULT_DENY_ID], ["Aucune règle n'autorise cette action"]

    # 4. HARDEN : uniquement si le verdict n'est pas DENY. Un ALLOW devient REVIEW ;
    #    un REVIEW reste REVIEW. Dans tous les cas la regle vraie est ajoutee.
    harden_ids, harden_reasons = _matching(policy, "harden", facts)
    if harden_ids:
        verdict = VERDICT_REVIEW
        rule_ids.extend(harden_ids)
        reasons.extend(harden_reasons)

    return verdict, rule_ids, reasons


def recipient_facts(domain: str | None, policy: Policy) -> dict[str, bool]:
    """Classe un domaine destinataire. None -> tout a False.

    Comparaison en minuscules. Un domaine interne n'est ni partenaire ni bloque,
    conformement aux listes de policies.yaml.
    """
    if domain is None:
        return {
            "recipient_internal": False,
            "recipient_partner": False,
            "recipient_blocked": False,
        }
    d = domain.lower()
    return {
        "recipient_internal": d in policy.internal_domains,
        "recipient_partner": d in policy.partner_domains,
        "recipient_blocked": d in policy.blocked_domains,
    }
