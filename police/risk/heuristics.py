"""Scoreur de risque SANS LLM (A). Produit un RiskSignal ; il ne décide jamais.

Signature appelée par le pipeline de L (objets du contrat) :
    score_action(request: ActionRequest, resource: ResourceInfo, session_tainted: bool) -> RiskSignal

Le seuil (R-REV-04 : score >= 0.7) est appliqué PAR LE MOTEUR, pas ici. Ce module
observe des faits (classification, domaine, taint) et renvoie score + signaux + résumé.
En --no-llm c'est le seul scoreur ; bedrock_risk.py réutilisera ces heuristiques
en repli (source="llm_unavailable") si Haiku échoue.
"""
from __future__ import annotations

import os
import time

import yaml

from contracts.models import ActionRequest, ResourceInfo, RiskSignal, RiskSource

SENSITIVE_ACTIONS = {"share_file", "delete_file", "send_email"}
SENSITIVE_KEYWORDS = ("confidential", "salaries", "salary", "audit", "financ",
                      "customer", "secret", "key", "password", "contract", "rh", "hr")

_POLICIES_PATH = os.getenv("POLICIES_PATH", "policies/policies.yaml")
_domains_cache: dict | None = None


def _domain_lists() -> dict:
    """Lit internal/partner/blocked_domains depuis policies.yaml (repli vide si absent)."""
    global _domains_cache
    if _domains_cache is None:
        try:
            data = yaml.safe_load(open(_POLICIES_PATH, encoding="utf-8")) or {}
            _domains_cache = {
                "internal": set(data.get("internal_domains", [])),
                "partner": set(data.get("partner_domains", [])),
                "blocked": set(data.get("blocked_domains", [])),
            }
        except Exception:
            _domains_cache = {"internal": set(), "partner": set(), "blocked": set()}
    return _domains_cache


def score_action(request: ActionRequest, resource: ResourceInfo,
                 session_tainted: bool) -> RiskSignal:
    t0 = time.perf_counter()
    action = request.action.value
    signals: list[str] = []
    score = 0.0

    if action not in SENSITIVE_ACTIONS:
        return _signal(0.0, signals, t0)

    domain = resource.recipient_domain
    if action in ("share_file", "send_email") and domain:
        d = _domain_lists()
        if domain in d["blocked"]:
            score += 0.6; signals.append(f"destinataire sur domaine bloqué ({domain})")
        elif domain in d["partner"]:
            score += 0.2; signals.append(f"destinataire partenaire ({domain})")
        elif domain not in d["internal"]:
            score += 0.4; signals.append(f"destinataire externe ({domain})")
        # domaine inconnu de toutes les listes : léger surcroît d'incertitude
        known = d["internal"] | d["partner"] | d["blocked"]
        if known and domain not in known:
            score += 0.15; signals.append("domaine destinataire inconnu des politiques")

    classification = resource.classification.value
    if classification in ("confidential", "restricted"):
        score += 0.3; signals.append(f"ressource {classification}")
    hit = next((k for k in SENSITIVE_KEYWORDS if k in request.resource_id.lower()), None)
    if hit:
        score += 0.15; signals.append(f"nom de fichier sensible (« {hit} »)")

    if action == "delete_file":
        score += 0.3; signals.append("action destructrice (suppression)")

    if session_tainted:
        score += 0.3; signals.append("session tainted (document non fiable lu plus tôt)")

    return _signal(min(score, 1.0), signals, t0)


def _signal(score: float, signals: list[str], t0: float) -> RiskSignal:
    return RiskSignal(
        score=round(score, 3),
        signals=signals,
        source=RiskSource.HEURISTICS,
        summary=_summary(score, signals),
        latency_ms=int((time.perf_counter() - t0) * 1000),
    )


def _summary(score: float, signals: list[str]) -> str | None:
    if not signals:
        return None
    niveau = "élevé" if score >= 0.7 else "modéré" if score >= 0.4 else "faible"
    return f"Risque {niveau} : " + " ; ".join(signals)