"""Point d'entrée unique du scoreur de risque (A).

    risk_scorer = make_scorer(use_llm=os.getenv("RISK_LLM_ENABLED") == "true")

renvoie une fonction de la signature du contrat :
    score_action(request, resource, session_tainted) -> RiskSignal

Le pipeline ne sait pas qui a répondu. Ce module ne décide rien : le moteur
applique R-REV-04 (score >= 0.7, ou llm_unavailable sur action sensible).
Garantie : ne lève JAMAIS d'exception vers le pipeline.
"""
from __future__ import annotations

import time
from typing import Callable

from contracts.models import ActionRequest, ResourceInfo, RiskSignal, RiskSource
from police.risk.heuristics import SENSITIVE_ACTIONS
from police.risk.heuristics import score_action as heuristic_score

ScoreFn = Callable[[ActionRequest, ResourceInfo, bool], RiskSignal]


def make_scorer(use_llm: bool, llm_client=None) -> ScoreFn:
    """`llm_client` : injectable pour les tests (sinon BedrockRiskClient réel)."""
    if not use_llm:
        return _heuristics_only

    if llm_client is None:
        try:
            from police.risk.bedrock_risk import BedrockRiskClient
            llm_client = BedrockRiskClient()
        except Exception as exc:  # pas de boto3, pas de région... : on reste fail closed
            llm_client = _BrokenClient(f"client indisponible ({type(exc).__name__})")

    def score_action(request: ActionRequest, resource: ResourceInfo,
                     session_tainted: bool) -> RiskSignal:
        t0 = time.perf_counter()
        h = _safe_heuristics(request, resource, session_tainted)
        h_score = h.score or 0.0

        try:
            llm = llm_client.assess(request, resource, session_tainted)
        except Exception as exc:
            reason = str(exc) or type(exc).__name__
            return RiskSignal(
                score=h_score,
                signals=h.signals + [f"llm_unavailable: {reason[:80]}"],
                source=RiskSource.LLM_UNAVAILABLE,
                summary=h.summary,
                latency_ms=_ms(t0),
            )

        return RiskSignal(
            score=round(max(h_score, llm.score), 3),   # le LLM ne peut que durcir
            signals=h.signals + [f"llm: {s[:200]}" for s in llm.signals],
            source=RiskSource.LLM,
            summary=llm.summary,
            latency_ms=_ms(t0),
        )

    return score_action


def _heuristics_only(request: ActionRequest, resource: ResourceInfo,
                     session_tainted: bool) -> RiskSignal:
    t0 = time.perf_counter()
    h = _safe_heuristics(request, resource, session_tainted)
    return h.model_copy(update={"latency_ms": _ms(t0)})


def _safe_heuristics(request, resource, session_tainted) -> RiskSignal:
    """Heuristiques protégées : si elles plantent, on échoue fermé sur les actions sensibles."""
    try:
        return heuristic_score(request, resource, session_tainted)
    except Exception as exc:
        sensitive = request.action.value in SENSITIVE_ACTIONS
        return RiskSignal(
            score=1.0 if sensitive else 0.0,
            signals=[f"erreur du scoreur heuristique ({type(exc).__name__})"],
            source=RiskSource.HEURISTICS,
            summary="Scoreur en erreur : action sensible traitée comme risquée" if sensitive else None,
            latency_ms=0,
        )


def _ms(t0: float) -> int:
    return int((time.perf_counter() - t0) * 1000)


class _BrokenClient:
    def __init__(self, reason: str):
        self.reason = reason

    def assess(self, *args, **kwargs):
        raise RuntimeError(self.reason)
