"""Tests du scoreur (A) : vérifie chaque règle de L, sans appeler Bedrock."""
import pytest

from contracts.models import ActionRequest, ResourceInfo, RiskSource
from police.risk.bedrock_risk import LLMRiskAssessment, LLMRiskError, _parse
from police.risk.scorer import make_scorer


def _req(action="share_file", rid="Confidential_Audit_Report.pdf", params=None):
    tool = "mail" if action == "send_email" else "google_drive"
    if params is None:
        params = {"recipient": "x@external.example", "role": "reader"} if action == "share_file" else {}
    return ActionRequest(tool=tool, action=action, resource_id=rid, parameters=params,
                         session_id="s", task_id="t")


def _res(cls="confidential", domain="external.example"):
    return ResourceInfo(exists=True, classification=cls, trusted=True, recipient_domain=domain)


class FakeLLM:
    def __init__(self, score=None, error=None):
        self.score, self.error = score, error

    def assess(self, *args):
        if self.error:
            raise self.error
        return LLMRiskAssessment(score=self.score, signals=["avis du faux LLM"], summary="résumé IA")


def test_no_llm_source_heuristics():
    r = make_scorer(use_llm=False)(_req(), _res(), True)
    assert r.source == RiskSource.HEURISTICS
    assert 0 <= r.score <= 1


def test_llm_ne_peut_pas_adoucir():
    # heuristique élevée, LLM qui dit "aucun risque" : le max garde l'heuristique
    h = make_scorer(use_llm=False)(_req(), _res(), True).score
    r = make_scorer(use_llm=True, llm_client=FakeLLM(score=0.0))(_req(), _res(), True)
    assert r.source == RiskSource.LLM
    assert r.score == h


def test_llm_peut_durcir():
    # partage interne légitime (heuristique 0), LLM inquiet : le score monte
    req = _req(rid="Team_Roadmap.md", params={"recipient": "x@acme.example", "role": "reader"})
    r = make_scorer(use_llm=True, llm_client=FakeLLM(score=0.9))(req, _res("internal", "acme.example"), False)
    assert r.score == 0.9
    assert any(s.startswith("llm:") for s in r.signals)


def test_echec_llm_bascule_llm_unavailable():
    h = make_scorer(use_llm=False)(_req(), _res(), False)
    r = make_scorer(use_llm=True, llm_client=FakeLLM(error=LLMRiskError("timeout")))(_req(), _res(), False)
    assert r.source == RiskSource.LLM_UNAVAILABLE
    assert r.score == h.score
    assert r.signals[-1] == "llm_unavailable: timeout"


def test_jamais_d_exception_vers_le_pipeline():
    r = make_scorer(use_llm=True, llm_client=FakeLLM(error=RuntimeError("boom")))(_req(), _res(), False)
    assert r.source == RiskSource.LLM_UNAVAILABLE


@pytest.mark.parametrize("text", ["pas de json", '{"score": 2}', '{"score": "abc", "summary": "x"}'])
def test_json_invalide_rejete(text):
    with pytest.raises(LLMRiskError):
        _parse(text)


def test_json_entoure_de_balises_accepte():
    out = _parse('```json\n{"score": 0.4, "signals": ["a"], "summary": "ok"}\n```')
    assert out.score == 0.4
