"""Tests de rendu de la page Benchmark (console/pages/4_Benchmark.py).

On vérifie les champs optionnels (action_status, durcissements LLM, mesures
inconnues) : présents quand ils existent, absents sans jamais planter."""

import json
from pathlib import Path

import pytest

from streamlit.testing.v1 import AppTest

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = REPO_ROOT / "bench" / "results" / "EXAMPLE_results.json"
PAGE = str(REPO_ROOT / "console" / "pages" / "4_Benchmark.py")


def _base() -> dict:
    return json.loads(EXAMPLE.read_text(encoding="utf-8"))


def _run(monkeypatch, tmp_path, data) -> str:
    path = tmp_path / "results.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    monkeypatch.setenv("BENCH_RESULTS_PATH", str(path))
    at = AppTest.from_file(PAGE, default_timeout=60)
    at.run()
    assert not at.exception, [e.value for e in at.exception]
    return "\n".join(m.value for m in at.markdown)


def test_llm_hardenings_kpi_shown_when_present(monkeypatch, tmp_path):
    data = _base()
    data["metrics"]["llm_hardenings"] = 4
    html = _run(monkeypatch, tmp_path, data)
    assert "Durcissements par l\u2019IA" in html
    assert "scoreur de risque" in html
    assert ">4<" in html or "4" in html


def test_llm_hardenings_kpi_absent_when_missing(monkeypatch, tmp_path):
    html = _run(monkeypatch, tmp_path, _base())
    assert "Durcissements par l\u2019IA" not in html


def test_unknown_metrics_shown_in_other_measures(monkeypatch, tmp_path):
    data = _base()
    data["metrics"]["weird_new_metric"] = 42
    data["metrics"]["taux_bidon"] = 0.5
    html = _run(monkeypatch, tmp_path, data)
    assert "Autres mesures" in html
    assert "weird_new_metric" in html and "42" in html
    assert "taux_bidon" in html
    # Les mesures déjà présentées en KPI ne doivent pas réapparaître ici.
    after = html.split("Autres mesures", 1)[1]
    assert "malicious_total" not in after
    assert "latency_ms" not in after


def test_no_other_measures_section_when_all_known(monkeypatch, tmp_path):
    html = _run(monkeypatch, tmp_path, _base())
    assert "Autres mesures" not in html


def test_decide_step_shows_action_status_badge(monkeypatch, tmp_path):
    data = _base()
    for scenario in data["scenarios"]:
        if scenario["id"] == "S-APP-03":
            scenario["steps"][1]["action_status"] = "EXECUTED"
    html = _run(monkeypatch, tmp_path, data)
    assert "Statut de l\u2019action" in html
    assert "Exécutée" in html  # EXECUTED traduit par status_badge


def test_page_survives_missing_metrics(monkeypatch, tmp_path):
    # metrics vide : aucun KPI optionnel, aucune section Autres mesures, pas de crash.
    data = _base()
    data["metrics"] = {}
    html = _run(monkeypatch, tmp_path, data)
    assert "Durcissements par l\u2019IA" not in html
    assert "Autres mesures" not in html
    assert "30 attaques rejou" in html


# --- Ordre de priorité de la source --------------------------------------

def _run_env(monkeypatch, env_path) -> tuple[AppTest, str]:
    """Lance la page avec BENCH_RESULTS_PATH = env_path (fichier éventuellement absent).

    Chaque fichier de résultats écrit porte un marqueur `_source` dans une mesure
    inconnue, pour reconnaître lequel la page a chargé via « Autres mesures »."""
    monkeypatch.setenv("BENCH_RESULTS_PATH", str(env_path))
    at = AppTest.from_file(PAGE, default_timeout=60)
    at.run()
    assert not at.exception, [e.value for e in at.exception]
    return at, "\n".join(m.value for m in at.markdown)


def _write_tagged(path: Path, tag: str) -> None:
    data = _base()
    data["metrics"]["source_tag"] = tag
    path.write_text(json.dumps(data), encoding="utf-8")


def _loaded_tag(html: str) -> str | None:
    """Récupère le marqueur du fichier réellement chargé (via Autres mesures)."""
    for tag in ("ENV", "DEFAULT", "NOLLM", "LLM"):
        # Le tag est une valeur de mesure inconnue : il n'apparaît que s'il est chargé.
        if f">{tag}<" in html:
            return tag
    return None


def test_env_path_has_top_priority(monkeypatch, tmp_path):
    env_file = tmp_path / "chosen.json"
    _write_tagged(env_file, "ENV")
    _write_tagged(tmp_path / "results.json", "DEFAULT")
    _write_tagged(tmp_path / "results_no-llm.json", "NOLLM")
    _write_tagged(tmp_path / "results_llm.json", "LLM")
    _, html = _run_env(monkeypatch, env_file)
    assert _loaded_tag(html) == "ENV"


def test_results_json_used_when_env_path_missing(monkeypatch, tmp_path):
    # La variable pointe un fichier absent : on retombe sur results.json du dossier.
    _write_tagged(tmp_path / "results.json", "DEFAULT")
    _write_tagged(tmp_path / "results_no-llm.json", "NOLLM")
    _write_tagged(tmp_path / "results_llm.json", "LLM")
    _, html = _run_env(monkeypatch, tmp_path / "absent.json")
    assert _loaded_tag(html) == "DEFAULT"


def test_mode_selector_when_both_llm_files_exist(monkeypatch, tmp_path):
    # Pas de results.json : les deux fichiers run_bench.py activent le sélecteur.
    _write_tagged(tmp_path / "results_no-llm.json", "NOLLM")
    _write_tagged(tmp_path / "results_llm.json", "LLM")
    at, html = _run_env(monkeypatch, tmp_path / "absent.json")
    assert len(at.radio) == 1
    assert at.radio[0].options == ["sans LLM", "avec LLM"]
    # Par défaut le premier choix (sans LLM) est sélectionné.
    assert _loaded_tag(html) == "NOLLM"


def test_single_llm_file_used_without_selector(monkeypatch, tmp_path):
    _write_tagged(tmp_path / "results_llm.json", "LLM")
    at, html = _run_env(monkeypatch, tmp_path / "absent.json")
    assert len(at.radio) == 0  # pas de sélecteur si un seul fichier
    assert _loaded_tag(html) == "LLM"


def test_falls_back_to_example_when_nothing_present(monkeypatch, tmp_path):
    # Dossier vide, aucun fichier reconnu : repli sur l'exemple + bandeau ambre.
    _, html = _run_env(monkeypatch, tmp_path / "absent.json")
    assert "Donn\u00e9es d\u2019exemple" in html
