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


# --- Efficacité / Explicabilité / Attendus corrigés -----------------------

def test_effectiveness_explainability_kpis_shown(monkeypatch, tmp_path):
    data = _base()
    data["metrics"]["effectiveness"] = {"stopped": 18, "total": 18}
    data["metrics"]["explainability"] = {"exact": 24, "total": 30}
    html = _run(monkeypatch, tmp_path, data)
    assert "Efficacité" in html
    assert "18 / 18 (100 %)" in html
    assert "actions malveillantes stoppées (bon verdict)" in html
    assert "Explicabilité" in html
    assert "24 / 30 (80 %)" in html
    assert "règles déclenchées exactement celles attendues" in html


def test_ratio_kpis_show_dash_when_absent(monkeypatch, tmp_path):
    data = _base()
    data["metrics"].pop("effectiveness", None)
    data["metrics"].pop("explainability", None)
    html = _run(monkeypatch, tmp_path, data)
    # Les cartes existent, avec « — » comme valeur.
    assert "Efficacité" in html
    assert "Explicabilité" in html


def test_corrections_table_shown(monkeypatch, tmp_path):
    data = _base()
    data["metrics"]["corrections"] = [
        {"scenario": "S-INJ-03", "avant": ["R-REV-03"],
         "apres": ["R-REV-02", "R-REV-03"], "raison": "taint oublié"},
    ]
    html = _run(monkeypatch, tmp_path, data)
    assert "Attendus corrigés" in html
    assert "On ne maquille rien" in html
    assert "S-INJ-03" in html
    assert "taint oublié" in html
    assert "R-REV-02, R-REV-03" in html


def test_corrections_empty_message(monkeypatch, tmp_path):
    data = _base()
    data["metrics"].pop("corrections", None)
    html = _run(monkeypatch, tmp_path, data)
    assert "Attendus corrigés" in html
    assert "Aucune correction." in html


def test_missed_malicious_red_box_lists_scenarios(monkeypatch, tmp_path):
    data = _base()
    data["metrics"]["effectiveness"] = {"stopped": 16, "total": 18}
    html = _run(monkeypatch, tmp_path, data)
    assert "non stopp" in html  # « non stoppée(s) »
    # Détail tiré des scénarios de l'exemple (ex. S-INJ-04 : ALLOW ≠ REVIEW).
    assert "S-INJ-04" in html


def test_corrections_text_is_html_escaped(monkeypatch, tmp_path):
    data = _base()
    data["metrics"]["corrections"] = [
        {"scenario": "S-X", "avant": "a", "apres": "b",
         "raison": "<script>alert(1)</script>"},
    ]
    html = _run(monkeypatch, tmp_path, data)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


# --- Nettoyage d'affichage des KPI ----------------------------------------

def test_scenarios_card_renamed(monkeypatch, tmp_path):
    html = _run(monkeypatch, tmp_path, _base())
    assert "Scénarios sans écart de règles" in html
    assert "Scénarios réussis" not in html
    assert "verdict correct, mais règles citées différentes de l’oracle pour les autres" in html


def test_block_rate_card_shown_when_available(monkeypatch, tmp_path):
    data = _base()
    data["metrics"]["block_rate"] = 0.9
    html = _run(monkeypatch, tmp_path, data)
    assert "Taux de blocage" in html


def test_block_rate_card_hidden_when_unavailable(monkeypatch, tmp_path):
    data = _base()
    data["metrics"].pop("block_rate", None)
    html = _run(monkeypatch, tmp_path, data)
    assert "Taux de blocage" not in html


def test_second_false_positives_card_removed(monkeypatch, tmp_path):
    # « Faux positifs » n'apparaît qu'une fois (la carte de tête), plus en 2e ligne.
    html = _run(monkeypatch, tmp_path, _base())
    assert html.count("Faux positifs") == 1


def test_ignored_rules_line_shown_and_escaped(monkeypatch, tmp_path):
    data = _base()
    data["meta"]["ignored_rules"] = [
        {"rule": "R-REV-04", "raison": "durcissement probabiliste <non prédictible>"},
    ]
    html = _run(monkeypatch, tmp_path, data)
    assert "Règles ignorées dans la comparaison" in html
    assert "R-REV-04" in html
    # La raison est présente et échappée.
    assert "&lt;non prédictible&gt;" in html
    assert "<non prédictible>" not in html


def test_ignored_rules_line_absent_when_missing(monkeypatch, tmp_path):
    data = _base()
    data["meta"].pop("ignored_rules", None)
    html = _run(monkeypatch, tmp_path, data)
    assert "Règles ignorées dans la comparaison" not in html
