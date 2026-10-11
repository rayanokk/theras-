"""Tests de la logique de lecture du benchmark (console/bench_view.py)."""

from pathlib import Path

from console.bench_view import (
    corrections,
    failed_malicious_scenarios,
    load_results,
    metric,
    ratio_parts,
    summarize,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = REPO_ROOT / "bench" / "results" / "EXAMPLE_results.json"


def test_load_results_example_returns_dict():
    data = load_results(EXAMPLE)
    assert isinstance(data, dict)
    assert "scenarios" in data
    assert isinstance(data["scenarios"], list)


def test_load_results_missing_path_returns_none(tmp_path):
    assert load_results(tmp_path / "nope.json") is None


def test_load_results_invalid_json_returns_none(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{ not valid json", encoding="utf-8")
    assert load_results(bad) is None


def test_summarize_counts_match_scenarios():
    data = load_results(EXAMPLE)
    summary = summarize(data)
    assert summary["ok"] + summary["ko"] == summary["total"]
    assert summary["total"] == len(data["scenarios"])


def test_summarize_example_counts():
    # Le fichier d'exemple fourni contient 21 OK / 9 KO sur 30 scénarios
    # (vérifié en comptant les champs "result" du JSON). summarize() lit le
    # fichier tel quel : c'est lui la source de vérité, pas une valeur supposée.
    summary = summarize(load_results(EXAMPLE))
    assert summary["total"] == 30
    assert summary["ok"] == 21
    assert summary["ko"] == 9


def test_summarize_by_category_sums_to_total():
    summary = summarize(load_results(EXAMPLE))
    cat_total = sum(c["total"] for c in summary["by_category"].values())
    cat_ok = sum(c["ok"] for c in summary["by_category"].values())
    cat_ko = sum(c["ko"] for c in summary["by_category"].values())
    assert cat_total == summary["total"]
    assert cat_ok == summary["ok"]
    assert cat_ko == summary["ko"]


def test_summarize_handles_none_and_partial():
    # Jamais de plantage sur None, dict vide, ou scénario partiel.
    assert summarize(None) == {"total": 0, "ok": 0, "ko": 0, "by_category": {}}
    assert summarize({})["total"] == 0
    partial = {"scenarios": [{"id": "X"}, {"categorie": "exfiltration", "result": "OK"}]}
    summary = summarize(partial)
    assert summary["total"] == 2
    assert summary["ok"] == 1
    assert summary["ko"] == 1  # scénario sans result compte comme KO


# --- metric() : metrics[key] puis racine en repli -------------------------

def test_metric_reads_from_metrics_first():
    results = {"metrics": {"effectiveness": {"stopped": 3}}, "effectiveness": "racine"}
    assert metric(results, "effectiveness") == {"stopped": 3}


def test_metric_falls_back_to_root():
    results = {"metrics": {"autre": 1}, "false_positives": 2}
    assert metric(results, "false_positives") == 2


def test_metric_missing_returns_default():
    assert metric({"metrics": {}}, "absent") is None
    assert metric({"metrics": {}}, "absent", "x") == "x"
    assert metric(None, "absent", 0) == 0


# --- ratio_parts() --------------------------------------------------------

def test_ratio_parts_stopped_total():
    parts = ratio_parts({"stopped": 12, "total": 18})
    assert parts == {"num": 12, "total": 18, "pct": 12 / 18}


def test_ratio_parts_exact_total_full():
    parts = ratio_parts({"exact": 30, "total": 30})
    assert parts["pct"] == 1.0


def test_ratio_parts_zero_total_pct_none():
    parts = ratio_parts({"stopped": 0, "total": 0})
    assert parts["pct"] is None


def test_ratio_parts_invalid_returns_none():
    assert ratio_parts(None) is None
    assert ratio_parts({"total": 5}) is None  # pas de numérateur
    assert ratio_parts({"stopped": 3}) is None  # pas de total
    assert ratio_parts("nope") is None


# --- corrections() --------------------------------------------------------

def test_corrections_normalizes_lists_and_strings():
    results = {
        "metrics": {
            "corrections": [
                {"scenario": "S-X", "avant": ["R-REV-01"], "apres": ["R-REV-01", "R-REV-02"], "raison": "oubli"},
                {"scenario": "S-Y", "avant": "ALLOW", "apres": "REVIEW", "raison": "taint"},
            ]
        }
    }
    out = corrections(results)
    assert len(out) == 2
    assert out[0]["avant"] == "R-REV-01"
    assert out[0]["apres"] == "R-REV-01, R-REV-02"
    assert out[1]["avant"] == "ALLOW"
    assert out[1]["raison"] == "taint"


def test_corrections_absent_returns_empty():
    assert corrections({"metrics": {}}) == []
    assert corrections(None) == []
    assert corrections({"metrics": {"corrections": "pasuneliste"}}) == []


# --- failed_malicious_scenarios() -----------------------------------------

def test_failed_malicious_scenarios_from_example():
    # L'exemple contient des étapes où obtenu ≠ attendu (ex. S-INJ-04).
    failed = failed_malicious_scenarios(load_results(EXAMPLE))
    ids = {s["id"] for s in failed}
    assert "S-INJ-04" in ids  # ALLOW obtenu ≠ REVIEW attendu
    for s in failed:
        assert s["steps"]
        for step in s["steps"]:
            assert step["attendu"] != step["obtenu"]


def test_failed_malicious_scenarios_no_scenarios():
    assert failed_malicious_scenarios({"metrics": {}}) == []
    assert failed_malicious_scenarios(None) == []
