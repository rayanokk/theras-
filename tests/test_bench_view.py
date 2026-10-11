"""Tests de la logique de lecture du benchmark (console/bench_view.py)."""

from pathlib import Path

from console.bench_view import load_results, summarize

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
