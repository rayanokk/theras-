"""Logique de lecture des résultats de benchmark, sans Streamlit.

Tout est lu défensivement (.get(), valeurs par défaut) : un fichier partiel ou
un champ manquant ne doit jamais faire planter la page qui s'appuie dessus.
"""

from __future__ import annotations

import json
from pathlib import Path


def load_results(path) -> dict | None:
    """Charge un fichier de résultats JSON.

    Renvoie le dict chargé, ou None si le fichier est absent, illisible ou
    n'est pas un objet JSON."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    return data


def summarize(results) -> dict:
    """Compte les OK/KO, au total et par catégorie.

    Renvoie :
      {
        "total": int, "ok": int, "ko": int,
        "by_category": {categorie: {"ok": int, "ko": int, "total": int}},
      }
    Tolère un `results` None, sans clé `scenarios`, ou avec des scénarios
    partiels (catégorie ou result manquants)."""
    scenarios = []
    if isinstance(results, dict):
        raw = results.get("scenarios")
        if isinstance(raw, list):
            scenarios = raw

    total = ok = ko = 0
    by_category: dict[str, dict] = {}

    for scenario in scenarios:
        if not isinstance(scenario, dict):
            continue
        total += 1
        category = scenario.get("categorie") or "inconnu"
        is_ok = str(scenario.get("result", "")).upper() == "OK"

        bucket = by_category.setdefault(category, {"ok": 0, "ko": 0, "total": 0})
        bucket["total"] += 1
        if is_ok:
            ok += 1
            bucket["ok"] += 1
        else:
            ko += 1
            bucket["ko"] += 1

    return {"total": total, "ok": ok, "ko": ko, "by_category": by_category}


def default_results_path() -> Path:
    """Chemin par défaut des résultats réels (relatif à la racine du repo)."""
    return Path("bench/results/results.json")


def example_results_path() -> Path:
    """Chemin du fichier d'exemple fourni avec le dépôt."""
    return Path("bench/results/EXAMPLE_results.json")
