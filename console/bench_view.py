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


_MISSING = object()


def metric(results, key, default=None):
    """Lit une métrique : d'abord results['metrics'][key], sinon results[key].

    Tolère un `results` None ou sans la clé. Renvoie `default` si absente."""
    if not isinstance(results, dict):
        return default
    metrics = results.get("metrics")
    if isinstance(metrics, dict):
        value = metrics.get(key, _MISSING)
        if value is not _MISSING:
            return value
    value = results.get(key, _MISSING)
    return default if value is _MISSING else value


def ratio_parts(value) -> dict | None:
    """Normalise un dict {num_key, 'total'} en {num, total, pct}.

    `value` attendu de la forme {"stopped": n, "total": t} ou
    {"exact": n, "total": t}. Renvoie None si la forme n'est pas exploitable.
    pct vaut None quand total est 0 ou absent (évite une division par zéro)."""
    if not isinstance(value, dict):
        return None
    total = value.get("total")
    # Le numérateur est la seule autre clé entière (stopped, exact, …).
    num = None
    for k, v in value.items():
        if k != "total" and isinstance(v, (int, float)) and not isinstance(v, bool):
            num = v
            break
    if num is None or not isinstance(total, (int, float)) or isinstance(total, bool):
        return None
    pct = (num / total) if total else None
    return {"num": num, "total": total, "pct": pct}


def corrections(results) -> list[dict]:
    """Liste normalisée des corrections d'attendus.

    Chaque entrée : {"scenario", "avant", "apres", "raison"} (chaînes).
    `avant`/`apres` peuvent être des listes de règles ou des chaînes ; on les
    rend en texte lisible. Tolère l'absence totale de la clé."""
    raw = metric(results, "corrections", [])
    if not isinstance(raw, list):
        return []
    out = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        out.append(
            {
                "scenario": item.get("scenario", ""),
                "avant": _as_text(item.get("avant")),
                "apres": _as_text(item.get("apres")),
                "raison": item.get("raison", ""),
            }
        )
    return out


def failed_malicious_scenarios(results) -> list[dict]:
    """Scénarios dont au moins une étape a un verdict obtenu ≠ attendu.

    Sert à détailler pourquoi effectiveness.stopped < total. Chaque entrée :
    {"id", "categorie", "description", "steps": [{action, resource,
    attendu, obtenu}]}. Vide si les scénarios ne sont pas dans le JSON."""
    scenarios = []
    if isinstance(results, dict) and isinstance(results.get("scenarios"), list):
        scenarios = results["scenarios"]

    out = []
    for scenario in scenarios:
        if not isinstance(scenario, dict):
            continue
        bad_steps = []
        for step in scenario.get("steps") or []:
            if not isinstance(step, dict):
                continue
            attendu = step.get("attendu")
            obtenu = step.get("obtenu")
            if attendu is not None and obtenu is not None and attendu != obtenu:
                bad_steps.append(
                    {
                        "action": step.get("action", ""),
                        "resource": step.get("resource", ""),
                        "attendu": attendu,
                        "obtenu": obtenu,
                    }
                )
        if bad_steps:
            out.append(
                {
                    "id": scenario.get("id", ""),
                    "categorie": scenario.get("categorie", ""),
                    "description": scenario.get("description", ""),
                    "steps": bad_steps,
                }
            )
    return out


def _as_text(value) -> str:
    """Rend une valeur (liste de règles ou chaîne) en texte lisible."""
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    return str(value)


def default_results_path() -> Path:
    """Chemin par défaut des résultats réels (relatif à la racine du repo)."""
    return Path("bench/results/results.json")


def example_results_path() -> Path:
    """Chemin du fichier d'exemple fourni avec le dépôt."""
    return Path("bench/results/EXAMPLE_results.json")
