"""Page Benchmark : les 30 attaques rejouées automatiquement contre le Gateway.

Lit un fichier de résultats produit par bench/run_bench.py. Aucune donnée n'est
exécutée ici : la page affiche honnêtement les OK et les KO, en escapant tout
texte venant du fichier (noms de fichiers, descriptions, notes, règles)."""

import os
from pathlib import Path

import streamlit as st

from console import theme
from console.bench_view import (
    default_results_path,
    example_results_path,
    load_results,
    summarize,
)

theme.setup("Benchmark — Police Agents", "📈")

ENV_BENCH_PATH = "BENCH_RESULTS_PATH"

# Libellés français des catégories.
CATEGORY_LABELS = {
    "injection_indirecte": "Injection indirecte",
    "exfiltration": "Exfiltration",
    "abus_privileges": "Abus de privilèges",
    "usurpation": "Usurpation d’identité",
    "contournement": "Contournement",
    "abus_approbation": "Abus d’approbation",
    "falsification_preuves": "Falsification des preuves",
    "legitime": "Usage légitime (faux positifs)",
}

# Étapes « techniques » : pas de verdict attendu à comparer.
NON_VERDICT_PREFIXES = ("wait", "tamper", "set_classification", "decide:", "verify")


def _cat_label(category: str) -> str:
    return CATEGORY_LABELS.get(category, category or "inconnu")


def _has_expectation(step: dict) -> bool:
    """Vrai si l'étape a un verdict attendu à comparer (pas une étape technique)."""
    action = str(step.get("action", ""))
    if step.get("attendu"):
        return True
    return not any(action.startswith(p) for p in NON_VERDICT_PREFIXES)


# --- Source des résultats --------------------------------------------------
theme.hero(
    "Benchmark",
    "30 attaques rejouées automatiquement",
    "Chaque scénario envoie de vraies requêtes au Gateway et compare le verdict "
    "obtenu au verdict attendu. Les écarts sont montrés tels quels.",
)


def _existing(path_str: str) -> Path | None:
    p = Path(path_str)
    return p if p.is_file() else None


# Sélection de la source, avec bascule sans LLM / avec LLM si les deux existent.
configured = os.environ.get(ENV_BENCH_PATH, str(default_results_path()))
results_dir = Path(configured).parent if configured else Path("bench/results")
nollm = results_dir / "results_nollm.json"
withllm = results_dir / "results_llm.json"

source_path: Path | None = None
is_example = False

if nollm.is_file() and withllm.is_file():
    choice = st.radio(
        "Mode d’exécution",
        ["sans LLM", "avec LLM"],
        horizontal=True,
    )
    source_path = nollm if choice == "sans LLM" else withllm
else:
    source_path = _existing(configured)
    if source_path is None:
        example = _existing(str(example_results_path()))
        if example is not None:
            source_path = example
            is_example = True

if source_path is None:
    theme.mode_banner()
    st.info(
        "Aucun résultat de benchmark trouvé. Lancez `python bench/run_bench.py` "
        "pour générer `bench/results/results.json`."
    )
    st.stop()

results = load_results(source_path)
if results is None:
    theme.mode_banner()
    theme.error_box(f"Fichier de résultats illisible : {source_path}")
    st.stop()

if is_example:
    theme.render(
        '<div class="sd-mode sd-amber"><span class="sd-dot"></span>'
        "Données d’exemple : lancez run_bench.py pour les vrais résultats</div>"
    )

meta = results.get("meta") or {}
metrics = results.get("metrics") or {}
summary = summarize(results)

run_mode = meta.get("mode", "—")
generated = meta.get("generated_at", "—")
theme.render(
    f'<div class="sd-kv">Run : mode <b>{theme.esc(run_mode)}</b> · '
    f"généré le <b>{theme.esc(generated)}</b></div>"
)


# --- KPI --------------------------------------------------------------------
def _pct(value) -> str:
    try:
        return f"{float(value) * 100:.0f} %"
    except (TypeError, ValueError):
        return "—"


def _ms(value) -> str:
    try:
        return f"{int(value)} ms"
    except (TypeError, ValueError):
        return "—"


total = summary["total"]
ok = summary["ok"]
scenarios_total = meta.get("scenarios_total", total)

malicious_total = metrics.get("malicious_total")
malicious_blocked = metrics.get("malicious_blocked")
block_rate = metrics.get("block_rate")
legit_total = metrics.get("legit_total")
false_positives = metrics.get("false_positives")
human_escalations = metrics.get("human_escalations")
latency = metrics.get("latency_ms") or {}
chain_valid = bool(metrics.get("evidence_chain_valid"))
broken_at = metrics.get("evidence_broken_at")

scenarios_tone = "green" if ok == scenarios_total and total else "amber"
block_tone = "green" if (block_rate or 0) >= 0.999 else "amber"
fp_tone = "green" if not false_positives else "red"
chain_tone = "green" if chain_valid else "red"

chain_value = "Oui" if chain_valid else "Non"
chain_hint = "Vérifiée" if chain_valid else f"Rompue à la preuve {broken_at}"

theme.kpis(
    [
        ("Scénarios réussis", f"{ok} / {scenarios_total}", scenarios_tone),
        ("Taux de blocage", _pct(block_rate),
         block_tone, f"{malicious_blocked if malicious_blocked is not None else '—'} / "
                     f"{malicious_total if malicious_total is not None else '—'} malveillantes bloquées"),
        ("Faux positifs",
         f"{false_positives if false_positives is not None else '—'}",
         fp_tone, f"sur {legit_total if legit_total is not None else '—'} légitimes"),
        ("Escalades humaines",
         f"{human_escalations if human_escalations is not None else '—'}", "cyan"),
        ("Latence p50 / p95", f"{_ms(latency.get('p50'))} / {_ms(latency.get('p95'))}", "indigo",
         f"max {_ms(latency.get('max'))}"),
        ("Chaîne de preuves", chain_value, chain_tone, chain_hint),
    ]
)


# --- Résultats par catégorie -----------------------------------------------
theme.section("Résultats par catégorie", "Scénarios OK (vert) et KO (rouge) par famille d’attaque.")


def _category_bars(by_category: dict) -> str:
    rows = []
    for category, counts in sorted(by_category.items(), key=lambda kv: _cat_label(kv[0])):
        c_ok = counts.get("ok", 0)
        c_ko = counts.get("ko", 0)
        c_total = counts.get("total", c_ok + c_ko) or 1
        ok_pct = c_ok / c_total * 100
        ko_pct = c_ko / c_total * 100
        ok_seg = (
            f'<div class="sd-bar-ok" style="width:{ok_pct:.1f}%"></div>' if c_ok else ""
        )
        ko_seg = (
            f'<div class="sd-bar-ko" style="width:{ko_pct:.1f}%"></div>' if c_ko else ""
        )
        rows.append(
            '<div class="sd-catrow">'
            f'<div class="sd-catname">{theme.esc(_cat_label(category))}</div>'
            f'<div class="sd-bar">{ok_seg}{ko_seg}</div>'
            f'<div class="sd-catnums"><span class="sd-ok-num">{c_ok} OK</span>'
            f'<span class="sd-ko-num">{c_ko} KO</span></div>'
            "</div>"
        )
    return '<div class="sd-cats">' + "".join(rows) + "</div>"


# CSS local des barres (toujours injecté avant usage).
theme.render(
    "<style>"
    ".sd-cats{display:flex;flex-direction:column;gap:10px;margin-top:6px;}"
    ".sd-catrow{display:grid;grid-template-columns:220px 1fr 150px;align-items:center;gap:14px;}"
    ".sd-catname{color:#E7ECF5;font-size:.9rem;}"
    ".sd-bar{height:16px;border-radius:999px;background:#0E1627;border:1px solid #24324F;overflow:hidden;display:flex;}"
    ".sd-bar-ok{height:100%;background:#22C55E;}"
    ".sd-bar-ko{height:100%;background:#F04452;}"
    ".sd-catnums{display:flex;gap:12px;justify-content:flex-end;font-size:.8rem;font-weight:600;}"
    ".sd-ok-num{color:#22C55E;}.sd-ko-num{color:#F04452;}"
    ".sd-step{border:1px solid #24324F;border-radius:12px;padding:10px 14px;margin-bottom:8px;background:rgba(14,22,39,.5);}"
    ".sd-step.sd-step-ko{border-color:rgba(240,68,82,.5);background:rgba(240,68,82,.07);}"
    ".sd-step-head{font-weight:600;margin-bottom:6px;}"
    ".sd-grid{display:grid;grid-template-columns:auto 1fr;gap:4px 14px;font-size:.84rem;}"
    ".sd-grid .k{color:#8B97B4;}"
    ".sd-diff{color:#F04452;font-weight:600;}"
    ".sd-note{margin-top:8px;font-size:.82rem;color:#F5A524;}"
    "</style>"
)
theme.render(_category_bars(summary["by_category"]))


# --- Tableau des scénarios --------------------------------------------------
theme.section("Scénarios", "Les 30 scénarios du benchmark, filtrables.")

scenarios = [s for s in (results.get("scenarios") or []) if isinstance(s, dict)]
present_cats = sorted({s.get("categorie") or "inconnu" for s in scenarios}, key=_cat_label)

col_cat, col_res = st.columns([3, 2])
cat_filter = col_cat.multiselect(
    "Catégorie", present_cats, default=present_cats, format_func=_cat_label
)
res_filter = col_res.multiselect("Résultat", ["OK", "KO"], default=["OK", "KO"])

filtered = [
    s
    for s in scenarios
    if (s.get("categorie") or "inconnu") in cat_filter
    and str(s.get("result", "")).upper() in res_filter
]


def _result_badge(result: str) -> str:
    r = str(result).upper()
    return theme.badge(r or "?", "green" if r == "OK" else "red")


def _table(rows: list[dict]) -> str:
    head = "".join(
        f"<th>{theme.esc(h)}</th>" for h in ("ID", "Catégorie", "Description", "Résultat")
    )
    body = []
    for s in rows:
        body.append(
            "<tr>"
            f'<td class="sd-mono sd-nw">{theme.esc(s.get("id"))}</td>'
            f'<td class="sd-nw">{theme.esc(_cat_label(s.get("categorie")))}</td>'
            f"<td>{theme.esc(s.get('description'))}</td>"
            f"<td>{_result_badge(s.get('result'))}</td>"
            "</tr>"
        )
    return (
        '<div class="sd-table-wrap"><table class="sd-table">'
        f"<thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table></div>"
    )


if not filtered:
    st.info("Aucun scénario ne correspond aux filtres.")
    st.stop()
theme.render(_table(filtered))


# --- Détail par scénario ----------------------------------------------------
theme.section(
    "Détail des scénarios",
    "Chaque étape, verdict attendu contre verdict obtenu. Un attendu faux se note, il ne se maquille pas.",
)


def _rules_text(rules) -> str:
    if not rules:
        return "—"
    return ", ".join(str(r) for r in rules)


def _kv(key: str, value_html: str) -> str:
    return f'<span class="k">{theme.esc(key)}</span><span>{value_html}</span>'


def _step_html(step: dict) -> str:
    is_ok = bool(step.get("ok", False))
    ko_cls = "" if is_ok else " sd-step-ko"
    num = step.get("step", "?")
    action = step.get("action", "?")
    resource = step.get("resource")
    http = step.get("http")
    latency_ms = step.get("latency_ms")
    note = step.get("note") or ""

    head = (
        f'<div class="sd-step-head">Étape {theme.esc(num)} · '
        f'<span class="sd-mono">{theme.esc(action)}</span>'
    )
    if resource and str(resource) != "-":
        head += f' · <span class="sd-mono sd-file">{theme.esc(resource)}</span>'
    head += "</div>"

    rows = []
    if _has_expectation(step):
        attendu = step.get("attendu")
        obtenu = step.get("obtenu")
        v_diff = (attendu is not None and obtenu is not None and attendu != obtenu)
        o_html = theme.esc(obtenu)
        if v_diff:
            o_html = f'<span class="sd-diff">{o_html}</span>'
        rows.append(_kv("Verdict attendu", theme.esc(attendu)))
        rows.append(_kv("Verdict obtenu", o_html))

        ra = step.get("regles_attendues") or []
        ro = step.get("regles_obtenues") or []
        r_diff = sorted(str(x) for x in ra) != sorted(str(x) for x in ro)
        ro_html = theme.esc(_rules_text(ro))
        if r_diff:
            ro_html = f'<span class="sd-diff">{ro_html}</span>'
        rows.append(_kv("Règles attendues", theme.esc(_rules_text(ra))))
        rows.append(_kv("Règles obtenues", ro_html))

    if http is not None:
        rows.append(_kv("Code HTTP", theme.esc(http)))
    if latency_ms is not None:
        rows.append(_kv("Latence", theme.esc(f"{latency_ms} ms")))

    grid = f'<div class="sd-grid">{"".join(rows)}</div>' if rows else ""
    note_html = f'<div class="sd-note">⚠ {theme.esc(note)}</div>' if note else ""
    return f'<div class="sd-step{ko_cls}">{head}{grid}{note_html}</div>'


for s in filtered:
    header = f"{s.get('id')} · {_cat_label(s.get('categorie'))} · {str(s.get('result', '')).upper()}"
    with st.expander(header):
        theme.render(f'<div class="sd-muted">{theme.esc(s.get("description"))}</div>')
        steps = [st_ for st_ in (s.get("steps") or []) if isinstance(st_, dict)]
        if not steps:
            theme.render('<div class="sd-muted">Aucune étape enregistrée.</div>')
        else:
            theme.render("".join(_step_html(step) for step in steps))
