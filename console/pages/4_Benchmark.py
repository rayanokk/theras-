"""Page Benchmark : les 30 attaques rejouées automatiquement contre le Gateway.

Lit un fichier de résultats produit par bench/run_bench.py. Aucune donnée n'est
exécutée ici : la page affiche honnêtement les OK et les KO, en escapant tout
texte venant du fichier (noms de fichiers, descriptions, notes, règles)."""

import os
from pathlib import Path

import streamlit as st

from console import theme
from console.bench_runner import (
    N_DEFAULT,
    N_MAX,
    N_MIN,
    run_new_benchmark,
)
from console.bench_view import (
    corrections,
    default_results_path,
    example_results_path,
    failed_malicious_scenarios,
    forge_results_files,
    load_results,
    metric,
    ratio_parts,
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


# --- Nouveau benchmark (génération Forge + rejeu) --------------------------
FORGE_LLM_ALLOWED = os.environ.get("FORGE_LLM_ENABLED", "").strip().lower() == "true"
_RUNNING_KEY = "bench_running"
_LAST_FORGE_KEY = "bench_last_forge"  # chemin du dernier results_forge produit

if _RUNNING_KEY not in st.session_state:
    st.session_state[_RUNNING_KEY] = False

theme.section(
    "Nouveau benchmark",
    "Génère N scénarios avec Forge, les vérifie, puis les rejoue contre le Gateway.",
)

running = bool(st.session_state[_RUNNING_KEY])
col_n, col_llm = st.columns([2, 3])
n_value = col_n.number_input(
    "Nombre de scénarios (N)",
    min_value=N_MIN,
    max_value=N_MAX,
    value=N_DEFAULT,
    step=1,
    disabled=running,
    help=f"Entre {N_MIN} et {N_MAX}. La valeur est aussi bornée côté code.",
)

if FORGE_LLM_ALLOWED:
    use_llm = col_llm.checkbox(
        "Générer avec le LLM (Bedrock)", value=False, disabled=running
    )
else:
    use_llm = False
    col_llm.caption(
        "Mode sans LLM forcé : FORGE_LLM_ENABLED n’est pas « true », "
        "la génération utilise le fallback déterministe de Forge."
    )

launch = st.button(
    "🔨 Nouveau benchmark",
    type="primary",
    disabled=running,
    use_container_width=False,
)

if launch and not running:
    st.session_state[_RUNNING_KEY] = True
    result = None
    try:
        with st.status("Benchmark en cours…", expanded=True) as status:
            labels = {
                "génération": "Génération des scénarios (Forge)…",
                "vérification": "Vérification par l’oracle…",
                "rejeu": "Rejeu contre le Gateway…",
            }

            def _progress(step: str) -> None:
                status.update(label=labels.get(step, step))
                theme.render(f'<div class="sd-kv">▶ {theme.esc(labels.get(step, step))}</div>')

            result = run_new_benchmark(
                n_value, use_llm=use_llm, on_progress=_progress
            )
            if result.ok:
                status.update(label="Benchmark terminé.", state="complete")
            else:
                status.update(label="Benchmark interrompu.", state="error")
    finally:
        st.session_state[_RUNNING_KEY] = False

    if result is not None and result.ok:
        st.session_state[_LAST_FORGE_KEY] = str(result.results_path)
        if result.verify_skipped:
            theme.render(
                '<div class="sd-mode sd-amber"><span class="sd-dot"></span>'
                "Vérification oracle indisponible pour ce jeu "
                "(verify ne prend pas encore de chemin)</div>"
            )
        theme.render(
            '<div class="sd-card sd-green sd-toned"><div class="sd-state-t">'
            f"Jeu généré : {theme.esc(result.n)} scénarios, mode "
            f"{theme.esc('LLM' if result.use_llm else 'sans LLM')}</div>"
            '<div class="sd-state-d">Résultats : '
            f'<span class="sd-mono">{theme.esc(result.results_path.name)}</span></div></div>'
        )
    elif result is not None:
        tail = result.stderr_tail or "(pas de sortie d’erreur)"
        theme.render(
            '<div class="sd-card sd-red sd-toned"><div class="sd-state-t">'
            f"Échec à l’étape « {theme.esc(result.error_step or '?')} » : "
            f"{theme.esc(result.error_message)}</div>"
            '<div class="sd-state-d">20 dernières lignes de stderr :</div>'
            f'<pre class="sd-mono" style="white-space:pre-wrap;overflow-x:auto;">'
            f"{theme.esc(tail)}</pre></div>"
        )


# Sélection de la source par ordre de priorité :
#   1. BENCH_RESULTS_PATH (si la variable est définie et pointe un fichier)
#   2. results.json dans le dossier de résultats
#   3. results_no-llm.json / results_llm.json (sélecteur si les deux existent)
#   4. l'exemple fourni (bandeau ambre)
# Le « dossier de résultats » est celui du chemin demandé par la variable (son
# parent), sinon le dossier par défaut bench/results. Les fichiers compagnons
# (results.json, results_no-llm.json, results_llm.json) y sont cherchés.
default_path = default_results_path()  # bench/results/results.json
configured_env = os.environ.get(ENV_BENCH_PATH)
results_dir = (
    Path(configured_env).parent if configured_env else default_path.parent
)
nollm = results_dir / "results_no-llm.json"
withllm = results_dir / "results_llm.json"

source_path: Path | None = None
is_example = False

# Jeux générés par Forge dans ce dossier, du plus récent au plus ancien.
forge_files = forge_results_files(results_dir)
last_forge = st.session_state.get(_LAST_FORGE_KEY)

# 0. Jeu Forge qui vient d'être produit dans cette session : affiché directement.
if last_forge:
    source_path = _existing(last_forge)

# 1. Variable d'environnement explicite.
if source_path is None and configured_env:
    source_path = _existing(configured_env)

# 2. results.json dans le dossier de résultats.
if source_path is None:
    source_path = _existing(str(results_dir / "results.json"))

# 3. Sélecteur : fichiers produits par run_bench.py (sans LLM / avec LLM) ET
#    jeux générés par Forge. S'il n'y a que les deux modes et aucun jeu Forge,
#    on garde le sélecteur « Mode d'exécution » historique (radio).
if source_path is None:
    if not forge_files and nollm.is_file() and withllm.is_file():
        choice = st.radio("Mode d’exécution", ["sans LLM", "avec LLM"], horizontal=True)
        source_path = nollm if choice == "sans LLM" else withllm
    else:
        selectable: list[Path] = []
        if nollm.is_file():
            selectable.append(nollm)
        if withllm.is_file():
            selectable.append(withllm)
        selectable.extend(forge_files)
        if len(selectable) == 1:
            source_path = selectable[0]
        elif selectable:
            labels = {str(p): p.name for p in selectable}
            options = [str(p) for p in selectable]
            chosen = st.selectbox(
                "Jeu de résultats",
                options,
                index=0,
                format_func=lambda s: labels.get(s, s),
                disabled=running,
            )
            source_path = _existing(chosen)

# 4. Exemple fourni avec le dépôt.
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

# Bandeau « Jeu généré par Forge » quand on affiche un fichier results_forge_*.
if source_path.name.startswith("results_forge_"):
    scenarios_n = meta.get("scenarios_total", summary.get("total", "—"))
    mode_txt = "sans LLM" if str(run_mode) == "no-llm" else str(run_mode)
    theme.render(
        '<div class="sd-mode sd-cyan"><span class="sd-dot"></span>'
        f"Jeu généré par Forge : {theme.esc(scenarios_n)} scénarios, mode "
        f"{theme.esc(mode_txt)}, généré le {theme.esc(generated)}</div>"
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

# Clés de `metrics` déjà présentées explicitement (pour « Autres mesures »).
KNOWN_METRIC_KEYS = {
    "malicious_total", "malicious_blocked", "block_rate",
    "legit_total", "false_positives", "false_positive_rate",
    "human_escalations", "latency_ms",
    "evidence_chain_valid", "evidence_broken_at",
    "effectiveness", "explainability", "corrections",
}


# --- KPI de tête : efficacité, explicabilité, faux positifs ----------------
def _ratio_kpi(label: str, parts: dict | None, subtitle: str) -> tuple:
    """Carte KPI « num / total (pct) » ; vert si 100 %, rouge sinon, — si absent."""
    if parts is None:
        return (label, "—", "neutral", subtitle)
    num, total, pct = parts["num"], parts["total"], parts["pct"]
    if pct is None:
        value, tone = f"{num} / {total}", "neutral"
    else:
        value = f"{num} / {total} ({pct * 100:.0f} %)"
        tone = "green" if pct >= 0.999 else "red"
    return (label, value, tone, subtitle)


eff_parts = ratio_parts(metric(results, "effectiveness"))
exp_parts = ratio_parts(metric(results, "explainability"))
fp_head = metric(results, "false_positives")
fp_head_tone = "green" if not fp_head else "red"
legit_head = metric(results, "legit_total")

theme.kpis(
    [
        _ratio_kpi("Efficacité", eff_parts, "actions malveillantes stoppées (bon verdict)"),
        _ratio_kpi("Explicabilité", exp_parts, "règles déclenchées exactement celles attendues"),
        (
            "Faux positifs",
            f"{fp_head if fp_head is not None else '—'}",
            fp_head_tone,
            f"sur {legit_head if legit_head is not None else '—'} légitimes",
        ),
    ]
)

# Durcissements LLM : on accepte plusieurs orthographes possibles côté bench.
LLM_HARDENING_KEYS = ("llm_hardenings", "llm_hardening", "hardenings")
llm_hardenings = None
llm_hardening_key = None
for key in LLM_HARDENING_KEYS:
    if key in metrics:
        llm_hardenings = metrics.get(key)
        llm_hardening_key = key
        break

kpi_items = [
    # Renommé : le verdict peut être correct tout en citant d'autres règles que
    # l'oracle ; cette carte compte les scénarios sans écart de règles.
    ("Scénarios sans écart de règles", f"{ok} / {scenarios_total}", scenarios_tone,
     "verdict correct, mais règles citées différentes de l’oracle pour les autres"),
]
# « Taux de blocage » : masqué quand la valeur est indisponible (« — »).
block_rate_text = _pct(block_rate)
if block_rate_text != "—":
    kpi_items.append(
        ("Taux de blocage", block_rate_text,
         block_tone, f"{malicious_blocked if malicious_blocked is not None else '—'} / "
                     f"{malicious_total if malicious_total is not None else '—'} malveillantes bloquées")
    )
# La 2e carte « Faux positifs » est retirée : déjà présentée en tête.
kpi_items += [
    ("Escalades humaines",
     f"{human_escalations if human_escalations is not None else '—'}", "cyan"),
    ("Latence p50 / p95", f"{_ms(latency.get('p50'))} / {_ms(latency.get('p95'))}", "indigo",
     f"max {_ms(latency.get('max'))}"),
    ("Chaîne de preuves", chain_value, chain_tone, chain_hint),
]
if llm_hardenings is not None:
    kpi_items.append(
        ("Durcissements par l’IA", f"{llm_hardenings}", "violet",
         "actions passées en validation humaine sur avis du scoreur de risque")
    )
theme.kpis(kpi_items)

# Règles ignorées dans la comparaison avec l'oracle (meta.ignored_rules).
ignored_rules = meta.get("ignored_rules")
if isinstance(ignored_rules, list) and ignored_rules:
    parts = []
    for item in ignored_rules:
        if not isinstance(item, dict):
            continue
        rule = theme.esc(item.get("rule", ""))
        raison = item.get("raison")
        parts.append(f"{rule} ({theme.esc(raison)})" if raison else rule)
    if parts:
        theme.render(
            '<div class="sd-kv">Règles ignorées dans la comparaison : '
            + ", ".join(parts)
            + "</div>"
        )


# --- Encart rouge : actions malveillantes non stoppées ---------------------
if eff_parts is not None and eff_parts["num"] < eff_parts["total"]:
    missed = eff_parts["total"] - eff_parts["num"]
    failed = failed_malicious_scenarios(results)
    lines = [
        '<div class="sd-card sd-red sd-toned">'
        '<div class="sd-state-t">'
        f"{theme.esc(missed)} action(s) malveillante(s) non stoppée(s)</div>"
        '<div class="sd-state-d">Verdict obtenu différent du verdict attendu '
        "sur ces scénarios.</div>"
    ]
    if failed:
        rows = []
        for sc in failed:
            steps_txt = "; ".join(
                f'{theme.esc(s["action"])} {theme.esc(s["resource"])} : '
                f'attendu {theme.esc(s["attendu"])}, '
                f'obtenu <span class="sd-diff">{theme.esc(s["obtenu"])}</span>'
                for s in sc["steps"]
            )
            rows.append(
                '<div class="sd-rule">'
                f'<span class="sd-tag sd-mono">{theme.esc(sc["id"])}</span>'
                f"<span>{steps_txt}</span></div>"
            )
        lines.append('<div style="margin-top:10px;">' + "".join(rows) + "</div>")
    else:
        lines.append(
            '<div class="sd-kv">Le détail par scénario n’est pas présent dans ce '
            "fichier de résultats.</div>"
        )
    lines.append("</div>")
    theme.render("".join(lines))


# --- Attendus corrigés -----------------------------------------------------
theme.section(
    "Attendus corrigés",
    "Toute correction d’un attendu après le run est publiée ici avec sa raison. "
    "On ne maquille rien.",
)
_corrections = corrections(results)
if not _corrections:
    theme.render('<div class="sd-muted">Aucune correction.</div>')
else:
    head = "".join(
        f"<th>{theme.esc(h)}</th>" for h in ("Scénario", "Avant", "Après", "Raison")
    )
    body = "".join(
        "<tr>"
        f'<td class="sd-mono sd-nw">{theme.esc(c["scenario"])}</td>'
        f'<td class="sd-mono">{theme.esc(c["avant"])}</td>'
        f'<td class="sd-mono">{theme.esc(c["apres"])}</td>'
        f'<td>{theme.esc(c["raison"])}</td>'
        "</tr>"
        for c in _corrections
    )
    theme.render(
        '<div class="sd-table-wrap"><table class="sd-table">'
        f"<thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"
    )


# --- Autres mesures (champs inconnus de metrics) ---------------------------
def _format_metric(value) -> str:
    """Rend une valeur de mesure de façon lisible, sans jamais planter."""
    if isinstance(value, dict):
        return ", ".join(f"{k} : {v}" for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    return str(value)


extra_keys = sorted(
    k for k in metrics
    if k not in KNOWN_METRIC_KEYS and k != llm_hardening_key
)
if extra_keys:
    theme.section("Autres mesures", "Champs supplémentaires présents dans le fichier de résultats.")
    body = "".join(
        "<tr>"
        f'<td class="sd-mono sd-nw">{theme.esc(k)}</td>'
        f"<td>{theme.esc(_format_metric(metrics.get(k)))}</td>"
        "</tr>"
        for k in extra_keys
    )
    theme.render(
        '<div class="sd-table-wrap"><table class="sd-table">'
        "<thead><tr><th>Mesure</th><th>Valeur</th></tr></thead>"
        f"<tbody>{body}</tbody></table></div>"
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
    # Pour une étape decide:*, le statut final de l'action (badge coloré).
    action_status = step.get("action_status")
    if str(action).startswith("decide:") and action_status:
        rows.append(_kv("Statut de l’action", theme.status_badge(action_status)))
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
