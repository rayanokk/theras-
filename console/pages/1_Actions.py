"""Page Actions : journal filtrable des décisions, avec détail par action."""

import streamlit as st

from console import theme
from console.client import get_client
from console.labels import RULE_LABELS, action_label

theme.setup("Actions — Theras", "📋")


@st.cache_resource
def _client():
    """Client partagé pour toute la session (une seule connexion)."""
    return get_client()


theme.hero(
    "Actions",
    "Chaque action d’agent, jugée avant exécution",
    "Ce que les agents ont demandé, ce que les règles ont décidé, et pourquoi.",
)
theme.mode_banner()

try:
    client = _client()
    decisions = client.list_actions()
    rows_all = client.list_action_rows()
except Exception as exc:
    theme.error_box(exc)
    st.stop()

decisions_by_id = {d.action_id: d for d in decisions}

# --- Filtres ---------------------------------------------------------------
present_verdicts = {r["verdict"] for r in rows_all}
verdicts = [v for v in theme.VERDICT_LABELS if v in present_verdicts]
agents = sorted({(r.get("agent_id") or "?") for r in rows_all})

col_v, col_a, col_q = st.columns([2, 2, 3])
verdict_filter = col_v.multiselect(
    "Verdict",
    verdicts,
    default=verdicts,
    format_func=lambda v: theme.VERDICT_LABELS.get(v, v),
)
agent_filter = col_a.multiselect("Agent", agents, default=agents)
query = col_q.text_input("Recherche", placeholder="Nom de fichier ou destinataire…")


def _matches(row: dict, needle: str) -> bool:
    if not needle:
        return True
    haystack = f"{row.get('resource_id') or ''} {row.get('recipient') or ''}".lower()
    return needle in haystack


needle = query.strip().lower()
filtered = [
    r
    for r in rows_all
    if r["verdict"] in verdict_filter
    and (r.get("agent_id") or "?") in agent_filter
    and _matches(r, needle)
]

# --- KPI recalculés selon les filtres ---------------------------------------
counts = {"ALLOW": 0, "REVIEW": 0, "DENY": 0}
for r in filtered:
    if r["verdict"] in counts:
        counts[r["verdict"]] += 1
theme.kpis(
    [
        ("Actions affichées", len(filtered), "indigo"),
        ("Autorisées", counts["ALLOW"], "green"),
        ("Validation humaine", counts["REVIEW"], "amber"),
        ("Bloquées", counts["DENY"], "red"),
    ]
)


# --- Tableau ---------------------------------------------------------------
def _table_html(rows: list[dict]) -> str:
    headers = ("ID", "Agent", "Action", "Fichier", "Destinataire", "Verdict", "Statut", "Règles")
    head = "".join(f"<th>{theme.esc(h)}</th>" for h in headers)
    body = []
    for r in rows:
        verdict_cell = theme.verdict_badge(r["verdict"])
        if r.get("taint_sources"):
            verdict_cell += theme.badge("session contaminée", "amber")
        rule_ids = [x for x in (r.get("rule_ids") or "").split(", ") if x]
        rules = "".join(
            theme.badge(rid, "indigo", mono=True, title=RULE_LABELS.get(rid)) for rid in rule_ids
        )
        body.append(
            "<tr>"
            f'<td class="sd-mono sd-nw">{theme.esc(r["action_id"])}</td>'
            f'<td class="sd-nw">{theme.esc(r.get("agent_id") or "?")}</td>'
            f'<td class="sd-nw">{theme.esc(action_label(r.get("action")).capitalize())}</td>'
            f'<td class="sd-mono">{theme.esc(r.get("resource_id") or "—")}</td>'
            f"<td>{theme.esc(r.get('recipient') or '—')}</td>"
            f'<td><div class="sd-cell-badges">{verdict_cell}</div></td>'
            f"<td>{theme.status_badge(r['status'])}</td>"
            f'<td><div class="sd-rules">{rules}</div></td>'
            "</tr>"
        )
    return (
        '<div class="sd-table-wrap"><table class="sd-table">'
        f"<thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table></div>"
    )


theme.section("Journal des actions")
if not filtered:
    st.info("Aucune action ne correspond aux filtres.")
    st.stop()
theme.render(_table_html(filtered))

# --- Détail d'une action ---------------------------------------------------
theme.section("Inspecter une action", "Sa décision, ses règles et son parcours de preuves.")
by_id = {r["action_id"]: r for r in filtered}


def _option_label(action_id: str) -> str:
    r = by_id[action_id]
    label = f"{action_id} · {r.get('agent_id') or '?'} veut {action_label(r.get('action'))} {r.get('resource_id') or '?'}"
    if r.get("recipient"):
        label += f" → {r['recipient']}"
    return label


selected_id = st.selectbox("Action", list(by_id), format_func=_option_label)
row = by_id[selected_id]
decision = decisions_by_id.get(selected_id)

try:
    events = client.list_events(action_id=selected_id)
except Exception as exc:
    theme.error_box(exc)
    st.stop()

col_left, col_right = st.columns([3, 2], gap="large")

with col_left:
    theme.render(
        theme.action_sentence(
            row.get("agent_id"),
            row.get("action"),
            row.get("resource_id"),
            row.get("recipient"),
            big=True,
        )
    )
    badges = theme.verdict_badge(row["verdict"]) + theme.status_badge(row["status"])
    if row.get("taint_sources"):
        badges += theme.badge(
            "session contaminée par " + ", ".join(row["taint_sources"]), "amber"
        )
    theme.render(f'<div class="sd-badges">{badges}</div>')

    theme.panel_title("Règles appliquées")
    rule_ids = decision.rule_ids if decision is not None else []
    if rule_ids:
        theme.render("".join(theme.rule_line(rid) for rid in rule_ids))
    else:
        theme.render('<div class="sd-muted">Aucune règle enregistrée.</div>')

    if row.get("reason"):
        theme.render(
            '<div class="sd-quote"><div class="sd-quote-h">Ce que l’agent dit vouloir faire</div>'
            f"{theme.esc(row['reason'])}</div>"
        )

    if decision is not None and decision.reasons:
        with st.expander("Raisons détaillées du moteur"):
            for reason in decision.reasons:
                st.write(f"- {reason}")

with col_right:
    theme.panel_title("Parcours de preuves")
    if not events:
        theme.render('<div class="sd-muted">Aucun événement pour cette action.</div>')
    else:
        items = []
        for e in events:
            items.append(
                f'<div class="sd-tl-item sd-{theme.event_tone(e.type)}">'
                '<span class="sd-tl-dot"></span>'
                f'<div><div class="sd-tl-title">{theme.esc(theme.event_label(e.type))}</div>'
                '<div class="sd-tl-meta">'
                f'<span class="sd-mono">PREUVE #{theme.esc(e.seq)}</span> · '
                f"{theme.esc(theme.fmt_time(e.ts))} · "
                f'<span class="sd-mono">{theme.esc(theme.short(e.hash, 8))}</span>'
                "</div></div></div>"
            )
        theme.render('<div class="sd-timeline">' + "".join(items) + "</div>")
