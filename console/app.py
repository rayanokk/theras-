"""Console Theras — page d'accueil (Streamlit).

Lancer : streamlit run console/app.py
Mode choisi par CONSOLE_MODE (local par défaut, ou http) ; cf. console/client.py.
"""

import streamlit as st

from console import theme
from console.client import get_client

theme.setup("Theras — Console", "🛡️")

# Étapes du trajet d'une action : (numéro, titre, phrase, ton).
_FLOW = [
    ("1", "Agent IA", "Propose une action : lire, partager, envoyer ou supprimer un fichier.", "violet"),
    ("2", "Gateway", "Reçoit la demande, vérifie l'identité de l'agent et son périmètre.", "cyan"),
    ("3", "Règles", "Autorisent, bloquent ou exigent une validation humaine, de façon déterministe.", "indigo"),
    ("4", "Humain", "Tranche les cas sensibles et signe sa décision d'une justification.", "amber"),
    ("5", "Boîte noire", "Scelle chaque étape dans un registre chaîné où toute altération se détecte.", "green"),
]


def _plural(n: int, singular: str, plural: str | None = None) -> str:
    return f"{n} {singular if n < 2 else (plural or singular + 's')}"


def _flow_html() -> str:
    parts = []
    for i, (num, title, desc, tone) in enumerate(_FLOW):
        parts.append(
            f'<div class="sd-step sd-{tone}"><div class="sd-step-n">{theme.esc(num)}</div>'
            f'<div><div class="sd-step-t">{theme.esc(title)}</div>'
            f'<div class="sd-step-d">{theme.esc(desc)}</div></div></div>'
        )
        if i < len(_FLOW) - 1:
            parts.append('<div class="sd-flow-arrow">↓</div>')
    return "".join(parts)


theme.hero(
    "Theras",
    "Les agents IA proposent. Les règles décident. L’humain tranche.",
    "Chaque action d’un agent IA passe par un gateway : autorisée, bloquée, ou soumise "
    "à une validation humaine, avec une preuve vérifiable à chaque étape.",
)
theme.mode_banner()


@st.cache_resource
def _client():
    """Client partagé pour toute la session (une seule connexion)."""
    return get_client()


try:
    client = _client()
    actions = client.list_actions()
    rows = {r["action_id"]: r for r in client.list_action_rows()}
    pending = len(client.list_pending_approvals())
    events = client.list_events()
    chain = client.verify_chain()
except Exception as exc:
    theme.error_box(exc)
    st.stop()

by_verdict = {"ALLOW": 0, "REVIEW": 0, "DENY": 0}
for decision in actions:
    verdict = decision.verdict.value
    if verdict in by_verdict:
        by_verdict[verdict] += 1

theme.kpis(
    [
        ("Actions contrôlées", len(actions), "indigo"),
        ("Autorisées", by_verdict["ALLOW"], "green"),
        ("Validation humaine", by_verdict["REVIEW"], "amber"),
        ("Bloquées", by_verdict["DENY"], "red"),
        ("Décisions en attente", pending, "cyan"),
    ]
)

col_flow, col_chain = st.columns([3, 2], gap="large")

with col_flow:
    theme.section("Le trajet d’une action", "De la proposition de l’agent à la preuve archivée.")
    theme.render(f'<div class="sd-flow">{_flow_html()}</div>')

with col_chain:
    theme.section("Intégrité de la boîte noire", "Le registre qui garde la trace de tout.")
    valid = bool(chain.get("valid"))
    count = len(events)
    last_hash = theme.short(events[-1].hash, 16) + "…" if events else "aucune"
    if valid:
        icon, title, tone = "✅", "Chaîne intacte", "green"
        detail = "Aucune altération détectée."
    else:
        broken_at = chain.get("broken_at")
        icon, title, tone = "⛔", f"Chaîne rompue à la preuve {broken_at}", "red"
        detail = "Le registre a été modifié : les preuves ne sont plus fiables."
    theme.render(
        theme.card(
            '<div class="sd-state">'
            f'<div class="sd-state-icon">{icon}</div>'
            f'<div><div class="sd-state-t">{theme.esc(title)}</div>'
            f'<div class="sd-state-d">{theme.esc(detail)}</div></div></div>'
            f'<div class="sd-kv">{theme.esc(_plural(count, "preuve enregistrée", "preuves enregistrées"))}</div>'
            f'<div class="sd-kv">Dernière empreinte : '
            f'<b class="sd-mono">{theme.esc(last_hash)}</b></div>',
            tone,
        )
    )
    if pending:
        try:
            st.page_link(
                "pages/3_Approvals.py",
                label=f"Traiter les décisions en attente ({pending})",
                icon="⚖️",
            )
        except Exception:
            # Lien de confort : s'il ne peut pas se résoudre (lancement hors
            # `streamlit run console/app.py`), on n'affiche simplement rien.
            pass

theme.section("Activité récente", "Les 8 dernières actions contrôlées par le gateway.")
recent = sorted(actions, key=lambda a: (a.created_at or "", a.action_id), reverse=True)[:8]
if not recent:
    theme.render('<div class="sd-muted">Aucune action enregistrée pour l’instant.</div>')
else:
    items = []
    for a in recent:
        row = rows.get(a.action_id, {})
        sentence = theme.action_sentence(
            row.get("agent_id") or a.agent_id,
            row.get("action"),
            row.get("resource_id"),
            row.get("recipient"),
        )
        items.append(
            '<div class="sd-act">'
            f'<span class="sd-id sd-mono">{theme.esc(a.action_id)}</span>'
            f"{sentence}"
            '<div class="sd-act-badges">'
            f"{theme.verdict_badge(a.verdict)}{theme.status_badge(a.status)}"
            "</div></div>"
        )
    theme.render('<div class="sd-activity">' + "".join(items) + "</div>")
