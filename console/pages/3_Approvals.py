"""Page Approvals : « Human Decision Center ».

Chaque approbation en attente est présentée comme une carte avec le contexte de
l'action, les règles, l'avis IA éventuel, le temps restant, et un formulaire de
décision. Tout passe par get_client().
"""

from datetime import datetime, timezone

import streamlit as st

from console import theme
from console.client import DecideError, get_client
from console.labels import INTERNAL_DOMAIN

theme.setup("Approvals — Police Agents", "⚖️")


@st.cache_resource
def _client():
    """Client partagé pour toute la session (une seule connexion)."""
    return get_client()


theme.hero(
    "Approvals",
    "Human Decision Center",
    "Les règles ont signalé ces actions. L’IA donne un avis, mais seul un humain peut trancher.",
)
theme.mode_banner()

try:
    client = _client()
    pending = client.list_pending_approvals()
    decisions = {d.action_id: d for d in client.list_actions()}
    rows = {r["action_id"]: r for r in client.list_action_rows()}
except Exception as exc:
    theme.error_box(exc)
    st.stop()

# Message de succès conservé à travers le st.rerun().
if "approval_success" in st.session_state:
    st.success(st.session_state.pop("approval_success"))

if not pending:
    st.info("Aucune décision en attente.")
    st.stop()


def _is_external(recipient: str | None) -> bool:
    """Vrai si le destinataire n'est pas sur le domaine interne."""
    if not recipient or "@" not in recipient:
        return False
    domain = recipient.rsplit("@", 1)[1].lower()
    return domain != INTERNAL_DOMAIN


def _remaining_minutes(expires_at: str) -> float | None:
    """Minutes restantes avant expiration, ou None si non parsable."""
    try:
        exp = datetime.fromisoformat(expires_at)
    except (ValueError, TypeError):
        return None
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    delta = exp - datetime.now(timezone.utc)
    return delta.total_seconds() / 60.0


def _chrono_badge(expires_at: str) -> str:
    """Badge du temps restant, rouge sous 2 minutes ou une fois expirée."""
    remaining = _remaining_minutes(expires_at)
    if remaining is None:
        return theme.badge("⏱ Expiration inconnue", "neutral")
    if remaining <= 0:
        return theme.badge("⏱ Expirée", "red")
    if remaining < 2:
        return theme.badge(f"⏱ Expire dans {remaining:.1f} min", "red")
    return theme.badge(f"⏱ Expire dans {remaining:.0f} min", "cyan")


# Options de décision : aucune présélection (index=None).
_DECISION_OPTIONS = ["approve", "reject"]
_DECISION_LABELS = {
    "approve": "✅ Approuver",
    "reject": "⛔ Refuser",
}

for approval in pending:
    action_id = approval.action_id
    row = rows.get(action_id, {})
    decision = decisions.get(action_id)
    risk = decision.risk if decision is not None else None

    with st.container(key=f"sd-card-{approval.approval_id}"):
        # --- En-tête : badge, ids en mono, chrono ---
        theme.render(
            '<div class="sd-card-head"><div class="sd-card-ids">'
            f'{theme.badge("EN ATTENTE", "amber")}'
            f'<span class="sd-id sd-mono">{theme.esc(action_id)}</span>'
            f'<span class="sd-id sd-mono">{theme.esc(approval.approval_id)}</span>'
            f"</div>{_chrono_badge(approval.expires_at)}</div>"
        )

        # --- Grande phrase ---
        theme.render(
            theme.action_sentence(
                row.get("agent_id"),
                row.get("action"),
                row.get("resource_id"),
                row.get("recipient"),
                big=True,
            )
        )

        # --- Badges de contexte ---
        context = ""
        if _is_external(row.get("recipient")):
            context += theme.badge("destinataire externe", "amber")
        taint_sources = row.get("taint_sources") or []
        if taint_sources:
            context += theme.badge(
                "session contaminée par " + ", ".join(taint_sources), "amber"
            )
        if risk is not None:
            level, level_tone = theme.risk_level(risk.score)
            context += theme.badge(f"risque IA {level}", level_tone)
        if context:
            theme.render(f'<div class="sd-badges">{context}</div>')

        # --- Deux colonnes : pourquoi | avis IA ---
        col_left, col_right = st.columns(2, gap="large")

        with col_left:
            theme.panel_title("Pourquoi une validation humaine est demandée")
            rule_ids = decision.rule_ids if decision is not None else []
            if rule_ids:
                theme.render("".join(theme.rule_line(rid) for rid in rule_ids))
            else:
                theme.render('<div class="sd-muted">Aucune règle enregistrée.</div>')

            agent_reason = row.get("reason")
            if agent_reason:
                theme.render(
                    '<div class="sd-quote">'
                    '<div class="sd-quote-h">Ce que l’agent dit vouloir faire</div>'
                    f"{theme.esc(agent_reason)}</div>"
                )

        with col_right:
            if risk is None:
                ai_body = '<div class="sd-ai-text">Aucun avis IA pour cette action.</div>'
            else:
                level, level_tone = theme.risk_level(risk.score)
                if risk.score is None:
                    gauge = '<div class="sd-ai-score">Score indisponible</div>'
                else:
                    pct = max(0.0, min(100.0, float(risk.score) * 100))
                    gauge = (
                        f'<div class="sd-gauge"><div class="sd-gauge-fill sd-{level_tone}" '
                        f'style="width:{pct:.0f}%"></div></div>'
                        f'<div class="sd-ai-score">Score : {risk.score:.2f} / 1</div>'
                    )
                summary = (
                    f'<div class="sd-ai-text">{theme.esc(risk.summary)}</div>'
                    if risk.summary
                    else ""
                )
                signals = "".join(theme.badge(s, "violet") for s in risk.signals)
                signals_html = f'<div class="sd-badges">{signals}</div>' if signals else ""
                ai_body = (
                    f'<div class="sd-ai-level sd-{level_tone}">Risque {theme.esc(level)}</div>'
                    f"{gauge}{summary}{signals_html}"
                )
            theme.render(
                '<div class="sd-ai"><div class="sd-ai-h">🤖 Avis IA, non décisionnel</div>'
                f"{ai_body}"
                '<div class="sd-ai-foot">L’IA éclaire la décision ; elle ne peut ni autoriser ni bloquer.</div>'
                "</div>"
            )

        # --- Formulaire de décision ---
        with st.form(f"decide-{approval.approval_id}"):
            choice = st.radio(
                "Décision",
                _DECISION_OPTIONS,
                index=None,
                format_func=lambda c: _DECISION_LABELS[c],
                horizontal=True,
            )
            justification = st.text_area(
                "Justification (10 caractères minimum)",
                placeholder="Ex. : l’auditeur externe est mandaté par la direction, le partage en lecture seule est validé.",
            )
            submitted = st.form_submit_button(
                "Envoyer la décision", type="primary", width="stretch"
            )

        if submitted:
            if choice is None:
                st.error("Choisis une décision avant d'envoyer.")
            elif len(justification.strip()) < 10:
                st.error("Justification trop courte : 10 caractères minimum.")
            else:
                try:
                    result = client.decide(
                        approval.approval_id, choice, justification.strip()
                    )
                except NotImplementedError:
                    st.error(
                        "Mode local : la décision doit passer par le Gateway "
                        "(lance la console avec CONSOLE_MODE=http)."
                    )
                except DecideError as exc:
                    st.error(str(exc))
                except Exception as exc:
                    st.error(f"Gateway injoignable ou erreur de lecture : {exc}")
                else:
                    final_status = result.get("status", "décision enregistrée")
                    st.session_state["approval_success"] = (
                        f"Décision envoyée. Statut final : {final_status}"
                    )
                    st.rerun()
