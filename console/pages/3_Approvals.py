"""Page Approvals : « Human Decision Center ».

Chaque approbation en attente est présentée comme une carte avec le contexte de
l'action, les règles/raisons, l'avis IA éventuel, le temps restant, et un
formulaire de décision. Tout passe par get_client().
"""

from datetime import datetime, timezone

import streamlit as st

from console.client import DecideError, get_client

st.set_page_config(page_title="Approvals — Police Agents", layout="wide")
st.title("Human Decision Center")


@st.cache_resource
def _client():
    """Client partagé pour toute la session (une seule connexion)."""
    return get_client()


try:
    client = _client()
    pending = client.list_pending_approvals()
    decisions = {d.action_id: d for d in client.list_actions()}
    rows = {r["action_id"]: r for r in client.list_action_rows()}
except Exception as exc:
    st.error(f"Gateway injoignable ou erreur de lecture : {exc}")
    st.stop()

# Message de succès conservé à travers le st.rerun().
if "approval_success" in st.session_state:
    st.success(st.session_state.pop("approval_success"))

if not pending:
    st.info("Aucune décision en attente.")
    st.stop()


def _title_for(action_id: str) -> str:
    """Titre lisible à partir de la ligne d'action, avec destinataire si connu."""
    row = rows.get(action_id)
    if row is None:
        return action_id
    agent = row.get("agent_id") or "?"
    action = row.get("action") or "?"
    resource = row.get("resource_id") or "?"
    title = f"{action_id} · {agent} veut {action} {resource}"
    recipient = row.get("recipient")
    if recipient:
        title += f" → {recipient}"
    return title


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


_DECISIONS = ["approve", "reject", "request_info"]


for approval in pending:
    action_id = approval.action_id
    with st.container(border=True):
        st.subheader(_title_for(action_id))

        row = rows.get(action_id, {})
        decision = decisions.get(action_id)

        # --- Ce que l'agent dit vouloir faire ---
        agent_reason = row.get("reason")
        if agent_reason:
            st.markdown("**Ce que l'agent dit vouloir faire**")
            st.write(agent_reason)

        # --- Session contaminée ---
        taint_sources = row.get("taint_sources") or []
        if taint_sources:
            st.warning("Session contaminée par : " + ", ".join(taint_sources))

        # --- Règles et raisons ---
        if decision is not None:
            st.markdown("**Règles**")
            if decision.rule_ids:
                for rule in decision.rule_ids:
                    st.write(f"- {rule}")
            else:
                st.write("- (aucune)")

            st.markdown("**Raisons**")
            if decision.reasons:
                for reason in decision.reasons:
                    st.write(f"- {reason}")
            else:
                st.write("- (aucune)")

            # --- Avis IA (non décisionnel) ---
            if decision.risk is not None:
                signals = ", ".join(decision.risk.signals) or "(aucun signal)"
                summary = decision.risk.summary or "(aucun résumé)"
                st.info(
                    f"**Avis IA, non décisionnel**\n\n"
                    f"{summary}\n\n"
                    f"Score : {decision.risk.score}\n\n"
                    f"Signaux : {signals}"
                )

        # --- Temps restant ---
        remaining = _remaining_minutes(approval.expires_at)
        if remaining is None:
            st.write("Expiration : inconnue.")
        elif remaining <= 0:
            st.markdown(":red[**Expirée**]")
        elif remaining < 2:
            st.markdown(f":red[**Expire dans {remaining:.1f} min**]")
        else:
            st.write(f"Expire dans {remaining:.0f} min")

        # --- Formulaire de décision ---
        with st.form(f"decide-{approval.approval_id}"):
            choice = st.radio("Décision", _DECISIONS, horizontal=True)
            justification = st.text_area("Justification (10 caractères minimum)")
            submitted = st.form_submit_button("Envoyer la décision")

        if submitted:
            if len(justification.strip()) < 10:
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
