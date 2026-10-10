"""Console Police Agents — page d'accueil (Streamlit).

Lancer : streamlit run console/app.py
Mode choisi par CONSOLE_MODE (local par défaut, ou http) ; cf. console/client.py.
"""

import os

import streamlit as st

from console.client import ENV_CONSOLE_MODE, get_client

st.set_page_config(page_title="Police Agents — Console", layout="wide")
st.title("Police Agents — Console")

mode = os.environ.get(ENV_CONSOLE_MODE, "local").strip().lower()
st.caption(f"Mode actif : {mode}")


@st.cache_resource
def _client():
    """Client partagé pour toute la session (une seule connexion)."""
    return get_client()


try:
    client = _client()
    actions = client.list_actions()
    pending = len(client.list_pending_approvals())
except Exception as exc:
    st.error(f"Gateway injoignable ou erreur de lecture : {exc}")
    st.stop()

by_verdict = {"ALLOW": 0, "REVIEW": 0, "DENY": 0}
for decision in actions:
    verdict = decision.verdict.value
    if verdict in by_verdict:
        by_verdict[verdict] += 1

col_allow, col_review, col_deny, col_pending = st.columns(4)
col_allow.metric("Actions ALLOW", by_verdict["ALLOW"])
col_review.metric("Actions REVIEW", by_verdict["REVIEW"])
col_deny.metric("Actions DENY", by_verdict["DENY"])
col_pending.metric("Approbations en attente", pending)
