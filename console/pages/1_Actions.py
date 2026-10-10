"""Page Actions : tableau filtrable des décisions, avec détail par action."""

import streamlit as st

from console.client import get_client

st.set_page_config(page_title="Actions — Police Agents", layout="wide")
st.title("Actions")


@st.cache_resource
def _client():
    """Client partagé pour toute la session (une seule connexion)."""
    return get_client()


try:
    client = _client()
    decisions = client.list_actions()
    rows_all = client.list_action_rows()
except Exception as exc:
    st.error(f"Gateway injoignable ou erreur de lecture : {exc}")
    st.stop()

# --- Filtres ---------------------------------------------------------------
verdicts = sorted({d.verdict.value for d in decisions})
statuses = sorted({d.status.value for d in decisions})

col_v, col_s = st.columns(2)
verdict_filter = col_v.multiselect("Verdict", verdicts, default=verdicts)
status_filter = col_s.multiselect("Statut", statuses, default=statuses)

filtered = [
    d
    for d in decisions
    if d.verdict.value in verdict_filter and d.status.value in status_filter
]

# --- Tableau ---------------------------------------------------------------
# agent / outil / action / ressource / destinataire viennent de la requête
# imbriquée : on les obtient via list_action_rows() (jamais SQLiteStore).
kept_ids = {d.action_id for d in filtered}
rows = [r for r in rows_all if r["action_id"] in kept_ids]
st.dataframe(
    [
        {
            "action_id": r["action_id"],
            "agent": r["agent_id"],
            "outil": r["tool"],
            "action": r["action"],
            "ressource": r["resource_id"],
            "destinataire": r["recipient"],
            "verdict": r["verdict"],
            "statut": r["status"],
            "règles": r["rule_ids"],
        }
        for r in rows
    ],
    use_container_width=True,
)

# --- Détail par action -----------------------------------------------------
for d in filtered:
    with st.expander(f"{d.action_id} — {d.verdict.value} / {d.status.value}"):
        st.subheader("Raisons")
        if d.reasons:
            for reason in d.reasons:
                st.write(f"- {reason}")
        else:
            st.write("Aucune raison enregistrée.")

        st.subheader("Événements")
        try:
            events = client.list_events(action_id=d.action_id)
        except Exception as exc:
            st.error(f"Gateway injoignable ou erreur de lecture : {exc}")
            st.stop()
        st.dataframe(
            [
                {
                    "seq": e.seq,
                    "ts": e.ts,
                    "type": e.type.value,
                    "hash": e.hash[:12],
                }
                for e in events
            ],
            use_container_width=True,
        )
