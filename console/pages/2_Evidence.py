"""Page Evidence : journal d'événements, vérification de chaîne, export, ancre."""

import streamlit as st

from console.client import get_client

st.set_page_config(page_title="Evidence — Police Agents", layout="wide")
st.title("Evidence")


@st.cache_resource
def _client():
    """Client partagé pour toute la session (une seule connexion)."""
    return get_client()


try:
    client = _client()
    events = client.list_events()
except Exception as exc:
    st.error(f"Gateway injoignable ou erreur de lecture : {exc}")
    st.stop()

# --- Tableau des événements ------------------------------------------------
st.dataframe(
    [
        {
            "seq": e.seq,
            "ts": e.ts,
            "type": e.type.value,
            "action_id": e.action_id,
            "hash": e.hash[:12],
        }
        for e in events
    ],
    use_container_width=True,
)

# --- Vérification de la chaîne ---------------------------------------------
if st.button("Vérifier la chaîne"):
    try:
        result = client.verify_chain()
    except Exception as exc:
        st.error(f"Gateway injoignable ou erreur de lecture : {exc}")
        st.stop()
        
    if result["valid"]:
        st.success("Chaîne de preuves intacte : aucune rupture détectée.")
    else:
        n = result["broken_at"]
        if n == 1:
            st.error("Chaîne rompue à l'événement 1 : le premier événement a été altéré.")
        else:
            st.error(
                f"Chaîne rompue à l'événement {n}. "
                f"L'altération porte sur l'événement {n} ou sur l'événement {n - 1}."
            )

# --- Export JSONL ----------------------------------------------------------
try:
    export_data = client.export_jsonl()
except Exception as exc:
    st.error(f"Gateway injoignable ou erreur de lecture : {exc}")
    st.stop()
st.download_button(
    "Télécharger l'export JSONL",
    data=export_data,
    file_name="evidence_export.jsonl",
    mime="application/x-ndjson",
)

# --- Ancre à conserver hors système ----------------------------------------
st.subheader("Ancre à conserver hors système")
if events:
    last = events[-1]
    st.write(f"Dernier seq : {last.seq}")
    st.code(last.hash, language="text")
else:
    st.write("Aucun événement : rien à ancrer pour l'instant.")

# --- Vérifier une ancre conservée ------------------------------------------
st.subheader("Vérifier une ancre conservée")
with st.form("verify_anchor"):
    anchor_seq = st.number_input("seq", min_value=1, step=1, value=1)
    anchor_hash = st.text_input("hash")
    submitted = st.form_submit_button("Vérifier l'ancre")

if submitted:
    # Comparaison faite ici, à partir de client.list_events().
    by_seq = {e.seq: e for e in events}
    event = by_seq.get(int(anchor_seq))
    if event is None:
        st.error(f"Troncature détectée : l'événement {int(anchor_seq)} a disparu.")
    elif event.hash != anchor_hash.strip():
        st.error(f"Réécriture détectée à l'événement {int(anchor_seq)}.")
    else:
        st.success("Ancre confirmée.")
