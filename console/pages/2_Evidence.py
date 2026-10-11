"""Page Evidence : boîte noire, état de la chaîne, export, ancre."""

import streamlit as st

from console import theme
from console.client import get_client

theme.setup("Evidence — Police Agents", "⛓️")


@st.cache_resource
def _client():
    """Client partagé pour toute la session (une seule connexion)."""
    return get_client()


theme.hero(
    "Boîte noire",
    "Le registre notarial des agents",
    "Chaque étape est scellée dans une chaîne d’empreintes : modifier ou supprimer une "
    "preuve casse toute la suite, et cela se voit.",
)
theme.mode_banner()

try:
    client = _client()
    events = client.list_events()
    result = client.verify_chain()
    export_data = client.export_jsonl()
except Exception as exc:
    theme.error_box(exc)
    st.stop()

valid = bool(result["valid"])
broken_at = result["broken_at"]

# --- État de la chaîne -----------------------------------------------------
if valid:
    count = len(events)
    detail = (
        "Aucune preuve enregistrée pour l’instant."
        if count == 0
        else f"{count} preuve{'s' if count > 1 else ''} vérifiée{'s' if count > 1 else ''} : aucune altération détectée."
    )
    icon, title, tone = "✅", "Chaîne intacte", "green"
else:
    n = broken_at
    if n == 1:
        detail = "L’altération porte sur la première preuve."
    else:
        detail = f"L’altération porte sur la preuve {n} ou sur la preuve {n - 1}."
    icon, title, tone = "⛔", f"Chaîne rompue à la preuve {n}", "red"

theme.render(
    theme.card(
        '<div class="sd-state">'
        f'<div class="sd-state-icon">{icon}</div>'
        f'<div><div class="sd-state-t">{theme.esc(title)}</div>'
        f'<div class="sd-state-d">{theme.esc(detail)}</div></div></div>',
        tone,
    )
)

col_recheck, col_export, _spacer = st.columns([1, 1, 3])
with col_recheck:
    # Un clic relance le script : la vérification ci-dessus est refaite à neuf.
    if st.button("Revérifier", width="stretch"):
        st.toast("Chaîne revérifiée")
with col_export:
    st.download_button(
        "Export SIEM",
        data=export_data,
        file_name="evidence_export.jsonl",
        mime="application/x-ndjson",
        width="stretch",
    )


# --- La chaîne en visuel ---------------------------------------------------
def _chain_html(chain_events, broken) -> str:
    """Rangée de blocs reliés ; les blocs N et N-1 sont en rouge si la chaîne est rompue."""
    broken_seqs = set()
    if broken is not None:
        broken_seqs.add(broken)
        if broken > 1:
            broken_seqs.add(broken - 1)

    items = [("event", e) for e in chain_events]
    present = {e.seq for e in chain_events}
    if broken is not None and broken not in present:
        # Preuve supprimée : on matérialise le trou à sa place dans la chaîne.
        index = next((i for i, e in enumerate(chain_events) if e.seq > broken), len(chain_events))
        items.insert(index, ("ghost", broken))

    flagged = [kind == "ghost" or obj.seq in broken_seqs for kind, obj in items]

    parts = []
    for i, (kind, obj) in enumerate(items):
        if kind == "ghost":
            parts.append(
                '<div class="sd-block sd-ghost">'
                f'<div class="sd-block-n">PREUVE {theme.esc(obj)}</div>'
                '<div class="sd-block-t">Manquante</div>'
                '<div class="sd-block-h">Cette preuve a disparu de la chaîne.</div></div>'
            )
        else:
            bad = " sd-broken" if flagged[i] else ""
            parts.append(
                f'<div class="sd-block sd-{theme.event_tone(obj.type)}{bad}">'
                f'<div class="sd-block-n">PREUVE {theme.esc(obj.seq)}</div>'
                f'<div class="sd-block-t">{theme.esc(theme.event_label(obj.type))}</div>'
                f'<div class="sd-block-a sd-mono">{theme.esc(obj.action_id)}</div>'
                f'<div class="sd-block-h sd-mono">⛓ {theme.esc(theme.short(obj.prev_hash, 8))}</div>'
                f'<div class="sd-block-h sd-mono"># {theme.esc(theme.short(obj.hash, 8))}</div></div>'
            )
        if i < len(items) - 1:
            link_bad = " sd-broken" if (flagged[i] or flagged[i + 1]) else ""
            parts.append(f'<div class="sd-link{link_bad}"></div>')
    return '<div class="sd-chain">' + "".join(parts) + "</div>"


theme.section(
    "La chaîne en un coup d’œil",
    "Chaque bloc porte l’empreinte du précédent (⛓) et la sienne (#).",
)
if events:
    theme.render(_chain_html(events, None if valid else broken_at))
else:
    theme.render('<div class="sd-muted">Aucun événement : la chaîne est vide.</div>')

# --- Ancre -----------------------------------------------------------------
col_anchor, col_check = st.columns(2, gap="large")

with col_anchor:
    theme.section(
        "Ancre à conserver hors du système",
        "Notez ce numéro et cette empreinte ailleurs (papier, autre outil).",
    )
    if events:
        last = events[-1]
        st.write(f"Dernière preuve : n° {last.seq}")
        st.code(last.hash, language="text")
    else:
        st.write("Aucun événement : rien à ancrer pour l'instant.")

with col_check:
    theme.section(
        "Vérifier une ancre conservée",
        "Détecte une troncature ou une réécriture que la chaîne seule ne voit pas.",
    )
    with st.form("verify_anchor"):
        anchor_seq = st.number_input("Numéro de la preuve (seq)", min_value=1, step=1, value=1)
        anchor_hash = st.text_input("Empreinte conservée (hash)")
        submitted = st.form_submit_button("Vérifier l'ancre", width="stretch")

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

# --- Aide ------------------------------------------------------------------
with st.expander("Comment lire cette page ?"):
    st.markdown(
        "- **Une preuve** est un événement horodaté : demande reçue, décision des règles, "
        "décision humaine, exécution ou blocage.\n"
        "- **⛓** est le début de l’empreinte de la preuve précédente, **#** celui de sa propre "
        "empreinte. Si l’on modifie une preuve, son empreinte change et ne correspond plus au "
        "⛓ de la suivante.\n"
        "- **En rouge**, les preuves où la rupture est détectée : l’altération porte sur la "
        "preuve signalée ou sur la précédente. Un bloc en pointillés indique une preuve supprimée.\n"
        "- **L’ancre** est une copie du dernier numéro et de la dernière empreinte, gardée "
        "hors du système. Elle révèle ce que la chaîne seule ne peut pas voir : la suppression "
        "des dernières preuves (troncature) ou la réécriture complète du registre.\n"
        "- **Export SIEM** : un événement JSON par ligne, prêt à être ingéré par un outil de supervision."
    )
