"""Thème et briques visuelles partagées de la console (sombre, produit SaaS sécurité).

Uniquement Streamlit + HTML/CSS injectés avec st.markdown(unsafe_allow_html=True).

SÉCURITÉ (XSS) : tout texte issu des données (raison de l'agent, noms de fichiers,
e-mails, identifiants, payloads, messages d'erreur) passe par esc() / html.escape()
avant d'entrer dans du HTML. Un agent manipulé pourrait sinon injecter du HTML ou
du JavaScript via sa « raison ».
Convention : les fonctions de ce module qui renvoient ou rendent du HTML escapent
elles-mêmes leurs arguments texte. Ne jamais pré-échapper une valeur avant de la
leur passer (double échappement). Seuls les arguments nommés `*_html` sont du HTML
déjà construit par ce module.
"""

from __future__ import annotations

import html
import os
from datetime import datetime

import streamlit as st

from console.client import DEFAULT_GATEWAY_URL, ENV_CONSOLE_MODE, ENV_GATEWAY_URL
from console.labels import RULE_LABELS, action_label

# --- Palette -------------------------------------------------------------------

TONE_COLORS = {
    "green": "#22C55E",  # autorisé
    "amber": "#F5A524",  # validation humaine
    "red": "#F04452",  # bloqué
    "violet": "#A78BFA",  # IA
    "cyan": "#22D3EE",
    "indigo": "#7C8CFF",
    "neutral": "#8B97B4",
}

# --- Traductions affichées -----------------------------------------------------

VERDICT_LABELS = {
    "ALLOW": "Autorisé",
    "REVIEW": "Validation humaine",
    "DENY": "Bloqué",
}
VERDICT_TONES = {"ALLOW": "green", "REVIEW": "amber", "DENY": "red"}

STATUS_LABELS = {
    "EXECUTED": "Exécutée",
    "PENDING_REVIEW": "En attente",
    "DENIED": "Refusée",
    "EXPIRED": "Expirée",
    "FAILED": "Échec",
}
STATUS_TONES = {
    "EXECUTED": "green",
    "PENDING_REVIEW": "amber",
    "DENIED": "red",
    "EXPIRED": "neutral",
    "FAILED": "red",
}

EVENT_LABELS = {
    "REQUESTED": "Demande reçue",
    "DECIDED": "Décision des règles",
    "APPROVAL_DECIDED": "Décision humaine",
    "EXECUTED": "Exécutée",
    "BLOCKED": "Bloquée",
    "EXPIRED": "Expirée",
}
EVENT_TONES = {
    "REQUESTED": "cyan",
    "DECIDED": "indigo",
    "APPROVAL_DECIDED": "amber",
    "EXECUTED": "green",
    "BLOCKED": "red",
    "EXPIRED": "neutral",
}

# --- Échappement ---------------------------------------------------------------


def esc(value) -> str:
    """Échappe une valeur pour le HTML (texte ET attributs).

    Aplatit aussi les retours à la ligne : une ligne vide dans un bloc HTML
    interromprait le bloc côté Markdown et laisserait le reste être interprété."""
    if value is None:
        return ""
    return html.escape(" ".join(str(value).split()), quote=True)


def _raw(value):
    """Valeur d'un Enum (.value) ou la valeur elle-même."""
    return getattr(value, "value", value)


def _tone(tone: str | None) -> str:
    return tone if tone in TONE_COLORS else "neutral"


def render(markup: str) -> None:
    """Injecte du HTML déjà construit (et déjà échappé) dans la page."""
    st.markdown(markup, unsafe_allow_html=True)


# --- CSS global ----------------------------------------------------------------


def _rgba(hex_color: str, alpha: float) -> str:
    h = hex_color.lstrip("#")
    r, g, b = (int(h[i : i + 2], 16) for i in (0, 2, 4))
    return f"rgba({r},{g},{b},{alpha})"


def _tone_css() -> str:
    """Une classe .sd-<ton> qui définit les variables de couleur de sens."""
    rules = []
    for name, color in TONE_COLORS.items():
        rules.append(
            f".sd-{name}{{--tone:{color};--tone-bg:{_rgba(color, 0.12)};"
            f"--tone-bd:{_rgba(color, 0.4)};--tone-glow:{_rgba(color, 0.5)};}}"
        )
    return "".join(rules)


_BASE_CSS = r"""
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

:root{--bg:#0A0F1E;--panel:#111A2E;--panel2:#16213A;--border:#24324F;--text:#E7ECF5;--muted:#8B97B4;}

/* ---------- Fond, typo, chrome Streamlit ---------- */
.stApp,[data-testid="stApp"]{
  background:
    radial-gradient(900px 520px at 0% 0%, rgba(124,140,255,.18), transparent 62%),
    radial-gradient(900px 520px at 100% 0%, rgba(34,211,238,.13), transparent 62%),
    #0A0F1E !important;
  background-attachment:fixed !important;
  font-family:'Inter',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;
  color:#E7ECF5;
}
[data-testid="stHeader"]{background:transparent;}
[data-testid="stMainBlockContainer"],.block-container{padding-top:2rem;max-width:1280px;}
footer{visibility:hidden;}
[data-testid="stSidebar"]{background:#0D1426;border-right:1px solid #24324F;}
div[data-testid="stElementContainer"]:has(> div > [data-testid="stMarkdownContainer"] > style){display:none;}
.sd-mono,.sd-mono *{font-family:'JetBrains Mono',ui-monospace,SFMono-Regular,Menlo,Consolas,monospace !important;}

/* ---------- Hero ---------- */
.sd-hero{padding:4px 0 14px 0;}
.sd-kicker{font-size:.74rem;font-weight:700;letter-spacing:.18em;text-transform:uppercase;color:#7C8CFF;margin-bottom:8px;}
.sd-title{display:inline-block;max-width:100%;font-size:2.35rem;line-height:1.15;font-weight:800;letter-spacing:-.02em;
  background:linear-gradient(90deg,#FFFFFF 15%,#22D3EE 100%);-webkit-background-clip:text;background-clip:text;
  -webkit-text-fill-color:transparent;color:transparent;}
.sd-sub{color:#8B97B4;font-size:1.02rem;margin-top:10px;max-width:900px;line-height:1.55;}

/* ---------- Bandeau de mode ---------- */
.sd-mode{display:inline-flex;align-items:center;gap:8px;padding:5px 14px;border-radius:999px;font-size:.8rem;font-weight:600;
  color:var(--tone);background:var(--tone-bg);border:1px solid var(--tone-bd);margin-bottom:18px;}
.sd-dot{width:8px;height:8px;border-radius:50%;background:var(--tone);box-shadow:0 0 10px var(--tone);}

/* ---------- Sections ---------- */
.sd-section{margin:26px 0 12px 0;}
.sd-h2{font-size:1.15rem;font-weight:700;color:#E7ECF5;letter-spacing:-.01em;}
.sd-muted{color:#8B97B4;font-size:.9rem;margin-top:3px;}
.sd-panel-title{font-size:.76rem;font-weight:700;letter-spacing:.09em;text-transform:uppercase;color:#8B97B4;margin:4px 0 10px 0;}

/* ---------- KPI ---------- */
.sd-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin:6px 0 10px 0;}
.sd-kpi{position:relative;overflow:hidden;background:linear-gradient(180deg,#16213A,#111A2E);border:1px solid #24324F;
  border-radius:16px;padding:16px 18px 16px 24px;}
.sd-kpi::before{content:"";position:absolute;left:0;top:0;bottom:0;width:5px;background:var(--tone);box-shadow:0 0 18px var(--tone-glow);}
.sd-kpi-label{color:#8B97B4;font-size:.76rem;font-weight:600;letter-spacing:.05em;text-transform:uppercase;}
.sd-kpi-value{font-size:2.3rem;font-weight:800;line-height:1.1;margin-top:4px;color:#E7ECF5;}
.sd-kpi-hint{color:#8B97B4;font-size:.78rem;margin-top:2px;}

/* ---------- Badges et étiquettes ---------- */
.sd-badge{display:inline-flex;align-items:center;gap:6px;padding:2px 10px;border-radius:999px;font-size:.74rem;font-weight:600;
  line-height:1.5;color:var(--tone);background:var(--tone-bg);border:1px solid var(--tone-bd);white-space:nowrap;}
.sd-badges{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0 4px 0;}
.sd-tag{display:inline-block;flex:0 0 auto;padding:1px 8px;border-radius:6px;font-size:.72rem;font-weight:600;color:#E7ECF5;
  background:#1B2946;border:1px solid #24324F;white-space:nowrap;}

/* ---------- Cartes ---------- */
.sd-card.sd-toned{max-width:720px !important;}
div[data-testid="stElementContainer"]:has(.sd-card.sd-toned){margin-bottom:28px;}.sd-card{background:linear-gradient(180deg,#16213A,#111A2E);border:1px solid #24324F;border-radius:16px;padding:18px 20px;}
.sd-card.sd-toned{border-color:var(--tone-bd);box-shadow:0 0 0 1px var(--tone-bd) inset,0 10px 34px -14px var(--tone-glow);}
.sd-state{display:flex;align-items:center;gap:16px;}
.sd-state-icon{font-size:2rem;line-height:1;}
.sd-state-t{font-size:1.45rem;font-weight:800;color:var(--tone);line-height:1.2;}
.sd-state-d{color:#8B97B4;font-size:.92rem;margin-top:4px;}
.sd-kv{color:#8B97B4;font-size:.8rem;margin-top:10px;}
.sd-kv b{color:#E7ECF5;font-weight:600;}

[class*="st-key-sd-card"]{background:linear-gradient(180deg,#16213A,#111A2E);border:1px solid #24324F;border-radius:18px;
  padding:20px 22px;margin-bottom:10px;}
.sd-card-head{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;}
.sd-card-ids{display:flex;align-items:center;gap:10px;flex-wrap:wrap;}
.sd-id{color:#8B97B4;font-size:.8rem;}

/* ---------- Phrase d'action ---------- */
.sd-sentence{font-size:1rem;line-height:1.6;color:#E7ECF5;}
.sd-sentence.sd-big{font-size:1.5rem;font-weight:600;line-height:1.45;margin:14px 0 2px 0;}
.sd-agent{font-weight:700;}
.sd-verb{color:#F5A524;font-weight:700;}
.sd-file{color:#22D3EE;font-size:.92em;}
.sd-arrow{color:#8B97B4;margin:0 4px;}
.sd-recipient{font-weight:600;}

/* ---------- Règles, citation ---------- */
.sd-rule{display:flex;gap:10px;align-items:flex-start;padding:9px 0;border-bottom:1px solid rgba(36,50,79,.55);font-size:.92rem;line-height:1.45;}
.sd-rule:last-of-type{border-bottom:none;}
.sd-quote{margin:14px 0 18px 0;padding:12px 16px;border-left:3px solid #7C8CFF;background:rgba(124,140,255,.07);
  border-radius:0 12px 12px 0;color:#E7ECF5;font-style:italic;line-height:1.5;}
.sd-quote-h{font-style:normal;font-size:.7rem;font-weight:700;letter-spacing:.09em;text-transform:uppercase;color:#8B97B4;margin-bottom:4px;}

/* ---------- Avis IA ---------- */
.sd-ai{background:linear-gradient(180deg,rgba(167,139,250,.15),rgba(167,139,250,.05));border:1px solid rgba(167,139,250,.42);
  border-radius:16px;padding:16px 18px;margin-bottom:18px;}
.sd-ai-h{font-weight:700;color:#A78BFA;margin-bottom:10px;}
.sd-ai-level{font-size:1.3rem;font-weight:800;color:var(--tone);}
.sd-gauge{height:8px;border-radius:999px;background:#0E1627;border:1px solid #24324F;overflow:hidden;margin:8px 0 6px 0;}
.sd-gauge-fill{height:100%;border-radius:999px;background:var(--tone);box-shadow:0 0 12px var(--tone-glow);}
.sd-ai-score{color:#8B97B4;font-size:.8rem;}
.sd-ai-text{margin:10px 0 0 0;line-height:1.5;font-size:.92rem;}
.sd-ai-foot{margin-top:14px;font-size:.78rem;color:#8B97B4;border-top:1px solid rgba(167,139,250,.25);padding-top:10px;}

/* ---------- Tableau ---------- */
.sd-table-wrap{overflow-x:auto;border:1px solid #24324F;border-radius:16px;background:linear-gradient(180deg,#16213A,#111A2E);}
.sd-table{width:100%;border-collapse:collapse;font-size:.82rem;}
.sd-table th{text-align:left;padding:10px 10px !important;color:#8B97B4;font-size:.68rem;letter-spacing:.08em;text-transform:uppercase;
  font-weight:600;border:none !important;border-bottom:1px solid #24324F !important;white-space:nowrap;background:transparent !important;}
.sd-table td{padding:10px 10px !important;border:none !important;border-bottom:1px solid rgba(36,50,79,.6) !important;vertical-align:middle;background:transparent !important;}
.sd-table td.sd-nw{white-space:nowrap;}
.sd-table td.sd-mono{font-size:.78rem;}
.sd-table .sd-rules{display:flex;flex-wrap:wrap;gap:4px;max-width:150px;}
.sd-table tbody tr:last-child td{border-bottom:none !important;}
.sd-table tbody tr:hover td{background:rgba(124,140,255,.06) !important;}
.sd-cell-badges{display:flex;flex-wrap:wrap;gap:6px;}

/* ---------- Chaîne de preuves ---------- */
.sd-chain{display:flex;align-items:stretch;overflow-x:auto;padding:14px 4px 20px 4px;}
.sd-chain::-webkit-scrollbar{height:8px;}
.sd-chain::-webkit-scrollbar-thumb{background:#24324F;border-radius:8px;}
.sd-block{flex:0 0 196px;background:linear-gradient(180deg,#16213A,#111A2E);border:1px solid #24324F;border-top:3px solid var(--tone);
  border-radius:14px;padding:12px 14px;}
.sd-block-n{font-size:.68rem;font-weight:700;letter-spacing:.12em;color:#7C8CFF;}
.sd-block-t{font-weight:700;margin:6px 0 2px 0;font-size:.92rem;}
.sd-block-a{color:#22D3EE;font-size:.78rem;}
.sd-block-h{color:#8B97B4;font-size:.72rem;margin-top:5px;}
.sd-link{flex:0 0 32px;align-self:center;height:3px;border-radius:2px;background:linear-gradient(90deg,#7C8CFF,#22D3EE);}
.sd-block.sd-broken{border-color:#F04452;box-shadow:0 0 0 1px #F04452,0 0 26px rgba(240,68,82,.65);
  background:linear-gradient(180deg,rgba(240,68,82,.24),rgba(240,68,82,.08));}
.sd-block.sd-ghost{border:1px dashed #F04452;border-top:3px dashed #F04452;background:rgba(240,68,82,.06);}
.sd-block.sd-ghost .sd-block-n,.sd-block.sd-ghost .sd-block-t{color:#F04452;}
.sd-link.sd-broken{background:#F04452;box-shadow:0 0 12px rgba(240,68,82,.7);}

/* ---------- Timeline ---------- */
.sd-timeline{position:relative;padding-left:4px;margin-top:4px;}
.sd-tl-item{position:relative;display:flex;gap:14px;padding:0 0 18px 0;}
.sd-tl-item::before{content:"";position:absolute;left:7px;top:20px;bottom:-4px;width:2px;background:linear-gradient(180deg,var(--tone-bd),rgba(36,50,79,.35));}
.sd-tl-item:last-child{padding-bottom:0;}
.sd-tl-item:last-child::before{display:none;}
.sd-tl-dot{flex:0 0 16px;width:16px;height:16px;border-radius:50%;background:var(--tone);margin-top:3px;
  box-shadow:0 0 0 4px var(--tone-bg),0 0 14px var(--tone-glow);}
.sd-tl-title{font-weight:700;}
.sd-tl-meta{color:#8B97B4;font-size:.78rem;margin-top:2px;}

/* ---------- Trajet d'une action (accueil) ---------- */
.sd-step{display:flex;gap:14px;align-items:flex-start;background:linear-gradient(180deg,#16213A,#111A2E);border:1px solid #24324F;
  border-radius:14px;padding:12px 16px;}
.sd-step-n{flex:0 0 32px;height:32px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-weight:800;
  color:var(--tone);background:var(--tone-bg);border:1px solid var(--tone-bd);}
.sd-step-t{font-weight:700;}
.sd-step-d{color:#8B97B4;font-size:.86rem;line-height:1.45;}
.sd-flow-arrow{text-align:center;color:#8B97B4;line-height:1;padding:5px 0;font-size:1.1rem;}

/* ---------- Activité récente ---------- */
.sd-activity{display:flex;flex-direction:column;gap:10px;}
.sd-act{display:flex;align-items:center;gap:14px;flex-wrap:wrap;background:linear-gradient(180deg,#16213A,#111A2E);
  border:1px solid #24324F;border-radius:14px;padding:12px 16px;}
.sd-act .sd-sentence{flex:1 1 340px;}
.sd-act-badges{display:flex;gap:8px;flex-wrap:wrap;}

/* ---------- Erreur ---------- */
.sd-error{border:1px solid rgba(240,68,82,.5);background:rgba(240,68,82,.1);border-radius:14px;padding:14px 18px;color:#FFB4BB;line-height:1.5;}

/* ---------- Widgets Streamlit ---------- */
button[data-testid^="stBaseButton"],[data-testid="stPageLink-NavLink"]{
  border-radius:12px;border:1px solid #24324F;background:linear-gradient(180deg,#16213A,#111A2E);color:#E7ECF5;font-weight:600;
  transition:border-color .15s,box-shadow .15s;}
button[data-testid^="stBaseButton"]:hover,[data-testid="stPageLink-NavLink"]:hover{
  border-color:#7C8CFF;box-shadow:0 0 0 1px #7C8CFF,0 8px 22px -10px rgba(124,140,255,.7);color:#FFFFFF;}
button[data-testid="stBaseButton-primary"],button[data-testid="stBaseButton-primaryFormSubmit"]{
  background:linear-gradient(90deg,#7C8CFF,#22D3EE);border:none;color:#0A0F1E;font-weight:700;}
button[data-testid="stBaseButton-primary"]:hover,button[data-testid="stBaseButton-primaryFormSubmit"]:hover{
  box-shadow:0 8px 26px -8px rgba(34,211,238,.7);color:#0A0F1E;}
[data-baseweb="input"],[data-baseweb="textarea"],[data-baseweb="select"]>div{
  background:#0E1627 !important;border:1px solid #24324F !important;border-radius:12px !important;}
[data-baseweb="input"] input,[data-baseweb="textarea"] textarea{background:transparent !important;color:#E7ECF5 !important;}
[data-testid="stForm"]{border:1px solid #24324F;border-radius:16px;background:rgba(10,15,30,.4);padding:18px 20px;}
[data-testid="stExpander"]{border:1px solid #24324F !important;border-radius:14px !important;background:rgba(17,26,46,.6);}
[data-testid="stAlert"]{border-radius:14px;border:1px solid #24324F;}
[data-testid="stCode"],[data-testid="stCode"] pre{border-radius:12px;}
[data-testid="stCode"]{border:1px solid #24324F;}
[data-testid="stRadio"] [role="radiogroup"]{gap:10px;}
[data-testid="stRadio"] [role="radiogroup"] label{background:#0E1627;border:1px solid #24324F;border-radius:12px;padding:8px 16px;}
[data-testid="stRadio"] [role="radiogroup"] label:hover{border-color:#7C8CFF;}
[data-testid="stRadio"] [role="radiogroup"] label:has(input:checked){border-color:#7C8CFF;background:rgba(124,140,255,.14);}
[data-testid="stAppDeployButton"]{display:none;}
[data-testid="stPageLink"]{margin-top:12px;}
"""

_CSS = " ".join((_BASE_CSS + _tone_css()).split())


def setup(page_title: str, icon: str = "🛡️") -> None:
    """À appeler en premier dans chaque page : config de page puis CSS global."""
    st.set_page_config(page_title=page_title, page_icon=icon, layout="wide")
    st.markdown(f"<style>{_CSS}</style>", unsafe_allow_html=True)
    st.markdown(NAV_CSS, unsafe_allow_html=True)


# --- Briques : badges ----------------------------------------------------------


def badge(
    text, tone: str = "neutral", *, mono: bool = False, title: str | None = None
) -> str:
    """Pilule colorée (HTML). `text` et `title` sont échappés ici."""
    cls = f"sd-badge sd-{_tone(tone)}" + (" sd-mono" if mono else "")
    title_attr = f' title="{esc(title)}"' if title else ""
    return f'<span class="{cls}"{title_attr}>{esc(text)}</span>'


def verdict_badge(verdict) -> str:
    v = str(_raw(verdict))
    return badge(VERDICT_LABELS.get(v, v), VERDICT_TONES.get(v, "neutral"))


def status_badge(status) -> str:
    s = str(_raw(status))
    return badge(STATUS_LABELS.get(s, s), STATUS_TONES.get(s, "neutral"))


def event_label(event_type) -> str:
    t = str(_raw(event_type))
    return EVENT_LABELS.get(t, t)


def event_tone(event_type) -> str:
    return EVENT_TONES.get(str(_raw(event_type)), "neutral")


# --- Briques : blocs rendus ----------------------------------------------------


def hero(kicker: str, title: str, subtitle: str = "") -> None:
    sub = f'<div class="sd-sub">{esc(subtitle)}</div>' if subtitle else ""
    render(
        '<div class="sd-hero">'
        f'<div class="sd-kicker">{esc(kicker)}</div>'
        f'<div role="heading" aria-level="1" class="sd-title">{esc(title)}</div>'
        f"{sub}</div>"
    )


def mode_banner() -> None:
    """Pastille verte en mode http, ambre en mode local."""
    mode = os.environ.get(ENV_CONSOLE_MODE, "local").strip().lower()
    if mode == "http":
        url = os.environ.get(ENV_GATEWAY_URL, DEFAULT_GATEWAY_URL)
        text, tone = f"Connecté au Gateway ({url})", "green"
    else:
        text, tone = "Mode local, décisions désactivées", "amber"
    render(
        f'<div class="sd-mode sd-{tone}"><span class="sd-dot"></span>{esc(text)}</div>'
    )


def section(title: str, subtitle: str = "") -> None:
    sub = f'<div class="sd-muted">{esc(subtitle)}</div>' if subtitle else ""
    render(
        '<div class="sd-section">'
        f'<div role="heading" aria-level="2" class="sd-h2">{esc(title)}</div>{sub}</div>'
    )


def panel_title(text: str) -> None:
    render(f'<div class="sd-panel-title">{esc(text)}</div>')


def kpis(items) -> None:
    """Grille de cartes KPI. Chaque item : (libellé, valeur, ton[, indice])."""
    cells = []
    for item in items:
        label, value, tone = item[0], item[1], item[2]
        hint = item[3] if len(item) > 3 else ""
        hint_html = f'<div class="sd-kpi-hint">{esc(hint)}</div>' if hint else ""
        cells.append(
            f'<div class="sd-kpi sd-{_tone(tone)}">'
            f'<div class="sd-kpi-label">{esc(label)}</div>'
            f'<div class="sd-kpi-value">{esc(value)}</div>{hint_html}</div>'
        )
    render('<div class="sd-kpis">' + "".join(cells) + "</div>")


def card(inner_html: str, tone: str | None = None) -> str:
    """Enveloppe de carte. `inner_html` doit déjà être du HTML sûr."""
    extra = f" sd-{_tone(tone)} sd-toned" if tone else ""
    return f'<div class="sd-card{extra}">{inner_html}</div>'


def error_box(exc) -> None:
    """Boîte d'erreur lisible, jamais une trace Python. Le message est échappé."""
    render(
        '<div class="sd-error" role="alert">'
        f"Gateway injoignable ou erreur de lecture : {esc(exc)}</div>"
    )


# --- Briques : fragments métier ------------------------------------------------


def action_sentence(
    agent, action, resource, recipient=None, *, big: bool = False
) -> str:
    """« agent veut <verbe> fichier → destinataire » (HTML, tout est échappé)."""
    cls = "sd-sentence sd-big" if big else "sd-sentence"
    out = (
        f'<div class="{cls}">'
        f'<span class="sd-agent">{esc(agent or "?")}</span> veut '
        f'<span class="sd-verb">{esc(action_label(action))}</span> '
        f'<span class="sd-file sd-mono">{esc(resource or "?")}</span>'
    )
    if recipient:
        out += (
            ' <span class="sd-arrow">→</span> '
            f'<span class="sd-recipient">{esc(recipient)}</span>'
        )
    return out + "</div>"


def rule_line(rule_id: str) -> str:
    """Une règle : id dans une étiquette + explication française."""
    explanation = RULE_LABELS.get(rule_id, "Règle non documentée")
    return (
        '<div class="sd-rule">'
        f'<span class="sd-tag sd-mono">{esc(rule_id)}</span>'
        f"<span>{esc(explanation)}</span></div>"
    )


def risk_level(score) -> tuple[str, str]:
    """(niveau en mots, ton) : élevé ≥ 0,7, moyen ≥ 0,4, faible sinon."""
    if score is None:
        return "inconnu", "neutral"
    if score >= 0.7:
        return "élevé", "red"
    if score >= 0.4:
        return "moyen", "amber"
    return "faible", "green"


def short(value, n: int = 8) -> str:
    return str(value or "")[:n]


def fmt_time(ts: str) -> str:
    """Heure (HH:MM:SS) d'un horodatage ISO 8601, ou le texte brut si illisible."""
    try:
        return datetime.fromisoformat(ts).strftime("%H:%M:%S")
    except (ValueError, TypeError):
        return str(ts)

NAV_CSS = """
<style>
/* Nom du produit et sous-titre au-dessus du menu */
[data-testid="stSidebarNav"]::before {
  content: "🛡️ Police Agents";
  display: block;
  font-size: 1.15rem;
  font-weight: 800;
  color: #E7ECF5;
  padding: 0.5rem 1rem 0;
}
[data-testid="stSidebarNavItems"]::before {
  content: "Gouvernance des agents IA";
  display: block;
  font-size: 0.75rem;
  color: #8B97B4;
  padding: 0 0.6rem 0.9rem;
}
/* On masque le nom de fichier... */
/* On masque tout le contenu d'origine du lien (nom de fichier)... */
a[data-testid="stSidebarNavLink"] > * { display: none !important; }
/* ...et on écrit le vrai titre directement sur le lien */
a[data-testid="stSidebarNavLink"]::after { font-size: 0.95rem; color: #E7ECF5; }
[data-testid="stSidebarNavItems"] > :nth-child(1) a[data-testid="stSidebarNavLink"]::after { content: "📊  Vue d'ensemble"; }
[data-testid="stSidebarNavItems"] > :nth-child(2) a[data-testid="stSidebarNavLink"]::after { content: "📋  Journal des actions"; }
[data-testid="stSidebarNavItems"] > :nth-child(3) a[data-testid="stSidebarNavLink"]::after { content: "🔒  Boîte noire · preuves"; }
[data-testid="stSidebarNavItems"] > :nth-child(4) a[data-testid="stSidebarNavLink"]::after { content: "⚖️  Décisions en attente"; } > span:last-child::after { content: "⚖️  Décisions en attente"; }
</style>
"""