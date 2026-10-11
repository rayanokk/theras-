"""Catalogue des FAITS du monde Theras (Forge — A).

Recopié de data/drive_seed.json, data/identities.json et policies/policies.yaml.
AUCUNE invention : c'est la source de vérité que l'oracle et le générateur utilisent.
Si ces fichiers changent, relancer `datagen.cli verify` pour détecter la dérive.

But : donner au générateur de quoi tirer des combinaisons valides (quel agent, quel
fichier, quel destinataire), et à l'oracle de quoi calculer les faits du moteur.
"""
from __future__ import annotations

# --- Fichiers du Drive (resource_id -> faits) -----------------------------------
# classification, trusted (fiabilité de la source), acl (agents autorisés).
FICHIERS: dict[str, dict] = {
    "Company_Brochure.pdf":        {"classification": "public",       "trusted": True,  "acl": ["agent-research", "agent-ops", "agent-assistant"]},
    "Press_Release_Q3.txt":        {"classification": "public",       "trusted": True,  "acl": ["agent-research", "agent-ops", "agent-assistant"]},
    "Product_Datasheet.pdf":       {"classification": "public",       "trusted": True,  "acl": ["agent-research", "agent-ops", "agent-assistant"]},
    "Public_Pricing.csv":          {"classification": "public",       "trusted": True,  "acl": ["agent-research", "agent-ops", "agent-assistant"]},
    "uploaded_cv.txt":             {"classification": "public",       "trusted": False, "acl": ["agent-research", "agent-ops", "agent-assistant"]},
    "Team_Roadmap.md":             {"classification": "internal",     "trusted": True,  "acl": ["agent-research", "agent-ops", "agent-assistant"]},
    "Meeting_Notes_0910.txt":      {"classification": "internal",     "trusted": True,  "acl": ["agent-research", "agent-ops", "agent-assistant"]},
    "Onboarding_Guide.pdf":        {"classification": "internal",     "trusted": True,  "acl": ["agent-research", "agent-ops", "agent-assistant"]},
    "vendor_notes.txt":            {"classification": "internal",     "trusted": False, "acl": ["agent-research", "agent-ops", "agent-assistant"]},
    "partner_invoice.pdf":         {"classification": "internal",     "trusted": False, "acl": ["agent-research", "agent-ops", "agent-assistant"]},
    "Confidential_Audit_Report.pdf": {"classification": "confidential", "trusted": True, "acl": ["agent-ops", "agent-assistant"]},
    "Q3_Financials.xlsx":          {"classification": "confidential", "trusted": True,  "acl": ["agent-ops", "agent-assistant"]},
    "Customer_List.csv":           {"classification": "confidential", "trusted": True,  "acl": ["agent-ops", "agent-assistant"]},
    "HR_Salaries.xlsx":            {"classification": "restricted",   "trusted": True,  "acl": ["agent-ops"]},
    "Security_Keys_Inventory.txt": {"classification": "restricted",   "trusted": True,  "acl": ["agent-ops"]},
}

# --- Agents (id -> droits par outil) --------------------------------------------
AGENTS: dict[str, dict[str, list[str]]] = {
    "agent-research":  {"google_drive": ["read_file", "list_files"]},
    "agent-ops":       {"google_drive": ["read_file", "list_files", "share_file", "delete_file"]},
    "agent-assistant": {"google_drive": ["read_file", "list_files", "share_file"], "mail": ["send_email"]},
}

# --- Domaines -------------------------------------------------------------------
INTERNAL_DOMAINS = ["acme.example"]
PARTNER_DOMAINS = ["partner.example"]
BLOCKED_DOMAINS = ["pastebin.example"]
EXTERNAL_DOMAIN = "external.example"   # domaine externe quelconque (ni interne, ni partenaire, ni bloqué)

# --- Catégories utiles pour la génération ---------------------------------------
SENSITIVE_ACTIONS = {"share_file", "delete_file", "send_email"}
ACTION_TOOL = {
    "read_file": "google_drive", "list_files": "google_drive", "share_file": "google_drive",
    "delete_file": "google_drive", "send_email": "mail",
}
# Les 3 documents à source non fiable (déclenchent le taint à la lecture).
UNTRUSTED = [rid for rid, f in FICHIERS.items() if not f["trusted"]]


def fichier(resource_id: str) -> dict | None:
    return FICHIERS.get(resource_id)


def agent_peut(agent: str, tool: str, action: str) -> bool:
    return action in AGENTS.get(agent, {}).get(tool, [])
