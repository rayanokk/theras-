"""Libellés français pour la console : actions et règles du moteur de décision.

Source des règles : .kiro/steering/contracts.md (partie 3). Les libellés sont
des explications courtes destinées à l'affichage, pas des définitions normatives.
"""

# Domaine interne de l'entreprise (le reste est externe).
INTERNAL_DOMAIN = "acme.example"

# Traduction des actions pour les phrases lisibles.
ACTION_LABELS = {
    "share_file": "partager",
    "send_email": "envoyer par mail",
    "delete_file": "supprimer",
    "read_file": "lire",
    "list_files": "lister",
}


def action_label(action: str | None) -> str:
    """Verbe français pour une action, ou l'action brute si inconnue."""
    if not action:
        return "agir sur"
    return ACTION_LABELS.get(action, action)


# Libellé français par règle (contrat, partie 3).
RULE_LABELS = {
    "R-DENY-01": "Clé inconnue ou identité déclarée différente de l'identité réelle",
    "R-DENY-02": "Outil ou action hors des droits de l'agent",
    "R-DENY-03": "Ressource inexistante, ou agent absent de l'ACL",
    "R-DENY-04": "Fichier restreint partagé ou envoyé hors de l'entreprise",
    "R-DENY-05": "Destinataire sur un domaine bloqué",
    "R-DENY-06": "Requête ou paramètres invalides",
    "R-REV-01": "Fichier confidentiel partagé ou envoyé à l'extérieur",
    "R-REV-02": "Session contaminée et action sensible",
    "R-REV-03": "Suppression de fichier",
    "R-REV-04": "Score de risque élevé, ou avis IA indisponible sur une action sensible",
    "R-REV-05": "Fichier confidentiel partagé ou envoyé en interne",
    "R-ALLOW-01": "Lecture ou liste, agent présent dans l'ACL",
    "R-ALLOW-02": "Fichier public (ou mail sans pièce jointe) partagé ou envoyé au partenaire",
    "R-ALLOW-03": "Mail interne, pièce jointe publique, interne ou absente",
    "R-ALLOW-04": "Fichier public ou interne partagé en interne",
}


def rule_label(rule_id: str) -> str:
    """Explication française d'une règle, au format « explication (R-XXX) »."""
    explanation = RULE_LABELS.get(rule_id, "Règle non documentée")
    return f"{explanation} ({rule_id})"
