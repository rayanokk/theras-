"""Connecteur mail simulé (contrat 3).

Aucun envoi réel : pas d'import de smtplib ni d'accès réseau. Les faits sur la
pièce jointe sont lus depuis une instance partagée de `DriveMock` (injection de
dépendance, pas de copie du seed), de sorte qu'une reclassification ou une
suppression côté Drive est immédiatement visible côté Mail.
"""

from datetime import datetime, timezone

from police.connectors.base import ResourceInfo
from police.connectors.drive_mock import DriveMock, _extract_domain

# Valeur conventionnelle de resource_id quand il n'y a pas de pièce jointe.
NO_ATTACHMENT = "none"


class MailMock:
    """Mail simulé : s'appuie sur un DriveMock partagé pour les pièces jointes."""

    name = "mail"

    def __init__(self, drive: DriveMock) -> None:
        self._drive = drive
        # Messages envoyés, en mémoire : {to, subject, body, attachment, ts}.
        self.outbox: list[dict] = []

    # ----------------------------------------------------------------- describe

    def describe(self, action: str, resource_id: str, params: dict) -> ResourceInfo:
        """Renvoie un ResourceInfo pour send_email. Ne modifie rien."""
        recipient_email = params.get("to")
        recipient_domain = _extract_domain(recipient_email)

        # Mail sans pièce jointe.
        if resource_id == NO_ATTACHMENT:
            return ResourceInfo(
                exists=True,
                classification="none",
                owner=None,
                acl=list(self._drive.agents),
                trusted=True,
                recipient_email=recipient_email,
                recipient_domain=recipient_domain,
            )

        # Pièce jointe : faits lus depuis le Drive partagé.
        f = self._drive.get_file(resource_id)
        if f is None:
            # Pièce jointe introuvable ou supprimée.
            return ResourceInfo(
                exists=False,
                classification="none",
                owner=None,
                acl=[],
                trusted=False,
                recipient_email=recipient_email,
                recipient_domain=recipient_domain,
            )

        return ResourceInfo(
            exists=True,
            classification=f["classification"],
            owner=f.get("owner"),
            acl=list(f.get("acl", [])),
            trusted=f.get("trusted", False),
            recipient_email=recipient_email,
            recipient_domain=recipient_domain,
        )

    # ------------------------------------------------------------------ execute

    def execute(self, action: str, resource_id: str, params: dict) -> dict:
        """Enregistre le message dans l'outbox. N'envoie aucun vrai mail."""
        to = params.get("to")
        attachment = None if resource_id == NO_ATTACHMENT else resource_id
        self.outbox.append(
            {
                "to": to,
                "subject": params.get("subject"),
                "body": params.get("body"),
                "attachment": attachment,
                "ts": datetime.now(timezone.utc).isoformat(),
            }
        )
        return {"sent_to": to, "attachment": attachment}
