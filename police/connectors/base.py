# TODO: à déplacer dans contracts/models.py quand L l'aura créé.
"""Contrat 3 : interface `Connector` et modèle `ResourceInfo`.

`describe` renvoie des faits sans rien exécuter ; `execute` n'est appelé que
par le pipeline. Le connecteur rapporte le domaine du destinataire ; c'est le
moteur de règles qui décide s'il est interne, partenaire ou bloqué.
"""

from dataclasses import dataclass
from typing import Protocol


@dataclass
class ResourceInfo:
    """Faits sur une ressource, renvoyés par `Connector.describe`."""

    exists: bool
    classification: str  # public | internal | confidential | restricted | none
    owner: str | None
    acl: list[str]
    trusted: bool
    recipient_email: str | None  # share_file : recipient ; send_email : to
    recipient_domain: str | None  # partie après @, en minuscules


class Connector(Protocol):
    """Interface d'un outil (google_drive, mail)."""

    name: str  # "google_drive" ou "mail"

    def describe(self, action: str, resource_id: str, params: dict) -> ResourceInfo:
        """Renvoie des faits sur la ressource, sans rien exécuter."""
        ...

    def execute(self, action: str, resource_id: str, params: dict) -> dict:
        """Exécute l'action. Appelé uniquement par le pipeline."""
        ...
