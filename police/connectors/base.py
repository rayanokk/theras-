"""Contrat 3 : interface Connector (outils) et ResourceInfo.

Un connecteur expose un outil (google_drive ou mail). Il separe strictement
l'observation (`describe`, sans effet) de l'action (`execute`, avec effet). Seul
le pipeline (`police/gateway/pipeline.py`) importe les connecteurs et appelle
`execute` ; l'agent n'a ni import ni credentials vers eux.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from contracts.models import ResourceInfo


@runtime_checkable
class Connector(Protocol):
    """Protocole commun aux connecteurs d'outils (contrat 3)."""

    name: str  # "google_drive" ou "mail"

    def describe(
        self, action: str, resource_id: str, params: dict[str, Any]
    ) -> ResourceInfo:
        """Renvoie les faits sur la ressource SANS rien executer.

        Lecture seule : aucune ressource n'est partagee, supprimee, envoyee ni
        modifiee. Le pipeline s'appuie sur ces faits (classification, owner, acl,
        trusted, destinataire) pour decider via la politique.
        """
        ...

    def execute(
        self, action: str, resource_id: str, params: dict[str, Any]
    ) -> dict[str, Any]:
        """Realise effectivement l'action et renvoie son resultat.

        A n'appeler QUE par le pipeline, apres un verdict ALLOW (ou une REVIEW
        approuvee puis revalidee). Ne jamais appeler depuis l'agent ni avant la
        decision de la politique.
        """
        ...
