# TODO: remplacer dict par les modèles de contracts/models.py quand ils existeront.
"""Interface abstraite de persistance pour la gouvernance d'agents.

Définit le contrat `Store` : actions, approbations, journal d'événements
append-only et sessions. Aucune implémentation ici.
"""

from abc import ABC, abstractmethod


class Store(ABC):
    """Contrat de stockage abstrait pour actions, approbations, événements et sessions."""

    @abstractmethod
    def put_action(self, action: dict) -> None:
        """Crée ou remplace (upsert) une action. Champs : action_id, agent_id, user_id, session_id, tool, action, resource_id, params, params_hash, verdict, status, rule_ids, risk, created_at."""
        ...

    @abstractmethod
    def get_action(self, action_id: str) -> dict | None:
        """Retourne l'action d'identifiant action_id, ou None si absente."""
        ...

    @abstractmethod
    def list_actions(self, status: str | None = None) -> list[dict]:
        """Liste les actions, filtrées par status si fourni."""
        ...

    @abstractmethod
    def put_approval(self, approval: dict) -> None:
        """Crée ou remplace (upsert) une approbation. Champs : approval_id, action_id, params_hash, status, expires_at, approver_id, decision, justification, decided_at."""
        ...

    @abstractmethod
    def get_approval(self, approval_id: str) -> dict | None:
        """Retourne l'approbation d'identifiant approval_id, ou None si absente."""
        ...

    @abstractmethod
    def list_approvals(self, status: str | None = None) -> list[dict]:
        """Liste les approbations, filtrées par status si fourni."""
        ...

    @abstractmethod
    def append_event(self, event: dict) -> None:
        """Ajoute un événement au journal append-only. Champs : seq, ts, type, action_id, payload, policy_version, prev_hash, hash."""
        ...

    @abstractmethod
    def list_events(self, action_id: str | None = None) -> list[dict]:
        """Liste les événements triés par seq croissant, filtrés par action_id si fourni."""
        ...

    @abstractmethod
    def get_session(self, session_id: str) -> dict | None:
        """Retourne la session d'identifiant session_id, ou None. Champs : session_id, tainted, taint_sources."""
        ...

    @abstractmethod
    def set_session(self, session: dict) -> None:
        """Crée ou met à jour une session. Champs : session_id, tainted, taint_sources."""
        ...
