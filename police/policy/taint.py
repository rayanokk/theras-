"""Suivi de contamination (taint tracking) des sessions.

Regle d'or 5 : quand un agent lit un document non fiable, sa session devient
`tainted` et le reste. Lire un document douteux ne peut que rendre le systeme
plus prudent, jamais plus permissif : il n'existe donc AUCUNE methode pour
nettoyer une session.

L'etat vit dans le Store (contrat 6) au format :
    {"tainted": bool, "taint_sources": [resource_id, ...]}
"""

from __future__ import annotations

from police.store.base import Store


class TaintTracker:
    """Lit et met a jour l'etat de contamination des sessions via le Store."""

    def __init__(self, store: Store) -> None:
        self._store = store

    def is_tainted(self, session_id: str) -> bool:
        """True si la session est contaminee. Session inconnue -> False."""
        session = self._store.get_session(session_id)
        if session is None:
            return False
        return bool(session.get("tainted", False))

    def taint_sources(self, session_id: str) -> list[str]:
        """Ressources ayant contamine la session. Session inconnue -> []."""
        session = self._store.get_session(session_id)
        if session is None:
            return []
        return list(session.get("taint_sources", []))

    def mark(self, session_id: str, resource_id: str) -> None:
        """Marque la session contaminee et ajoute la ressource, sans doublon."""
        session = self._store.get_session(session_id)
        sources = list(session.get("taint_sources", [])) if session else []
        if resource_id not in sources:
            sources.append(resource_id)
        self._store.set_session(
            {
                "session_id": session_id,
                "tainted": True,
                "taint_sources": sources,
            }
        )
