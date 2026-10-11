"""Suivi de contamination (taint tracking) des sessions ET des agents.

Regle d'or 5 : quand un agent lit un document non fiable, sa session devient
`tainted` et le reste. Lire un document douteux ne peut que rendre le systeme
plus prudent, jamais plus permissif : il n'existe donc AUCUNE methode pour
nettoyer une session.

Le taint de session repose sur un session_id FOURNI PAR L'AGENT : un agent
manipule pourrait lire dans sess-1 puis agir dans sess-2 pour y echapper. On
ajoute donc un taint lie a l'IDENTITE REELLE de l'agent (issue de la cle API,
que l'agent ne peut pas changer), avec une duree de vie (TTL) pour qu'il ne
reste pas contamine a vie. Il est range dans le Store sous la cle "agent:<id>".

L'etat vit dans le Store (contrat 6) au format :
    session : {"tainted": bool, "taint_sources": [resource_id, ...]}
    agent   : idem + {"tainted_at": ISO 8601 UTC}
"""

from __future__ import annotations

from datetime import datetime, timezone

from police.store.base import Store

# Prefixe de cle pour le taint lie a l'identite (hors de l'espace des session_id
# agent, qui commencent par "sess-").
AGENT_KEY_PREFIX = "agent:"


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

    # ------------------------------------------------------------ taint agent

    def mark_agent(
        self, agent_id: str, resource_id: str, now: datetime | None = None
    ) -> None:
        """Contamine l'identite reelle de l'agent et repousse l'horodatage.

        Range sous la cle "agent:<id>". Un nouveau marquage repousse tainted_at
        (le TTL repart), et ajoute la ressource sans doublon.
        """
        when = now or datetime.now(timezone.utc)
        key = AGENT_KEY_PREFIX + agent_id
        record = self._store.get_session(key)
        sources = list(record.get("taint_sources", [])) if record else []
        if resource_id not in sources:
            sources.append(resource_id)
        self._store.set_session(
            {
                "session_id": key,
                "tainted": True,
                "taint_sources": sources,
                "tainted_at": when.isoformat(),
            }
        )

    def is_agent_tainted(
        self, agent_id: str, ttl_minutes: int, now: datetime | None = None
    ) -> bool:
        """True si l'agent a ete contamine il y a au plus ttl_minutes."""
        record = self._store.get_session(AGENT_KEY_PREFIX + agent_id)
        if record is None or not record.get("tainted_at"):
            return False
        try:
            tainted_at = datetime.fromisoformat(record["tainted_at"])
        except (TypeError, ValueError):
            return False
        when = now or datetime.now(timezone.utc)
        age = when - tainted_at
        return age.total_seconds() <= ttl_minutes * 60

    def agent_taint_sources(self, agent_id: str) -> list[str]:
        """Ressources ayant contamine l'identite de l'agent. Inconnu -> []."""
        record = self._store.get_session(AGENT_KEY_PREFIX + agent_id)
        if record is None:
            return []
        return list(record.get("taint_sources", []))
