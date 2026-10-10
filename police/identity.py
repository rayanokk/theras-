"""Registre d'identites : cle API -> identite reelle (contrat, section 1.2).

Le fichier d'identites (data/identities.json) ne contient que le NOM de la
variable d'environnement qui porte la cle (`key_env`), jamais sa valeur. La
valeur reelle est lue dans os.environ au chargement. Une variable absente ou
vide signifie que l'identite n'a pas de cle utilisable : elle ne sera jamais
resolue.

Les utilisateurs (type "user") ne portent pas de cle et ne sont jamais resolus :
ce sont des proprietaires de fichiers, pas des appelants du Gateway.
"""

from __future__ import annotations

import hmac
import json
import os
from pathlib import Path
from typing import Any


class IdentityRegistry:
    """Resout une cle API en identite (id, type, allowed)."""

    def __init__(self, path: str | Path) -> None:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        self._identities: list[dict[str, Any]] = raw.get("identities", [])
        # Table cle en clair -> identite, construite au chargement.
        # Les users (sans key_env) et les cles absentes/vides sont ignores.
        self._by_key: dict[str, dict[str, Any]] = {}
        for identity in self._identities:
            if identity.get("type") == "user":
                continue
            key_env = identity.get("key_env")
            if not key_env:
                continue
            value = os.environ.get(key_env)
            if not value:  # variable absente ou vide -> pas de cle utilisable
                continue
            self._by_key[value] = identity

    def resolve(self, api_key: str | None) -> dict[str, Any] | None:
        """Renvoie l'identite dont la cle correspond, sinon None.

        None ou chaine vide donnent None. Comparaison a temps constant via
        hmac.compare_digest. Ne leve jamais d'exception.
        """
        if not api_key:
            return None
        try:
            for key, identity in self._by_key.items():
                if hmac.compare_digest(api_key, key):
                    return identity
        except (TypeError, ValueError):
            return None
        return None

    def get(self, agent_id: str | None) -> dict[str, Any] | None:
        """Renvoie l'identite d'identifiant agent_id, sinon None.

        Sert a la revalidation d'une approbation : on retrouve l'identite reelle
        a partir de l'agent_id stocke dans l'action, sans repasser par la cle.
        None ou identifiant inconnu donnent None.
        """
        if not agent_id:
            return None
        for identity in self._identities:
            if identity.get("id") == agent_id:
                return identity
        return None
