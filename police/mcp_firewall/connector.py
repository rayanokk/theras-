"""Connecteur qui place un serveur MCP amont derriere le pare-feu de Theras.

McpUpstreamConnector implemente l'interface Connector (police/connectors/base.py)
en s'appuyant uniquement sur le manifeste et sur un client amont injecte. Il ne
decide rien : le pipeline du Gateway applique la politique a partir du
ResourceInfo renvoye par describe(), et n'appelle execute() qu'apres un verdict
favorable.

Fail closed : un outil absent du manifeste n'est jamais transmis a l'amont
(describe le marque inexistant/restricted, execute leve PermissionError).
"""

from __future__ import annotations

import json
from typing import Any, Protocol, runtime_checkable

from contracts.models import ResourceInfo
from police.mcp_firewall.manifest import Manifest
from police.mcp_firewall.translate import (
    canonical_action,
    extract_recipient,
)


@runtime_checkable
class UpstreamClient(Protocol):
    """Client synchrone vers un serveur MCP amont."""

    def call_tool(self, name: str, arguments: dict) -> Any:
        """Appelle un outil amont. Leve une exception en cas d'echec ou de timeout."""
        ...


def _domain(email: str | None) -> str | None:
    """Partie apres @ en minuscules, ou None."""
    if not email or "@" not in email:
        return None
    return email.rsplit("@", 1)[1].lower()


class McpUpstreamConnector:
    """Expose un serveur MCP amont comme un Connector du Gateway."""

    def __init__(self, manifest: Manifest, client: UpstreamClient) -> None:
        self._manifest = manifest
        self._client = client
        self.name = manifest.server

    def canonical_action(self, action: str) -> str | None:
        """Action canonique de l'outil amont, ou None s'il est inconnu."""
        return canonical_action(self._manifest, action)

    def describe(self, action: str, resource_id: str, params: dict) -> ResourceInfo:
        """Faits sur la ressource, sans rien executer. `action` = nom de l'outil amont."""
        spec = self._manifest.tool(action)
        if spec is None:
            # Outil inconnu : fail closed, ressource consideree inexistante et
            # ultra-sensible pour que la politique refuse (R-DENY-03).
            return ResourceInfo(
                exists=False,
                classification="restricted",
                owner=None,
                acl=[],
                trusted=False,
                recipient_email=None,
                recipient_domain=None,
            )

        classification, trusted = self._manifest.resource_facts(resource_id, spec)
        recipient_email = extract_recipient(spec, params)
        return ResourceInfo(
            exists=True,
            classification=classification,
            owner=None,
            acl=list(self._manifest.acl),
            trusted=trusted,
            recipient_email=recipient_email,
            recipient_domain=_domain(recipient_email),
        )

    def execute(self, action: str, resource_id: str, params: dict) -> dict:
        """Appelle l'outil amont (uniquement via le pipeline). `action` = nom de l'outil."""
        spec = self._manifest.tool(action)
        if spec is None:
            # On n'appelle JAMAIS l'amont pour un outil hors manifeste.
            raise PermissionError(
                f"Outil '{action}' absent du manifeste '{self.name}'"
            )

        result = self._client.call_tool(action, params)

        if spec.effect.value == "read":
            # trusted vient UNIQUEMENT du manifeste : on ignore tout "trusted"
            # renvoye par l'amont (il ne peut pas s'auto-declarer fiable).
            _classification, trusted = self._manifest.resource_facts(
                resource_id, spec
            )
            content = self._unwrap_content(result)
            return {"content": content, "trusted": trusted}
        return {"result": result}

    @staticmethod
    def _unwrap_content(result: Any) -> Any:
        """Extrait la valeur de "content" si l'amont enveloppe sa reponse.

        - dict avec "content" -> result["content"] ;
        - chaine JSON decodant en dict avec "content" -> cette valeur ;
        - sinon, le resultat tel quel.
        """
        if isinstance(result, dict) and "content" in result:
            return result["content"]
        if isinstance(result, str):
            try:
                decoded = json.loads(result)
            except (ValueError, TypeError):
                return result
            if isinstance(decoded, dict) and "content" in decoded:
                return decoded["content"]
        return result
