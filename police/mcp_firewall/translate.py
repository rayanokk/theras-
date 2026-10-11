"""Traduction entre un outil de serveur MCP amont et le vocabulaire du Gateway.

Le manifeste declare l'effet d'un outil ; ces helpers en derivent l'action
canonique du contrat 1, et extraient la ressource et le destinataire depuis les
arguments de l'appel amont. Toute extraction suspecte leve ValueError : le
pipeline la transformera en DENY (fail closed), jamais en appel a l'amont.
"""

from __future__ import annotations

import re
from typing import Any

from contracts.models import EMAIL_PATTERN
from police.mcp_firewall.manifest import Effect, Manifest, ToolSpec

# Effet declare -> action canonique du contrat 1. "write" n'a aucune regle dans
# policies.yaml : il tombera sur R-DENY-DEFAULT (fail closed).
EFFECT_TO_ACTION: dict[Effect, str] = {
    Effect.READ: "read_file",
    Effect.LIST: "list_files",
    Effect.SHARE: "share_file",
    Effect.DELETE: "delete_file",
    Effect.SEND: "send_email",
    Effect.WRITE: "write",
}

_MAX_RESOURCE_LEN = 512
_EMAIL_RE = re.compile(EMAIL_PATTERN)


def canonical_action(manifest: Manifest, tool_name: str) -> str | None:
    """Action canonique de l'outil, ou None s'il est absent du manifeste."""
    spec = manifest.tool(tool_name)
    if spec is None:
        return None
    return EFFECT_TO_ACTION[spec.effect]


def _has_control_char(value: str) -> bool:
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in value)


def extract_resource(spec: ToolSpec, arguments: dict) -> str:
    """Ressource designee par l'argument spec.resource_from, nettoyee.

    Les chemins peuvent contenir "/" (ce n'est pas un resource_id Drive), mais
    pas de caractere de controle, pas de valeur vide ni demesuree.
    """
    if spec.resource_from not in arguments:
        raise ValueError(f"argument '{spec.resource_from}' manquant")
    value = str(arguments[spec.resource_from])
    if not value:
        raise ValueError(f"argument '{spec.resource_from}' vide")
    if len(value) > _MAX_RESOURCE_LEN:
        raise ValueError(
            f"argument '{spec.resource_from}' trop long (> {_MAX_RESOURCE_LEN})"
        )
    if _has_control_char(value):
        raise ValueError(
            f"argument '{spec.resource_from}' contient un caractère de contrôle"
        )
    return value


def extract_recipient(spec: ToolSpec, arguments: dict) -> str | None:
    """Destinataire (email) si spec.recipient_from est defini, sinon None."""
    if spec.recipient_from is None:
        return None
    if spec.recipient_from not in arguments:
        raise ValueError(f"argument '{spec.recipient_from}' manquant")
    value = str(arguments[spec.recipient_from])
    if not _EMAIL_RE.match(value):
        raise ValueError(f"destinataire '{value}' n'est pas un email valide")
    return value
