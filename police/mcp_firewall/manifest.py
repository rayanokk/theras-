"""Manifestes du pare-feu MCP : decrire l'EFFET des outils d'un serveur amont.

Un serveur MCP amont (GitHub, filesystem, nos mocks...) expose des outils dont
le nom et les arguments ne disent rien de leur effet reel. Un manifeste declare,
pour chaque outil, s'il lit / liste / ecrit / partage / supprime / envoie, quel
argument porte la ressource et lequel porte le destinataire, et d'ou vient le
contenu renvoye. Le Gateway Theras applique alors sa politique SANS code
specifique a ce serveur.

Fail closed : un manifeste incomplet ou incoherent est refuse au chargement
(extra="forbid" partout, validations croisees, messages d'erreur explicites), et
un outil absent du manifeste n'est pas resolu (l'appelant refuse l'action).
"""

from __future__ import annotations

import fnmatch
import re
from enum import Enum
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from contracts.models import Classification

# Noms de serveur reserves aux connecteurs natifs du Gateway.
_RESERVED_SERVERS = {"google_drive", "mail"}
_SERVER_PATTERN = r"^[a-z][a-z0-9_]{1,30}$"
# Effets qui exigent un destinataire.
_RECIPIENT_EFFECTS = {"share", "send"}


class Effect(str, Enum):
    READ = "read"
    LIST = "list"
    WRITE = "write"
    SHARE = "share"
    DELETE = "delete"
    SEND = "send"


class ResourceRule(BaseModel):
    """Regle de classification/confiance pour les ressources dont le nom matche."""

    model_config = ConfigDict(extra="forbid")

    match: str  # motif fnmatch, ex. "Confidential_*"
    classification: Classification | None = None
    trusted: bool | None = None

    @model_validator(mode="after")
    def _at_least_one(self) -> "ResourceRule":
        if self.classification is None and self.trusted is None:
            raise ValueError(
                "ResourceRule doit préciser au moins 'classification' ou 'trusted'"
            )
        return self


class ToolSpec(BaseModel):
    """Effet declare d'un outil du serveur amont."""

    model_config = ConfigDict(extra="forbid")

    effect: Effect
    resource_from: str  # nom de l'argument qui designe la ressource
    recipient_from: str | None = None  # argument portant le destinataire
    untrusted_output: bool = False  # le contenu renvoye vient de l'exterieur -> taint
    classification: Classification | None = None

    @model_validator(mode="after")
    def _recipient_required(self) -> "ToolSpec":
        if self.effect.value in _RECIPIENT_EFFECTS and not self.recipient_from:
            raise ValueError(
                f"L'effet '{self.effect.value}' exige 'recipient_from'"
            )
        return self


class Manifest(BaseModel):
    """Description complete d'un serveur MCP amont."""

    model_config = ConfigDict(extra="forbid")

    server: str
    default_classification: Classification = Classification.INTERNAL
    acl: list[str]
    resources: list[ResourceRule] = []
    tools: dict[str, ToolSpec]

    @field_validator("server")
    @classmethod
    def _valid_server(cls, value: str) -> str:
        if not re.match(_SERVER_PATTERN, value):
            raise ValueError(
                f"server '{value}' invalide (attendu : {_SERVER_PATTERN})"
            )
        if value in _RESERVED_SERVERS:
            raise ValueError(f"server '{value}' est réservé au Gateway")
        return value

    @field_validator("acl")
    @classmethod
    def _acl_non_empty(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("acl ne peut pas être vide")
        return value

    @field_validator("tools")
    @classmethod
    def _tools_non_empty(cls, value: dict) -> dict:
        if not value:
            raise ValueError("tools ne peut pas être vide")
        return value

    def tool(self, name: str) -> ToolSpec | None:
        """ToolSpec de l'outil, ou None s'il est absent (fail closed cote appelant)."""
        return self.tools.get(name)

    def resource_facts(
        self, resource_id: str, spec: ToolSpec
    ) -> tuple[Classification, bool]:
        """Classification et confiance d'une ressource pour un outil donne.

        classification : premier ResourceRule qui matche ET precise une
        classification ; sinon spec.classification ; sinon default_classification.
        trusted : False si spec.untrusted_output ; sinon premier ResourceRule qui
        matche ET precise trusted ; sinon True.
        """
        classification: Classification | None = None
        trusted: bool | None = None
        for rule in self.resources:
            if fnmatch.fnmatch(resource_id, rule.match):
                if classification is None and rule.classification is not None:
                    classification = rule.classification
                if trusted is None and rule.trusted is not None:
                    trusted = rule.trusted

        if classification is None:
            classification = spec.classification or self.default_classification

        if spec.untrusted_output:
            trusted = False
        elif trusted is None:
            trusted = True

        return classification, trusted


def load_manifest(path: str | Path) -> Manifest:
    """Charge un manifeste YAML. Toute erreur cite le nom du fichier."""
    p = Path(path)
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"Manifeste illisible '{p.name}' : {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError(f"Manifeste '{p.name}' : la racine doit être un objet")
    try:
        return Manifest.model_validate(raw)
    except Exception as exc:
        raise ValueError(f"Manifeste invalide '{p.name}' : {exc}") from exc


def load_manifests(directory: str | Path) -> dict[str, Manifest]:
    """Charge tous les *.yaml d'un dossier. Deux memes 'server' -> erreur."""
    d = Path(directory)
    manifests: dict[str, Manifest] = {}
    for path in sorted(d.glob("*.yaml")):
        manifest = load_manifest(path)
        if manifest.server in manifests:
            raise ValueError(
                f"Deux manifestes declarent le meme server '{manifest.server}' "
                f"(dont {path.name})"
            )
        manifests[manifest.server] = manifest
    return manifests
