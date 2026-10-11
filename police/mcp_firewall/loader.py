"""Lancement des serveurs MCP amont et branchement de leurs connecteurs.

Fichier de configuration (upstreams.yaml) : purement operationnel (quel module
lancer, quelles variables lui transmettre). La SECURITE vit dans les manifestes.

Fail closed : un amont qui refuse de demarrer n'est pas enregistre ; ses outils
tomberont alors sur R-DENY-06 cote pipeline. Un manifeste sans config (ou
l'inverse) est ignore avec un avertissement. Les noms natifs "google_drive" et
"mail" ne peuvent jamais etre enregistres.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

import yaml
from mcp import StdioServerParameters
from pydantic import BaseModel, ConfigDict

from police.mcp_firewall.connector import McpUpstreamConnector
from police.mcp_firewall.manifest import load_manifests
from police.mcp_firewall.upstream import StdioUpstreamClient, UpstreamError

logger = logging.getLogger(__name__)

# Variables d'environnement toujours transmises au sous-processus si presentes
# (sinon Python/MCP peut ne pas demarrer sous Windows ou en venv).
_PASSTHROUGH_ENV = ("PATH", "SYSTEMROOT", "HOME", "SYSTEMDRIVE", "TEMP", "TMP")

_RESERVED = {"google_drive", "mail"}


class UpstreamConfig(BaseModel):
    """Configuration de lancement d'un serveur MCP amont."""

    model_config = ConfigDict(extra="forbid")

    module: str
    env: list[str] = []


def load_upstream_config(path: str | Path) -> dict[str, UpstreamConfig]:
    """Charge upstreams.yaml en dict server -> UpstreamConfig."""
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    upstreams = raw.get("upstreams", {}) or {}
    return {name: UpstreamConfig.model_validate(cfg) for name, cfg in upstreams.items()}


def _subprocess_env(cfg: UpstreamConfig) -> dict[str, str]:
    """Environnement minimal du sous-processus : variables demandees + passerelle."""
    env: dict[str, str] = {}
    for name in cfg.env:
        if name in os.environ:
            env[name] = os.environ[name]
    for name in _PASSTHROUGH_ENV:
        if name in os.environ:
            env[name] = os.environ[name]
    return env


def start_mcp_connectors(
    manifests_dir: str | Path,
    config_path: str | Path,
    repo_root: str | Path,
    timeout_s: float = 15,
) -> tuple[dict[str, McpUpstreamConnector], list[StdioUpstreamClient]]:
    """Lance les amonts configures ET manifestes, renvoie (connecteurs, clients).

    Pour chaque serveur present a la fois dans les manifestes et la config, lance
    le sous-processus et, en cas de succes, enregistre son connecteur. Tout echec
    est journalise (WARNING) et le serveur est simplement ignore (fail closed).
    """
    manifests = load_manifests(manifests_dir)
    config = load_upstream_config(config_path)

    connectors: dict[str, McpUpstreamConnector] = {}
    clients: list[StdioUpstreamClient] = []

    # Manifeste sans config, ou config sans manifeste : avertir et ignorer.
    for name in set(manifests) - set(config):
        logger.warning("MCP amont '%s' : manifeste sans configuration, ignoré", name)
    for name in set(config) - set(manifests):
        logger.warning("MCP amont '%s' : configuration sans manifeste, ignoré", name)

    for name in sorted(set(manifests) & set(config)):
        if name in _RESERVED:
            logger.warning("MCP amont '%s' : nom réservé, ignoré", name)
            continue
        manifest = manifests[name]
        cfg = config[name]
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", cfg.module],
            cwd=str(repo_root),
            env=_subprocess_env(cfg),
        )
        client = StdioUpstreamClient(name, params, timeout_s)
        try:
            client.start()
        except (UpstreamError, Exception) as exc:  # noqa: BLE001 - fail closed
            logger.warning("MCP amont '%s' : démarrage impossible (%s), ignoré", name, exc)
            try:
                client.close()
            except Exception:  # noqa: BLE001
                pass
            continue
        connectors[name] = McpUpstreamConnector(manifest, client)
        clients.append(client)
        logger.info("MCP amont '%s' branché", name)

    return connectors, clients
