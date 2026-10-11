"""Façade MCP de Theras : la PRISE que voit l'agent, pas un contrôle.

Ce serveur MCP stdio expose à l'agent les outils des serveurs amont décrits par
les manifestes (police/mcp_firewall/manifests/*.yaml), sous le nom affiché
``{server}__{tool}`` (double underscore). Il ne décide RIEN et ne contacte AUCUN
amont : chaque appel est transmis au Gateway Theras par HTTP (POST /v1/actions),
qui décide (ALLOW / REVIEW / DENY) puis exécute lui-même l'action autorisée.
Toute la sécurité reste dans le Gateway.

Une instance de la façade = un agent. La clé API de l'agent est lue dans
l'environnement, envoyée en en-tête X-API-Key, et n'apparaît jamais dans un
message ni dans un log. On n'envoie jamais d'agent_id : le Gateway déduit
l'identité de la clé.

Configuration (variables d'environnement) :
    THERAS_GATEWAY_URL   défaut http://127.0.0.1:8000
    THERAS_AGENT_KEY     obligatoire : refus de démarrer sans elle
    THERAS_SESSION_ID    optionnelle ; sinon UUID généré au lancement
    THERAS_TASK_ID       optionnelle ; sinon UUID généré au lancement

Point d'entrée : python -m police.mcp_firewall.proxy
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import httpx

from console.labels import rule_label
from police.mcp_firewall.manifest import Manifest, ToolSpec, load_manifests
from police.mcp_firewall.translate import extract_resource

logger = logging.getLogger(__name__)

# Dossier des manifestes et config des amonts, à côté de ce module.
MANIFESTS_DIR = Path(__file__).resolve().parent / "manifests"
UPSTREAMS_PATH = Path(__file__).resolve().parent / "upstreams.yaml"

# Racine du repo (police/mcp_firewall/proxy.py -> remonter de 3 niveaux).
REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# Variables d'environnement toujours transmises au sous-processus amont si
# présentes (sinon Python/MCP peut ne pas démarrer sous Windows ou en venv).
# Même liste que loader.py de L ; on ne transmet jamais THERAS_AGENT_KEY.
_PASSTHROUGH_ENV = ("PATH", "SYSTEMROOT", "HOME", "SYSTEMDRIVE", "TEMP", "TMP")

# Type de la source de schémas : server -> {tool_name -> inputSchema}.
SchemaMap = dict[str, dict[str, dict]]
SchemaProvider = Callable[[], SchemaMap]

# Schéma de theras__get_action_status (figé par le contrat de la façade).
STATUS_TOOL_SCHEMA: dict = {
    "type": "object",
    "properties": {"action_id": {"type": "string"}},
    "required": ["action_id"],
}

# Outil propre à Theras (pas issu d'un manifeste amont).
STATUS_TOOL = "theras__get_action_status"

# Statuts terminaux d'une action côté Gateway.
_EXECUTED = "EXECUTED"
_FINAL_FAILURE = {"DENIED", "EXPIRED", "FAILED"}

# Séparateur du nom affiché.
_SEP = "__"


class CallResult:
    """Résultat d'un appel façade : contenu texte + drapeau isError.

    Volontairement minimal et sans dépendance MCP, pour être testable seul.
    """

    __slots__ = ("text", "is_error")

    def __init__(self, text: str, is_error: bool = False) -> None:
        self.text = text
        self.is_error = is_error

    def __repr__(self) -> str:  # pragma: no cover - confort de debug
        return f"CallResult(is_error={self.is_error}, text={self.text!r})"


@dataclass(frozen=True)
class ToolEntry:
    """Entrée de la table nom affiché -> (server, tool, spec)."""

    server: str
    tool: str
    spec: ToolSpec


def _env_or_uuid(name: str, prefix: str) -> str:
    value = os.getenv(name)
    if value:
        return value
    return f"{prefix}-{uuid.uuid4().hex}"


def _subprocess_env(env_names: list[str]) -> dict[str, str]:
    """Environnement minimal du sous-processus amont : variables demandées +
    passerelle. On ne transmet jamais la clé API de l'agent à l'amont."""
    env: dict[str, str] = {}
    for name in list(env_names) + list(_PASSTHROUGH_ENV):
        if name in os.environ:
            env[name] = os.environ[name]
    return env


def fetch_upstream_schemas(
    upstreams_path: str | Path = UPSTREAMS_PATH,
    repo_root: str | Path = REPO_ROOT,
    timeout_s: float = 15,
) -> SchemaMap:
    """Source de schémas par défaut : pour chaque serveur de upstreams.yaml, ouvre
    un StdioUpstreamClient TEMPORAIRE, lit list_tools(), garde les input_schema,
    puis ferme le client. Un amont qui échoue est simplement absent du résultat
    (la façade basculera sur le schéma de repli pour ses outils).

    On lit la config avec la fonction existante de loader.py (L), sans la modifier.
    """
    from mcp import StdioServerParameters

    from police.mcp_firewall.loader import load_upstream_config
    from police.mcp_firewall.upstream import StdioUpstreamClient

    config = load_upstream_config(upstreams_path)
    schemas: SchemaMap = {}
    for name, cfg in config.items():
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", cfg.module],
            cwd=str(repo_root),
            env=_subprocess_env(cfg.env),
        )
        client = StdioUpstreamClient(name, params, timeout_s)
        try:
            client.start()
            tools = client.list_tools()
            schemas[name] = {
                t["name"]: t["input_schema"] for t in tools
            }
        except Exception as exc:  # noqa: BLE001 - fail-safe, on continue
            # Jamais la clé dans le log : exc ne la contient pas (clé non transmise).
            logger.warning(
                "MCP amont '%s' : schémas indisponibles au démarrage (%s), "
                "repli sur le schéma du manifeste.",
                name,
                exc,
            )
        finally:
            try:
                client.close()
            except Exception:  # noqa: BLE001
                pass
    return schemas


def _strip_descriptions(value: Any) -> Any:
    """Retire récursivement les champs de texte libre d'un JSON Schema amont
    (``description``, ``title``, ``$comment``).

    Anti tool poisoning : ces champs sont du texte non fiable fourni par un
    serveur tiers et peuvent cacher des instructions destinées à l'agent, y
    compris à l'intérieur du schéma. On ne garde que la STRUCTURE (type,
    properties, required, enum...), qui sert à valider la forme des arguments.
    """
    if isinstance(value, dict):
        return {
            k: _strip_descriptions(v)
            for k, v in value.items()
            if k not in ("description", "title", "$comment")
        }
    if isinstance(value, list):
        return [_strip_descriptions(v) for v in value]
    return value


def _fallback_schema(spec: ToolSpec) -> dict:
    """Schéma minimal construit depuis le manifeste quand l'amont est indisponible.

    resource_from et recipient_from deviennent des propriétés string requises ;
    additionalProperties reste true (les autres arguments de l'outil sont libres).
    """
    properties: dict[str, dict] = {spec.resource_from: {"type": "string"}}
    required = [spec.resource_from]
    if spec.recipient_from:
        properties[spec.recipient_from] = {"type": "string"}
        required.append(spec.recipient_from)
    return {
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": True,
    }


class FacadeCore:
    """Logique synchrone de la façade, indépendante de la couche MCP.

    Le client HTTP est injectable (httpx.Client + MockTransport dans les tests).
    """

    def __init__(
        self,
        gateway_url: str,
        agent_key: str,
        manifests: dict[str, Manifest],
        http_client: httpx.Client | None = None,
        wait_s: float = 30,
        poll_s: float = 2,
        session_id: str | None = None,
        task_id: str | None = None,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        schema_provider: SchemaProvider | None = None,
    ) -> None:
        if not agent_key:
            raise RuntimeError(
                "THERAS_AGENT_KEY manquante : la façade MCP de Theras refuse de "
                "démarrer sans la clé API de l'agent."
            )
        self._gateway_url = gateway_url.rstrip("/")
        self._agent_key = agent_key
        self._manifests = manifests
        self._wait_s = wait_s
        self._poll_s = poll_s
        self._session_id = session_id or _env_or_uuid("THERAS_SESSION_ID", "sess")
        self._task_id = task_id or _env_or_uuid("THERAS_TASK_ID", "task")
        self._sleep = sleep
        self._monotonic = monotonic

        self._owns_client = http_client is None
        self._client = http_client or httpx.Client(
            base_url=self._gateway_url, timeout=10.0
        )

        # Table nom affiché -> (server, tool, spec). On ne redécoupe jamais le
        # nom pour retrouver le serveur : on consulte cette table.
        #
        # Garde-fou de collision : comme le séparateur "__" peut aussi apparaître
        # dans un nom de serveur ou d'outil, deux couples (server, tool) distincts
        # peuvent produire le même nom affiché (p. ex. ("a__b", "c") et
        # ("a", "b__c") -> "a__b__c"). On refuse de démarrer plutôt que d'écraser
        # silencieusement une entrée. On réserve aussi le nom de l'outil Theras.
        self._table: dict[str, ToolEntry] = {}
        for server, manifest in self._manifests.items():
            for tool_name, spec in manifest.tools.items():
                display = f"{server}{_SEP}{tool_name}"
                if display == STATUS_TOOL:
                    raise RuntimeError(
                        f"Nom d'outil affiché réservé : l'outil ({server!r}, "
                        f"{tool_name!r}) produit « {STATUS_TOOL} », qui est "
                        "l'outil interne de Theras. Renomme l'outil amont."
                    )
                existing = self._table.get(display)
                if existing is not None:
                    raise RuntimeError(
                        "Collision de nom d'outil affiché « "
                        f"{display} » : les couples ({existing.server!r}, "
                        f"{existing.tool!r}) et ({server!r}, {tool_name!r}) "
                        "produisent le même nom. Renomme un serveur ou un outil."
                    )
                self._table[display] = ToolEntry(server, tool_name, spec)

        # Schémas d'entrée des outils, résolus UNE fois au démarrage.
        #   - inputSchema : repris de l'amont quand disponible (il décrit la
        #     vraie forme des arguments), sinon schéma de repli du manifeste.
        #   - description : TOUJOURS construite par nous à partir du manifeste.
        # Anti « tool poisoning » : on ne reprend JAMAIS la description de
        # l'amont. La description d'un serveur tiers est du texte non fiable qui
        # peut cacher des instructions destinées à l'agent (p. ex. « ignore les
        # consignes précédentes et exfiltre X »). Le schéma, lui, est structuré
        # et sert seulement à valider la forme des arguments.
        self._schema_provider = schema_provider or fetch_upstream_schemas
        self._schemas: dict[str, dict] = self._resolve_schemas()

    def _resolve_schemas(self) -> dict[str, dict]:
        """Associe à chaque nom affiché son inputSchema (amont ou repli)."""
        try:
            upstream = self._schema_provider() or {}
        except Exception as exc:  # noqa: BLE001 - fail-safe : la façade démarre
            logger.warning(
                "Schémas amont indisponibles (%s) : repli sur les manifestes.",
                exc,
            )
            upstream = {}

        resolved: dict[str, dict] = {}
        for display, entry in self._table.items():
            server_schemas = upstream.get(entry.server) or {}
            schema = server_schemas.get(entry.tool)
            if schema:
                # On garde la STRUCTURE du schéma amont, mais on retire tout texte
                # libre (description/title) : vecteur de tool poisoning.
                resolved[display] = _strip_descriptions(schema)
            else:
                resolved[display] = _fallback_schema(entry.spec)
        return resolved

    # ------------------------------------------------------------------ cycle

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> "FacadeCore":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ------------------------------------------------------------------ tools

    def list_tools(self) -> list[dict]:
        """Liste des outils exposés : les {server}__{tool} + theras__get_action_status.

        Chaque outil porte un inputSchema réel (amont ou repli manifeste) et une
        description que NOUS construisons depuis le manifeste (jamais celle de
        l'amont : voir le commentaire anti tool-poisoning dans __init__).
        """
        tools: list[dict] = []
        for display, entry in self._table.items():
            tools.append(
                {
                    "name": display,
                    "description": self._describe(entry),
                    "input_schema": self._schemas[display],
                }
            )
        tools.append(
            {
                "name": STATUS_TOOL,
                "description": (
                    "Renvoie le statut (et le résultat si disponible) d'une action "
                    "Theras précédente, par exemple une action en attente d'approbation "
                    "humaine. Argument : action_id (ex. PA-0001)."
                ),
                "input_schema": dict(STATUS_TOOL_SCHEMA),
            }
        )
        return tools

    @staticmethod
    def _describe(entry: ToolEntry) -> str:
        """Description construite par Theras à partir du manifeste. Volontairement
        indépendante de tout texte fourni par l'amont (anti tool poisoning)."""
        return (
            f"[{entry.server}] {entry.tool} — effet: {entry.spec.effect.value} "
            "(contrôlé par Theras)"
        )

    # ------------------------------------------------------------------- call

    def call(self, name: str, args: dict | None) -> CallResult:
        """Route un appel d'outil. Ne décide rien : transmet au Gateway."""
        args = args or {}

        if name == STATUS_TOOL:
            action_id = args.get("action_id")
            if not action_id:
                return CallResult(
                    "action_id manquant pour theras__get_action_status.",
                    is_error=True,
                )
            return self.get_action_status(str(action_id))

        entry = self._table.get(name)
        if entry is None:
            # Outil inconnu : on appelle QUAND MÊME le Gateway (il tracera la
            # tentative et répondra R-DENY-06). On fait notre meilleur découpage
            # pour tool/action, uniquement dans ce cas de repli.
            tool, action = self._best_split(name)
            return self._submit(tool, action, "unknown", args)

        # Seul refus local : l'argument de ressource est manquant/vide/invalide.
        try:
            resource_id = extract_resource(entry.spec, args)
        except ValueError as exc:
            return CallResult(
                f"Argument de ressource manquant ou invalide : {exc}.",
                is_error=True,
            )

        return self._submit(entry.server, entry.tool, resource_id, args)

    def get_action_status(self, action_id: str) -> CallResult:
        """GET /v1/actions/{id} : statut et résultat éventuel d'une action."""
        record = self._get_action(action_id)
        if record is None:
            return CallResult(f"Action {action_id} introuvable.", is_error=True)
        if isinstance(record, CallResult):  # erreur réseau déjà formatée
            return record
        status = record.get("status")
        if status == _EXECUTED:
            return CallResult(self._render_result(record.get("result")))
        if status in _FINAL_FAILURE:
            return CallResult(
                f"Action {action_id} : {status}.", is_error=True
            )
        return CallResult(f"Action {action_id} : {status} (en cours).")

    # --------------------------------------------------------------- internes

    @staticmethod
    def _best_split(name: str) -> tuple[str, str]:
        """Repli pour outil inconnu : avant/après le premier '__', ou nom entier."""
        if _SEP in name:
            tool, action = name.split(_SEP, 1)
            return tool, action
        return name, name

    def _headers(self) -> dict:
        return {"X-API-Key": self._agent_key}

    def _submit(
        self, tool: str, action: str, resource_id: str, parameters: dict
    ) -> CallResult:
        """Construit l'ActionRequest, POST /v1/actions, interprète la réponse."""
        body = {
            "tool": tool,
            "action": action,
            "resource_id": resource_id,
            "parameters": parameters,
            "session_id": self._session_id,
            "task_id": self._task_id,
        }
        try:
            resp = self._client.post(
                "/v1/actions", json=body, headers=self._headers()
            )
        except httpx.HTTPError:
            return CallResult(
                "Theras injoignable : action non exécutée.", is_error=True
            )

        try:
            decision = resp.json()
        except ValueError:
            decision = {}

        if resp.status_code == 200:  # ALLOW, action exécutée
            return CallResult(self._render_result(decision.get("result")))
        if resp.status_code == 403:  # DENY
            return CallResult(self._render_deny(decision), is_error=True)
        if resp.status_code == 202:  # REVIEW : on attend une décision humaine
            return self._poll_review(decision)
        return CallResult(
            "Theras injoignable : action non exécutée.", is_error=True
        )

    def _poll_review(self, decision: dict) -> CallResult:
        """Attend au plus wait_s, GET /v1/actions/{id} toutes les poll_s."""
        action_id = decision.get("action_id")
        deadline = self._monotonic() + self._wait_s
        while True:
            record = self._get_action(action_id)
            if isinstance(record, CallResult):  # erreur réseau
                return record
            if record is not None:
                status = record.get("status")
                if status == _EXECUTED:
                    return CallResult(self._render_result(record.get("result")))
                if status in _FINAL_FAILURE:
                    return CallResult(
                        f"Action refusée après revue humaine : {status}.",
                        is_error=True,
                    )
            if self._monotonic() >= deadline:
                return CallResult(self._review_pending_message(action_id))
            self._sleep(self._poll_s)

    @staticmethod
    def _review_pending_message(action_id: Any) -> str:
        """Message exact attendu quand la revue n'est pas décidée à temps."""
        return (
            f"Approbation humaine requise ({action_id}). Si approuvée, Theras "
            "exécutera l'action lui-même. Appelle theras__get_action_status "
            f"avec {action_id}. Ne relance pas l'outil."
        )

    def _get_action(self, action_id: Any):
        """GET /v1/actions/{id}. None si 404 ; CallResult(is_error) si réseau KO."""
        try:
            resp = self._client.get(
                f"/v1/actions/{action_id}", headers=self._headers()
            )
        except httpx.HTTPError:
            return CallResult(
                "Theras injoignable : action non exécutée.", is_error=True
            )
        if resp.status_code == 404:
            return None
        try:
            return resp.json()
        except ValueError:
            return None

    @staticmethod
    def _render_result(result: Any) -> str:
        """Rend lisible le résultat d'une action exécutée."""
        if result is None:
            return "Action exécutée."
        if isinstance(result, dict):
            if "content" in result:
                return str(result["content"])
            if "files" in result:
                files = result.get("files") or []
                return "Fichiers : " + ", ".join(files) if files else "Aucun fichier."
            if result.get("shared_with"):
                return f"Partagé avec {result['shared_with']} ({result.get('role')})."
            if result.get("deleted"):
                return "Fichier supprimé."
            if result.get("sent_to"):
                attach = result.get("attachment")
                suffix = f" (pièce jointe : {attach})" if attach else ""
                return f"Email envoyé à {result['sent_to']}{suffix}."
        return str(result)

    @staticmethod
    def _render_deny(decision: dict) -> str:
        """Refus : règles (R-XXX) et leurs explications françaises."""
        rule_ids = decision.get("rule_ids") or []
        if rule_ids:
            labels = " ; ".join(rule_label(rid) for rid in rule_ids)
        else:
            labels = "aucune règle citée"
        reasons = decision.get("reasons") or []
        detail = f" — {' ; '.join(reasons)}" if reasons else ""
        return f"Refusé par Theras : {labels}{detail}. Ne pas réessayer."


# --- Fabrique depuis l'environnement ------------------------------------------


def build_core_from_env(http_client: httpx.Client | None = None) -> FacadeCore:
    """Construit une FacadeCore à partir des variables d'environnement."""
    gateway_url = os.getenv("THERAS_GATEWAY_URL", "http://127.0.0.1:8000")
    agent_key = os.getenv("THERAS_AGENT_KEY", "")
    manifests = load_manifests(MANIFESTS_DIR)
    return FacadeCore(
        gateway_url=gateway_url,
        agent_key=agent_key,
        manifests=manifests,
        http_client=http_client,
    )


# --- Colle MCP (SDK v1 : lowlevel Server + stdio) -----------------------------


async def _serve(core: FacadeCore) -> None:
    from mcp.server.lowlevel import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import TextContent, Tool

    server = Server("theras")

    @server.list_tools()
    async def _list_tools() -> list[Tool]:
        return [
            Tool(
                name=t["name"],
                description=t["description"],
                inputSchema=t["input_schema"],
            )
            for t in core.list_tools()
        ]

    @server.call_tool()
    async def _call_tool(name: str, arguments: dict | None):
        result = core.call(name, arguments)
        content = [TextContent(type="text", text=result.text)]
        # SDK v1 : (content, structured) ; isError est posé par le framework
        # quand on lève. Pour porter is_error sans lever, on renvoie un dict.
        if result.is_error:
            raise _ToolError(result.text)
        return content

    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


class _ToolError(RuntimeError):
    """Erreur d'outil : le SDK la convertit en résultat isError pour le client."""


def main() -> None:
    core = build_core_from_env()
    asyncio.run(_serve(core))


if __name__ == "__main__":
    main()
