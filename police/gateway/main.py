"""Point d'entree de l'API : construit toutes les pieces et expose `app`.

Lancement :
    uvicorn police.gateway.main:app --reload

Les cles d'agent et d'approbateur sont lues depuis l'environnement (.env),
jamais ecrites dans le repo (regle d'or 10). Le scoreur de risque est None ici :
l'API tourne sans Bedrock par defaut (le pipeline fail-close sur action
sensible via R-REV-04 uniquement si un scoreur indisponible est branche).
"""

from __future__ import annotations

import os

from dotenv import load_dotenv

from police.approvals.service import ApprovalService
from police.connectors.drive_mock import DriveMock
from police.connectors.mail_mock import MailMock
from police.evidence.vault import EvidenceVault
from police.gateway.api import create_app
from police.gateway.pipeline import Pipeline
from police.identity import IdentityRegistry
from police.policy.engine import load_policy
from police.policy.taint import TaintTracker
from police.risk.scorer import make_scorer
from police.store.sqlite_store import SQLiteStore

load_dotenv()

policy = load_policy("policies/policies.yaml")
identities = IdentityRegistry("data/identities.json")
store = SQLiteStore(os.getenv("POLICE_DB_PATH", "./police.db"))

drive = DriveMock()
mail = MailMock(drive)
vault = EvidenceVault(store)
taint = TaintTracker(store)
connectors = {"google_drive": drive, "mail": mail}

risk_scorer = make_scorer(
    use_llm=os.getenv("RISK_LLM_ENABLED", "false").lower() == "true"
)

pipeline = Pipeline(
    policy=policy,
    identities=identities,
    connectors=connectors,
    store=store,
    vault=vault,
    taint=taint,
    risk_scorer=risk_scorer,
)

approvals = ApprovalService(store, vault, pipeline, identities)

# Pare-feu MCP : OFF par defaut. Si THERAS_MCP_FIREWALL != "true", le Gateway se
# comporte exactement comme avant (aucun manifeste charge, aucun sous-processus).
_MCP_ENABLED = os.getenv("THERAS_MCP_FIREWALL", "false").lower() == "true"
_lifespan = None

if _MCP_ENABLED:
    import logging
    from contextlib import asynccontextmanager

    from police.mcp_firewall.loader import start_mcp_connectors

    _logger = logging.getLogger(__name__)
    _REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    _MANIFESTS = os.getenv(
        "THERAS_MCP_MANIFESTS", "police/mcp_firewall/manifests"
    )
    _UPSTREAMS = os.getenv(
        "THERAS_MCP_UPSTREAMS", "police/mcp_firewall/upstreams.yaml"
    )

    def _resolve(path: str) -> str:
        # Chemin relatif -> resolu par rapport a la racine du repo, pas au cwd.
        return path if os.path.isabs(path) else os.path.join(_REPO_ROOT, path)

    @asynccontextmanager
    async def _lifespan(app):  # noqa: F811
        connectors, clients = start_mcp_connectors(
            _resolve(_MANIFESTS), _resolve(_UPSTREAMS), _REPO_ROOT
        )
        for name, connector in connectors.items():
            pipeline.register_connector(name, connector)
        app.state.mcp_clients = clients
        if not connectors:
            _logger.warning(
                "pare-feu MCP actif mais aucun serveur amont enregistré"
            )
        try:
            yield
        finally:
            for client in clients:
                try:
                    client.close()
                except Exception:  # noqa: BLE001
                    pass

app = create_app(pipeline, store, vault, identities, approvals, lifespan=_lifespan)
