"""Branchement des serveurs MCP amont au demarrage du Gateway (etape 4).

Le flag THERAS_MCP_FIREWALL gouverne tout : absent, le Gateway est identique a
avant. Present, les amonts manifestes ET configures sont lances en sous-processus
et branches ; un amont qui ne demarre pas est ignore (fail closed).

Ces tests lancent de VRAIS sous-processus (tests/fixtures/fake_upstream.py), mais
aucun acces reseau. Ils reconstruisent le cablage de main.py avec des chemins de
test, pour ne pas dependre de l'environnement global.
"""

from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from police.approvals.service import ApprovalService
from police.connectors.drive_mock import DriveMock
from police.connectors.mail_mock import MailMock
from police.evidence.vault import EvidenceVault
from police.gateway.api import create_app
from police.gateway.pipeline import Pipeline
from police.mcp_firewall.loader import start_mcp_connectors
from police.policy.engine import load_policy
from police.policy.taint import TaintTracker
from police.store.sqlite_store import SQLiteStore

REPO = Path(__file__).resolve().parents[1]
POLICIES = REPO / "policies" / "policies.yaml"
FIXTURES = REPO / "tests" / "fixtures"
FAKE_MANIFESTS = FIXTURES / "manifests"
FAKE_UPSTREAMS = FIXTURES / "upstreams_fake.yaml"
BAD_UPSTREAMS = FIXTURES / "upstreams_badmodule.yaml"

AGENT_KEY = "k-assistant"


class FakeIdentities:
    def __init__(self):
        self._agent = {
            "id": "agent-assistant",
            "type": "agent",
            "allowed": {"fake": ["read_file", "slow"]},
        }

    def resolve(self, api_key):
        return self._agent if api_key == AGENT_KEY else None

    def get(self, agent_id):
        return self._agent if agent_id == self._agent["id"] else None


def _make_pipeline(tmp_path):
    store = SQLiteStore(str(tmp_path / "test.db"))
    drive = DriveMock()
    mail = MailMock(drive)
    vault = EvidenceVault(store)
    pipeline = Pipeline(
        policy=load_policy(POLICIES),
        identities=FakeIdentities(),
        connectors={"google_drive": drive, "mail": mail},
        store=store,
        vault=vault,
        taint=TaintTracker(store),
        risk_scorer=None,
    )
    approvals = ApprovalService(store, vault, pipeline, FakeIdentities())
    return store, pipeline, vault, approvals


def _lifespan_for(pipeline, upstreams_path):
    @asynccontextmanager
    async def lifespan(app):
        connectors, clients = start_mcp_connectors(
            FAKE_MANIFESTS, upstreams_path, REPO, timeout_s=15
        )
        for name, connector in connectors.items():
            pipeline.register_connector(name, connector)
        app.state.mcp_clients = clients
        try:
            yield
        finally:
            for client in clients:
                client.close()

    return lifespan


def _body(action, resource_id, parameters=None):
    return {
        "agent_id": "agent-assistant",
        "tool": "fake",
        "action": action,
        "resource_id": resource_id,
        "parameters": parameters or {},
        "session_id": "sess-1",
        "task_id": "task-1",
    }


# --- a) flag absent : rien ne change ------------------------------------------


def test_flag_absent_registers_no_mcp(tmp_path):
    store, pipeline, vault, approvals = _make_pipeline(tmp_path)
    # Pas de lifespan : comportement identique a aujourd'hui.
    app = create_app(pipeline, store, vault, FakeIdentities(), approvals)
    with TestClient(app):
        assert set(pipeline._connectors) == {"google_drive", "mail"}
    store.close()


# --- b) flag true : le connecteur fake est branche et appele ------------------


def test_flag_true_registers_fake_and_reads(tmp_path):
    store, pipeline, vault, approvals = _make_pipeline(tmp_path)
    app = create_app(
        pipeline,
        store,
        vault,
        FakeIdentities(),
        approvals,
        lifespan=_lifespan_for(pipeline, FAKE_UPSTREAMS),
    )
    with TestClient(app) as client:
        assert "fake" in pipeline._connectors
        resp = client.post(
            "/v1/actions",
            json=_body("read_file", "notes.txt", {"path": "notes.txt"}),
            headers={"X-API-Key": AGENT_KEY},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "ALLOW"
        # Le contenu vient bien de fake_upstream (le SDK MCP peut l'emballer dans
        # structuredContent, d'ou la recherche de la sous-chaine).
        assert "contenu de notes.txt" in str(data["result"]["content"])
    store.close()


# --- c) outil non declare (boom) ----------------------------------------------


def test_undeclared_tool_is_deny_06(tmp_path):
    store, pipeline, vault, approvals = _make_pipeline(tmp_path)
    app = create_app(
        pipeline,
        store,
        vault,
        FakeIdentities(),
        approvals,
        lifespan=_lifespan_for(pipeline, FAKE_UPSTREAMS),
    )
    with TestClient(app) as client:
        resp = client.post(
            "/v1/actions",
            json=_body("boom", "x", {}),
            headers={"X-API-Key": AGENT_KEY},
        )
        assert resp.status_code == 403
        assert resp.json()["rule_ids"] == ["R-DENY-06"]
    store.close()


# --- d) module inexistant : Gateway demarre, serveur non enregistre -----------


def test_bad_module_gateway_starts_and_tool_is_deny_06(tmp_path):
    store, pipeline, vault, approvals = _make_pipeline(tmp_path)
    app = create_app(
        pipeline,
        store,
        vault,
        FakeIdentities(),
        approvals,
        lifespan=_lifespan_for(pipeline, BAD_UPSTREAMS),
    )
    with TestClient(app) as client:
        # Le Gateway a demarre malgre l'echec du sous-processus.
        assert "fake" not in pipeline._connectors
        resp = client.post(
            "/v1/actions",
            json=_body("read_file", "notes.txt", {"path": "notes.txt"}),
            headers={"X-API-Key": AGENT_KEY},
        )
        assert resp.status_code == 403
        assert resp.json()["rule_ids"] == ["R-DENY-06"]
    store.close()


# --- e) register_connector refuse d'ecraser un natif --------------------------


def test_register_connector_rejects_existing(tmp_path):
    store, pipeline, vault, approvals = _make_pipeline(tmp_path)
    with pytest.raises(ValueError):
        pipeline.register_connector("google_drive", object())
    store.close()


# --- f) les clients sont fermes a l'arret -------------------------------------


def test_clients_closed_on_shutdown(tmp_path):
    store, pipeline, vault, approvals = _make_pipeline(tmp_path)
    app = create_app(
        pipeline,
        store,
        vault,
        FakeIdentities(),
        approvals,
        lifespan=_lifespan_for(pipeline, FAKE_UPSTREAMS),
    )
    with TestClient(app) as client:
        clients = app.state.mcp_clients
        assert len(clients) == 1
        assert clients[0]._thread is not None
    # Apres la sortie du contexte (shutdown), le thread est arrete.
    assert clients[0]._thread is None
    store.close()
