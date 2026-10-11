"""Test bout en bout de la chaîne MCP de Theras, sans réseau ni Bedrock.

Montage réel :
    agent  ->  FacadeCore (police/mcp_firewall/proxy.py)
           ->  Gateway réel en mémoire (create_app + TestClient)
           ->  amont MCP réel theras_mocks (sous-processus stdio, lancé par le
               lifespan via start_mcp_connectors, config demo_drive)

Aucun secret réel : les clés sont posées par monkeypatch.setenv avec des valeurs
de test. Aucun accès réseau ni Bedrock (RISK_LLM_ENABLED=false -> heuristiques).

On reconstruit le câblage de main.py avec une base SQLite dans tmp_path et le
VRAI registre d'identités (data/identities.json), pour exercer les droits
demo_drive. Chaque scénario repart d'une base neuve.
"""

from __future__ import annotations

import time
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
from police.identity import IdentityRegistry
from police.mcp_firewall.loader import start_mcp_connectors
from police.mcp_firewall.proxy import STATUS_TOOL, FacadeCore
from police.policy.engine import load_policy
from police.policy.taint import TaintTracker
from police.risk.scorer import make_scorer
from police.store.sqlite_store import SQLiteStore

REPO = Path(__file__).resolve().parents[1]
POLICIES = REPO / "policies" / "policies.yaml"
IDENTITIES = REPO / "data" / "identities.json"
MANIFESTS = REPO / "police" / "mcp_firewall" / "manifests"
UPSTREAMS = REPO / "police" / "mcp_firewall" / "upstreams.yaml"

# Clés de test (valeurs factices, posées via monkeypatch dans la fixture).
TEST_KEYS = {
    "AGENT_KEY_RESEARCH": "test-key-research",
    "AGENT_KEY_OPS": "test-key-ops",
    "AGENT_KEY_ASSISTANT": "test-key-assistant",
    "APPROVER_KEY_ALICE": "test-key-alice",
    "APPROVER_KEY_BOB": "test-key-bob",
}

PUBLIC_FILE = "Press_Release_Q3.txt"
UNTRUSTED_FILE = "vendor_notes.txt"
CONFIDENTIAL_FILE = "Confidential_Audit_Report.pdf"
EXTERNAL_RECIPIENT = "audit@external.example"


class _Rig:
    """Un montage e2e complet : Gateway + amont + façade, nettoyable."""

    def __init__(self, tmp_path: Path):
        self.store = SQLiteStore(str(tmp_path / "e2e.db"))
        drive = DriveMock()
        mail = MailMock(drive)
        self.vault = EvidenceVault(self.store)
        identities = IdentityRegistry(str(IDENTITIES))
        self.pipeline = Pipeline(
            policy=load_policy(POLICIES),
            identities=identities,
            connectors={"google_drive": drive, "mail": mail},
            store=self.store,
            vault=self.vault,
            taint=TaintTracker(self.store),
            # RISK_LLM_ENABLED=false : heuristiques seules, jamais Bedrock.
            risk_scorer=make_scorer(use_llm=False),
        )
        self.approvals = ApprovalService(
            self.store, self.vault, self.pipeline, identities
        )

        @asynccontextmanager
        async def lifespan(app):
            connectors, clients = start_mcp_connectors(
                MANIFESTS, UPSTREAMS, REPO, timeout_s=20
            )
            for name, connector in connectors.items():
                self.pipeline.register_connector(name, connector)
            app.state.mcp_clients = clients
            try:
                yield
            finally:
                for client in clients:
                    client.close()

        self.app = create_app(
            self.pipeline, self.store, self.vault, identities, self.approvals,
            lifespan=lifespan,
        )
        self.client = TestClient(self.app)

    def facade_with_manifests(self, agent_key: str, **kwargs) -> FacadeCore:
        """FacadeCore branché sur le TestClient (un httpx.Client) comme amont HTTP,
        avec les manifestes réels (demo_drive) chargés depuis le disque."""
        from police.mcp_firewall.manifest import load_manifests

        return FacadeCore(
            gateway_url="http://testserver",
            agent_key=agent_key,
            manifests=load_manifests(MANIFESTS),
            http_client=self.client,
            wait_s=kwargs.pop("wait_s", 5),
            poll_s=kwargs.pop("poll_s", 0.05),
            **kwargs,
        )


@pytest.fixture
def rig(tmp_path, monkeypatch):
    # Clés de test dans l'environnement (lues par IdentityRegistry).
    for name, value in TEST_KEYS.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("RISK_LLM_ENABLED", "false")
    monkeypatch.delenv("APPROVAL_TTL_SECONDS", raising=False)

    rig = _Rig(tmp_path)
    with rig.client:  # déclenche le lifespan (démarre l'amont demo_drive)
        assert "demo_drive" in rig.pipeline._connectors, (
            "l'amont demo_drive n'a pas démarré"
        )
        yield rig
    rig.store.close()


def _core(rig, key, **kwargs):
    return rig.facade_with_manifests(key, **kwargs)


# --- 1. read ALLOW : contenu venu de l'amont ----------------------------------


def test_research_read_public_file_allow(rig):
    core = _core(rig, TEST_KEYS["AGENT_KEY_RESEARCH"])
    res = core.call("demo_drive__read_file", {"path": PUBLIC_FILE})
    assert not res.is_error
    # Le contenu provient bien de l'amont (fichier du seed).
    assert "Acme Corp" in res.text


# --- 2. delete DENY : pas le droit, amont non appelé --------------------------


def test_research_delete_denied_upstream_not_called(rig):
    core = _core(rig, TEST_KEYS["AGENT_KEY_RESEARCH"])
    target = "Team_Roadmap.md"
    res = core.call("demo_drive__delete_file", {"path": target})
    assert res.is_error  # R-DENY-02 : hors des droits

    # L'amont n'a pas été appelé : le fichier existe toujours côté amont.
    # On le prouve via un list_files (droit que research possède).
    listed = core.call("demo_drive__list_files", {"path": "root"})
    assert not listed.is_error
    assert target in listed.text


# --- 3. démo phare : taint puis share confidentiel externe -> REVIEW ----------


def _share_confidential_after_taint(rig):
    """Assistant lit vendor_notes.txt (non fiable) puis partage un confidentiel
    vers l'externe, dans la MÊME session (taint propagé). Renvoie (core, res)."""
    core = _core(rig, TEST_KEYS["AGENT_KEY_ASSISTANT"])
    read = core.call("demo_drive__read_file", {"path": UNTRUSTED_FILE})
    assert not read.is_error
    res = core.call(
        "demo_drive__share_file",
        {"path": CONFIDENTIAL_FILE, "email": EXTERNAL_RECIPIENT},
    )
    return core, res


def test_flagship_share_confidential_external_is_review(rig):
    core, res = _share_confidential_after_taint(rig)
    # Message exact de la façade en cas de REVIEW non décidée à temps.
    assert "Approbation humaine requise (PA-" in res.text
    assert not res.is_error

    # Mêmes verdicts que la démo directe : REVIEW avec R-REV-01 ET R-REV-02.
    pending = rig.approvals.list(status="pending")
    assert len(pending) == 1
    rule_ids = pending[0].get("rule_ids") or []
    assert "R-REV-01" in rule_ids
    assert "R-REV-02" in rule_ids


# --- 4. suite : approbation -> exécution unique, statut via la façade ---------


def test_flagship_approved_then_executed_once(rig):
    core, res = _share_confidential_after_taint(rig)
    # Récupère l'action_id (PA-xxxx) depuis le message de la façade.
    assert "PA-" in res.text
    pending = rig.approvals.list(status="pending")
    approval_id = pending[0]["approval_id"]
    action_id = pending[0]["action_id"]

    # Un approbateur approuve via l'API (auth par clé d'approbateur).
    resp = rig.client.post(
        f"/v1/approvals/{approval_id}/decide",
        json={"decision": "approve", "justification": "ok pour la démo"},
        headers={"X-API-Key": TEST_KEYS["APPROVER_KEY_ALICE"]},
    )
    assert resp.status_code == 200
    assert resp.json()["action_status"] == "EXECUTED"

    # theras__get_action_status renvoie le statut exécuté + résultat de l'amont.
    # Le connecteur emballe un résultat non-read sous {"result": ...} ; on vérifie
    # donc que le résultat de l'amont (le partage effectué) y figure bien.
    status = core.call(STATUS_TOOL, {"action_id": action_id})
    assert not status.is_error
    assert "shared_with" in status.text and EXTERNAL_RECIPIENT in status.text

    # Exécutée une seule fois : un seul événement EXECUTED pour cette action.
    events = rig.store.list_events()
    executed = [
        e for e in events
        if e["action_id"] == action_id and e["type"] == "EXECUTED"
    ]
    assert len(executed) == 1


# --- 5. outil absent du manifeste -> R-DENY-06 et tracé -----------------------


def test_unknown_tool_is_deny_06_and_traced(rig):
    core = _core(rig, TEST_KEYS["AGENT_KEY_ASSISTANT"])
    res = core.call("demo_drive__evil_tool", {"path": "x"})
    assert res.is_error

    # La tentative est tracée dans la boîte noire (événement BLOCKED R-DENY-06).
    events = rig.store.list_events()
    blocked = [e for e in events if e["type"] == "BLOCKED"]
    assert any(
        "R-DENY-06" in (e["payload"].get("rule_ids") or [])
        for e in blocked
    ), "aucun BLOCKED R-DENY-06 tracé pour l'outil inconnu"


# --- 6. intégrité du Vault après les appels MCP -------------------------------


def test_vault_verify_and_events_exist(rig):
    core = _core(rig, TEST_KEYS["AGENT_KEY_ASSISTANT"])
    core.call("demo_drive__read_file", {"path": PUBLIC_FILE})
    core.call("demo_drive__share_file", {"path": CONFIDENTIAL_FILE, "email": EXTERNAL_RECIPIENT})

    # Via la route (auth approbateur) : la chaîne est valide.
    resp = rig.client.get(
        "/v1/evidence/verify",
        headers={"X-API-Key": TEST_KEYS["APPROVER_KEY_ALICE"]},
    )
    assert resp.status_code == 200
    assert resp.json()["valid"] is True

    # Des événements existent bien pour les actions MCP (REQUESTED/DECIDED...).
    events = rig.store.list_events()
    assert len(events) > 0
    assert any(e["type"] == "REQUESTED" for e in events)
    assert any(e["type"] == "DECIDED" for e in events)


# --- 7. latence d'un read ALLOW de bout en bout -------------------------------


def test_latency_read_allow_under_budget(rig, capsys):
    core = _core(rig, TEST_KEYS["AGENT_KEY_RESEARCH"])
    n = 20
    # Un appel de chauffe (démarrage de la session MCP déjà fait par le lifespan).
    core.call("demo_drive__read_file", {"path": PUBLIC_FILE})

    t0 = time.perf_counter()
    for _ in range(n):
        res = core.call("demo_drive__read_file", {"path": PUBLIC_FILE})
        assert not res.is_error
    elapsed = time.perf_counter() - t0
    avg_ms = (elapsed / n) * 1000

    with capsys.disabled():
        print(
            f"\n[latence e2e] read_file ALLOW (façade->Gateway->amont) : "
            f"{avg_ms:.1f} ms/appel (moyenne sur {n})"
        )

    # Garde-fou souple, pas une assertion de perf stricte.
    assert avg_ms < 1000
