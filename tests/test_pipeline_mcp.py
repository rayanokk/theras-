"""Le Gateway accepte un outil declare par un manifeste MCP, sans traitement
special : meme pipeline, meme politique, meme registre que pour les outils natifs.

Le serveur amont est un McpUpstreamConnector adosse au manifeste demo_drive et a
un FakeUpstreamClient en memoire qui enregistre les appels. On verifie surtout
que l'amont n'est appele QU'APRES un verdict favorable (ou une approbation).
"""

from datetime import datetime, timezone
from pathlib import Path

import pytest

from contracts.models import ApprovalDecisionIn
from police.approvals.service import ApprovalService
from police.connectors.drive_mock import DriveMock
from police.connectors.mail_mock import MailMock
from police.evidence.vault import EvidenceVault
from police.gateway.pipeline import Pipeline
from police.mcp_firewall.connector import McpUpstreamConnector
from police.mcp_firewall.manifest import load_manifest
from police.policy.engine import load_policy
from police.policy.taint import TaintTracker
from police.store.sqlite_store import SQLiteStore

REPO = Path(__file__).resolve().parents[1]
POLICIES = REPO / "policies" / "policies.yaml"
DEMO = REPO / "police" / "mcp_firewall" / "manifests" / "demo_drive.yaml"

AGENT_KEY = "k-demo"
APPROVER_KEY = "k-alice"

ALL_DEMO_TOOLS = ["read_file", "list_files", "share_file", "delete_file", "send_email"]


class FakeUpstreamClient:
    def __init__(self, result="valeur amont"):
        self.calls: list[tuple[str, dict]] = []
        self._result = result

    def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        return self._result


class FakeIdentities:
    """Registre d'identites minimal : un agent avec des droits sur demo_drive."""

    def __init__(self, allowed):
        self._agent = {"id": "agent-assistant", "type": "agent", "allowed": allowed}
        self._approver = {"id": "approver-alice", "type": "approver"}

    def resolve(self, api_key):
        if api_key == AGENT_KEY:
            return self._agent
        if api_key == APPROVER_KEY:
            return self._approver
        return None

    def get(self, agent_id):
        if agent_id == self._agent["id"]:
            return self._agent
        return None


def _build(tmp_path, allowed=None):
    if allowed is None:
        allowed = {"demo_drive": list(ALL_DEMO_TOOLS)}
    store = SQLiteStore(str(tmp_path / "test.db"))
    drive = DriveMock()
    mail = MailMock(drive)
    vault = EvidenceVault(store)
    policy = load_policy(POLICIES)
    identities = FakeIdentities(allowed)
    taint = TaintTracker(store)
    upstream = FakeUpstreamClient()
    demo = McpUpstreamConnector(load_manifest(DEMO), upstream)
    pipeline = Pipeline(
        policy=policy,
        identities=identities,
        connectors={"google_drive": drive, "mail": mail, "demo_drive": demo},
        store=store,
        vault=vault,
        taint=taint,
        risk_scorer=None,
    )
    approvals = ApprovalService(store, vault, pipeline, identities)

    class Ctx:
        pass

    c = Ctx()
    c.store = store
    c.upstream = upstream
    c.pipeline = pipeline
    c.approvals = approvals
    return c


@pytest.fixture
def ctx(tmp_path):
    c = _build(tmp_path)
    yield c
    c.store.close()


def _body(action, resource_id, parameters=None, session="sess-1"):
    return {
        "agent_id": "agent-assistant",
        "tool": "demo_drive",
        "action": action,
        "resource_id": resource_id,
        "parameters": parameters or {},
        "session_id": session,
        "task_id": "task-1",
    }


# --- a) lecture ALLOW ---------------------------------------------------------


def test_mcp_read_allow(ctx):
    decision = ctx.pipeline.handle(_body("read_file", "Team_Roadmap.md"), AGENT_KEY)
    assert decision.verdict == "ALLOW"
    assert decision.rule_ids == ["R-ALLOW-01"]
    assert ctx.upstream.calls == [("read_file", {})]


# --- b) demo phare via MCP ----------------------------------------------------


def test_mcp_flagship_review_does_not_call_upstream(ctx):
    ctx.pipeline.handle(_body("read_file", "vendor_notes.txt"), AGENT_KEY)
    before = list(ctx.upstream.calls)
    decision = ctx.pipeline.handle(
        _body(
            "share_file",
            "Confidential_Audit_Report.pdf",
            {"email": "audit@external.example"},
        ),
        AGENT_KEY,
    )
    assert decision.verdict == "REVIEW"
    assert "R-REV-01" in decision.rule_ids
    assert "R-REV-02" in decision.rule_ids
    # Le share_file n'a PAS ete transmis a l'amont (en attente d'approbation).
    assert ctx.upstream.calls == before
    assert ("share_file", {"email": "audit@external.example"}) not in ctx.upstream.calls


# --- c) domaine bloque --------------------------------------------------------


def test_mcp_blocked_domain_denies_without_upstream(ctx):
    decision = ctx.pipeline.handle(
        _body(
            "send_email",
            "Q3_Financials.xlsx",
            {"to": "drop@pastebin.example"},
        ),
        AGENT_KEY,
    )
    assert decision.verdict == "DENY"
    assert "R-DENY-05" in decision.rule_ids
    assert ctx.upstream.calls == []


# --- d) outil absent du manifeste ---------------------------------------------


def test_mcp_unknown_tool_is_deny_06(ctx):
    decision = ctx.pipeline.handle(_body("rm_rf", "whatever"), AGENT_KEY)
    assert decision.verdict == "DENY"
    assert decision.rule_ids == ["R-DENY-06"]
    assert ctx.upstream.calls == []


# --- e) serveur inconnu -------------------------------------------------------


def test_mcp_unknown_server_is_deny_06(ctx):
    body = _body("read_file", "x")
    body["tool"] = "ghost"
    decision = ctx.pipeline.handle(body, AGENT_KEY)
    assert decision.verdict == "DENY"
    assert decision.rule_ids == ["R-DENY-06"]


# --- f) agent sans droit sur demo_drive ---------------------------------------


def test_mcp_agent_without_allowed_is_deny_02(tmp_path):
    c = _build(tmp_path, allowed={"google_drive": ["read_file"]})
    try:
        decision = c.pipeline.handle(
            _body("read_file", "Team_Roadmap.md"), AGENT_KEY
        )
        assert decision.verdict == "DENY"
        assert decision.rule_ids == ["R-DENY-02"]
        assert c.upstream.calls == []
    finally:
        c.store.close()


# --- g) approbation -> execution via l'amont ----------------------------------


def test_mcp_approval_then_upstream_executes(ctx):
    ctx.pipeline.handle(_body("read_file", "vendor_notes.txt"), AGENT_KEY)
    decision = ctx.pipeline.handle(
        _body(
            "share_file",
            "Confidential_Audit_Report.pdf",
            {"email": "audit@external.example"},
        ),
        AGENT_KEY,
    )
    assert decision.verdict == "REVIEW"
    approval_id = decision.approval_id

    out = ctx.approvals.decide(
        approval_id,
        APPROVER_KEY,
        ApprovalDecisionIn(decision="approve", justification="validé par alice"),
    )
    assert out["action_status"] == "EXECUTED"
    # L'amont recoit ALORS le share_file.
    assert ("share_file", {"email": "audit@external.example"}) in ctx.upstream.calls
