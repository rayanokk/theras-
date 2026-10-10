"""Tests d'integration du pipeline (police/gateway/pipeline.py).

On branche les vrais modules : SQLiteStore, DriveMock, MailMock, EvidenceVault,
IdentityRegistry sur data/identities.json et le vrai policies.yaml. Les cles
d'agent sont posees avec monkeypatch. execute() n'est appele qu'a travers le
pipeline : les tests le verifient indirectement (etat des mocks, verdict).
"""

from pathlib import Path

import pytest

from police.connectors.drive_mock import DriveMock
from police.connectors.mail_mock import MailMock
from police.evidence.vault import EvidenceVault
from police.gateway.pipeline import Pipeline
from police.identity import IdentityRegistry
from police.policy.engine import load_policy
from police.policy.taint import TaintTracker
from police.store.sqlite_store import SQLiteStore

REPO = Path(__file__).resolve().parents[1]
POLICIES = REPO / "policies" / "policies.yaml"
IDENTITIES = REPO / "data" / "identities.json"

KEY_RESEARCH = "k-research"
KEY_OPS = "k-ops"
KEY_ASSISTANT = "k-assistant"


@pytest.fixture
def env_keys(monkeypatch):
    monkeypatch.setenv("AGENT_KEY_RESEARCH", KEY_RESEARCH)
    monkeypatch.setenv("AGENT_KEY_OPS", KEY_OPS)
    monkeypatch.setenv("AGENT_KEY_ASSISTANT", KEY_ASSISTANT)
    monkeypatch.setenv("APPROVER_KEY_ALICE", "k-alice")
    monkeypatch.setenv("APPROVER_KEY_BOB", "k-bob")


@pytest.fixture
def ctx(tmp_path, env_keys):
    """Construit un pipeline complet et expose ses pieces pour les assertions."""
    store = SQLiteStore(str(tmp_path / "test.db"))
    drive = DriveMock()
    mail = MailMock(drive)
    vault = EvidenceVault(store)
    policy = load_policy(POLICIES)
    identities = IdentityRegistry(IDENTITIES)
    taint = TaintTracker(store)

    class Ctx:
        pass

    c = Ctx()
    c.store = store
    c.drive = drive
    c.mail = mail
    c.vault = vault
    c.policy = policy
    c.identities = identities
    c.taint = taint
    c.connectors = {"google_drive": drive, "mail": mail}

    def make(risk_scorer=None):
        return Pipeline(
            policy=policy,
            identities=identities,
            connectors=c.connectors,
            store=store,
            vault=vault,
            taint=taint,
            risk_scorer=risk_scorer,
        )

    c.make = make
    yield c
    store.close()


def _read(resource_id: str, session="sess-1", agent_id="agent-research"):
    return {
        "agent_id": agent_id,
        "tool": "google_drive",
        "action": "read_file",
        "resource_id": resource_id,
        "parameters": {},
        "session_id": session,
        "task_id": "task-1",
    }


def _share(agent_id, resource_id, recipient, session="sess-1"):
    return {
        "agent_id": agent_id,
        "tool": "google_drive",
        "action": "share_file",
        "resource_id": resource_id,
        "parameters": {"recipient": recipient, "role": "reader"},
        "session_id": session,
        "task_id": "task-1",
    }


# --- Lecture normale ----------------------------------------------------------


def test_normal_read_allow_and_chained_evidence(ctx):
    pipe = ctx.make()
    decision = pipe.handle(_read("Company_Brochure.pdf"), KEY_RESEARCH)
    assert decision.verdict == "ALLOW"
    assert decision.status == "EXECUTED"
    assert "R-ALLOW-01" in decision.rule_ids

    events = ctx.store.list_events(decision.action_id)
    assert [e["type"] for e in events] == ["REQUESTED", "DECIDED", "EXECUTED"]
    assert ctx.vault.verify()["valid"] is True


# --- Requete invalide ---------------------------------------------------------


def test_unknown_field_is_deny_06_and_blocked(ctx):
    pipe = ctx.make()
    body = _read("Company_Brochure.pdf")
    body["unexpected"] = "boom"
    decision = pipe.handle(body, KEY_RESEARCH)
    assert decision.verdict == "DENY"
    assert "R-DENY-06" in decision.rule_ids
    types = [e["type"] for e in ctx.store.list_events(decision.action_id)]
    assert "BLOCKED" in types


# --- Identite -----------------------------------------------------------------


def test_unknown_key_is_deny_01_without_execute(ctx):
    pipe = ctx.make()
    decision = pipe.handle(_read("Company_Brochure.pdf"), "wrong-key")
    assert decision.verdict == "DENY"
    assert "R-DENY-01" in decision.rule_ids
    # Aucune lecture n'a eu lieu : pas d'evenement EXECUTED.
    types = [e["type"] for e in ctx.store.list_events(decision.action_id)]
    assert "EXECUTED" not in types


def test_declared_agent_id_mismatch_is_deny_01(ctx):
    pipe = ctx.make()
    body = _read("Company_Brochure.pdf")
    body["agent_id"] = "agent-ops"  # declare != cle de research
    decision = pipe.handle(body, KEY_RESEARCH)
    assert decision.verdict == "DENY"
    assert decision.rule_ids == ["R-DENY-01"]


def test_research_delete_is_deny_02(ctx):
    pipe = ctx.make()
    body = {
        "agent_id": "agent-research",
        "tool": "google_drive",
        "action": "delete_file",
        "resource_id": "Company_Brochure.pdf",
        "parameters": {},
        "session_id": "sess-1",
        "task_id": "task-1",
    }
    decision = pipe.handle(body, KEY_RESEARCH)
    assert decision.verdict == "DENY"
    assert "R-DENY-02" in decision.rule_ids


# --- Explicabilite : un fait non verifie est absent, pas False ----------------


def test_delete_out_of_rights_yields_only_deny_02(ctx):
    # agent-research n'a pas delete_file : R-DENY-02 seul, pas de R-DENY-03 a cote.
    pipe = ctx.make()
    body = {
        "agent_id": "agent-research",
        "tool": "google_drive",
        "action": "delete_file",
        "resource_id": "Team_Roadmap.md",
        "parameters": {},
        "session_id": "sess-1",
        "task_id": "task-1",
    }
    decision = pipe.handle(body, KEY_RESEARCH)
    assert decision.verdict == "DENY"
    assert decision.rule_ids == ["R-DENY-02"]


def test_unknown_key_yields_only_deny_01(ctx):
    # Cle inconnue : R-DENY-01 seul, pas de R-DENY-02 a cote.
    pipe = ctx.make()
    decision = pipe.handle(_read("Company_Brochure.pdf"), "wrong-key")
    assert decision.verdict == "DENY"
    assert decision.rule_ids == ["R-DENY-01"]


def test_read_outside_acl_yields_deny_03(ctx):
    # agent-assistant n'est pas dans l'ACL de HR_Salaries.xlsx (restricted, ops).
    pipe = ctx.make()
    body = {
        "agent_id": "agent-assistant",
        "tool": "google_drive",
        "action": "read_file",
        "resource_id": "HR_Salaries.xlsx",
        "parameters": {},
        "session_id": "sess-1",
        "task_id": "task-1",
    }
    decision = pipe.handle(body, KEY_ASSISTANT)
    assert decision.verdict == "DENY"
    assert decision.rule_ids == ["R-DENY-03"]


def test_missing_connector_is_deny_03_fail_closed(ctx):
    # Connecteur retire du dict : resource_ok fail closed -> DENY R-DENY-03.
    ctx.connectors.pop("google_drive")
    pipe = ctx.make()
    decision = pipe.handle(_read("Company_Brochure.pdf"), KEY_RESEARCH)
    assert decision.verdict == "DENY"
    assert "R-DENY-03" in decision.rule_ids


# --- ACL / resource_id ---------------------------------------------------------


def test_share_file_with_root_resource_is_deny(ctx):
    # root n'est exempte d'ACL que pour list_files : un share_file sur "root"
    # ne trouve pas de fichier -> DENY (R-DENY-03).
    pipe = ctx.make()
    decision = pipe.handle(
        _share("agent-ops", "root", "colleague@acme.example"), KEY_OPS
    )
    assert decision.verdict == "DENY"
    assert "R-DENY-03" in decision.rule_ids


def test_action_record_stores_request_and_agent_id(ctx):
    pipe = ctx.make()
    decision = pipe.handle(_read("Company_Brochure.pdf"), KEY_RESEARCH)
    stored = ctx.store.get_action(decision.action_id)
    assert stored is not None
    assert stored["agent_id"] == "agent-research"
    assert stored["declared_agent_id"] == "agent-research"
    assert stored["session_id"] == "sess-1"
    assert stored["created_at"]
    assert stored["request"]["action"] == "read_file"
    assert stored["request"]["resource_id"] == "Company_Brochure.pdf"


def test_describe_exception_is_deny_03_with_decided_and_blocked(ctx):
    # Un connecteur dont describe leve une exception : le pipeline continue,
    # resource_ok = False -> DENY R-DENY-03, avec DECIDED et BLOCKED journalises.
    class BoomDrive:
        name = "google_drive"

        def describe(self, action, resource_id, params):
            raise RuntimeError("describe down")

        def execute(self, action, resource_id, params):  # pragma: no cover
            raise AssertionError("execute ne doit pas etre appele")

    ctx.connectors["google_drive"] = BoomDrive()
    pipe = ctx.make()
    decision = pipe.handle(_read("Company_Brochure.pdf"), KEY_RESEARCH)
    assert decision.verdict == "DENY"
    assert "R-DENY-03" in decision.rule_ids
    types = [e["type"] for e in ctx.store.list_events(decision.action_id)]
    assert "DECIDED" in types
    assert "BLOCKED" in types


# --- Taint --------------------------------------------------------------------


def test_tainted_then_public_internal_share_is_review_02(ctx):
    pipe = ctx.make()
    # Lecture d'un document non fiable -> session contaminee.
    r = pipe.handle(_read("vendor_notes.txt", agent_id="agent-ops"), KEY_OPS)
    assert r.verdict == "ALLOW"
    assert ctx.taint.is_tainted("sess-1") is True
    # Partage d'un fichier public en interne : ALLOW durci en REVIEW par R-REV-02.
    decision = pipe.handle(
        _share("agent-ops", "Company_Brochure.pdf", "colleague@acme.example"),
        KEY_OPS,
    )
    assert decision.verdict == "REVIEW"
    assert "R-REV-02" in decision.rule_ids


def test_flagship_demo_confidential_external_tainted(ctx):
    pipe = ctx.make()
    pipe.handle(_read("vendor_notes.txt", agent_id="agent-ops"), KEY_OPS)
    assert ctx.taint.is_tainted("sess-1") is True
    decision = pipe.handle(
        _share(
            "agent-ops",
            "Confidential_Audit_Report.pdf",
            "audit@external.example",
        ),
        KEY_OPS,
    )
    assert decision.verdict == "REVIEW"
    assert "R-REV-01" in decision.rule_ids
    assert "R-REV-02" in decision.rule_ids


# --- Domaine bloque -----------------------------------------------------------


def test_mail_to_blocked_domain_is_deny_05(ctx):
    pipe = ctx.make()
    body = {
        "agent_id": "agent-assistant",
        "tool": "mail",
        "action": "send_email",
        "resource_id": "Q3_Financials.xlsx",
        "parameters": {
            "to": "drop@pastebin.example",
            "subject": "x",
            "body": "y",
        },
        "session_id": "sess-1",
        "task_id": "task-1",
    }
    decision = pipe.handle(body, KEY_ASSISTANT)
    assert decision.verdict == "DENY"
    assert "R-DENY-05" in decision.rule_ids


# --- Scoreur de risque --------------------------------------------------------


def test_risk_scorer_exception_hardens_to_review_04(ctx):
    def boom(request, resource_info, tainted):
        raise RuntimeError("scorer down")

    pipe = ctx.make(risk_scorer=boom)
    decision = pipe.handle(
        _share("agent-ops", "Company_Brochure.pdf", "colleague@acme.example"),
        KEY_OPS,
    )
    assert decision.verdict == "REVIEW"
    assert "R-REV-04" in decision.rule_ids


def test_risk_scorer_exception_is_fail_closed_on_internal_share(ctx):
    # Partage d'un fichier internal vers un destinataire interne : normalement
    # ALLOW (R-ALLOW-04). Un scoreur qui plante doit durcir en REVIEW (R-REV-04)
    # sans propager l'exception, et renseigner un RiskSignal "indisponible".
    def boom(request, resource_info, tainted):
        raise RuntimeError("scorer down")

    pipe = ctx.make(risk_scorer=boom)
    decision = pipe.handle(
        _share("agent-ops", "Team_Roadmap.md", "colleague@acme.example"),
        KEY_OPS,
    )
    assert decision.verdict == "REVIEW"
    assert "R-REV-04" in decision.rule_ids
    assert decision.risk is not None
    assert decision.risk.source.value == "llm_unavailable"
    assert decision.risk.signals == ["scorer_error: RuntimeError"]


def test_risk_scorer_not_called_when_deny(ctx):
    calls = []

    def spy(request, resource_info, tainted):
        calls.append(request)
        raise AssertionError("ne doit pas etre appele sur un DENY")

    pipe = ctx.make(risk_scorer=spy)
    # Cle inconnue -> DENY R-DENY-01 des la premiere evaluation.
    decision = pipe.handle(_read("Company_Brochure.pdf"), "wrong-key")
    assert decision.verdict == "DENY"
    assert calls == []
