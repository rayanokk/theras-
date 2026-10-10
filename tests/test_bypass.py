"""Tentatives de contournement de Theras : un test par attaque.

Chaque test passe par l'API (TestClient) avec les vraies donnees (identities.json,
drive_seed.json) et les cles de test, sauf mention contraire. Le pipeline est
construit sans scoreur de risque (risk_scorer=None), sauf le test 14.

Ces tests sont adversariaux : ils ne doivent jamais etre "adaptes" pour passer.
Un echec signale soit une vraie faille, soit une regression.
"""

import ast
import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
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
from police.policy.engine import load_policy
from police.policy.taint import TaintTracker
from police.risk.scorer import make_scorer
from police.store.sqlite_store import SQLiteStore

REPO = Path(__file__).resolve().parents[1]
POLICIES = REPO / "policies" / "policies.yaml"
IDENTITIES = REPO / "data" / "identities.json"

KEY_RESEARCH = "k-research"
KEY_OPS = "k-ops"
KEY_ASSISTANT = "k-assistant"
KEY_ALICE = "k-alice"


class FakeClock:
    """Horloge injectable pour l'expiration des approbations."""

    def __init__(self, start: datetime) -> None:
        self.current = start

    def __call__(self) -> datetime:
        return self.current

    def advance(self, delta: timedelta) -> None:
        self.current += delta


@pytest.fixture
def env_keys(monkeypatch):
    monkeypatch.setenv("AGENT_KEY_RESEARCH", KEY_RESEARCH)
    monkeypatch.setenv("AGENT_KEY_OPS", KEY_OPS)
    monkeypatch.setenv("AGENT_KEY_ASSISTANT", KEY_ASSISTANT)
    monkeypatch.setenv("APPROVER_KEY_ALICE", KEY_ALICE)
    monkeypatch.setenv("APPROVER_KEY_BOB", "k-bob")


def _build(tmp_path, risk_scorer=None, clock=None):
    """Construit la pile complete et renvoie un contexte expose aux tests."""
    db_path = str(tmp_path / "test.db")
    store = SQLiteStore(db_path)
    drive = DriveMock()
    mail = MailMock(drive)
    vault = EvidenceVault(store)
    policy = load_policy(POLICIES)
    identities = IdentityRegistry(IDENTITIES)
    taint = TaintTracker(store)
    pipeline = Pipeline(
        policy=policy,
        identities=identities,
        connectors={"google_drive": drive, "mail": mail},
        store=store,
        vault=vault,
        taint=taint,
        risk_scorer=risk_scorer,
    )
    if clock is not None:
        approvals = ApprovalService(store, vault, pipeline, identities, now=clock)
    else:
        approvals = ApprovalService(store, vault, pipeline, identities)
    app = create_app(pipeline, store, vault, identities, approvals)

    class Ctx:
        pass

    c = Ctx()
    c.db_path = db_path
    c.store = store
    c.drive = drive
    c.mail = mail
    c.vault = vault
    c.policy = policy
    c.pipeline = pipeline
    c.approvals = approvals
    c.client = TestClient(app)
    return c


@pytest.fixture
def ctx(tmp_path, env_keys):
    c = _build(tmp_path)
    with c.client:
        yield c
    c.store.close()


# --- Corps de requetes ---------------------------------------------------------


def _read(resource_id, agent_id, session="sess-1"):
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


def _post(client, body, key):
    return client.post("/v1/actions", json=body, headers={"X-API-Key": key})


def _trigger_flagship_review(client):
    """Demo phare via HTTP : renvoie (action_id, approval_id)."""
    _post(client, _read("vendor_notes.txt", "agent-assistant"), KEY_ASSISTANT)
    resp = _post(
        client,
        _share(
            "agent-assistant",
            "Confidential_Audit_Report.pdf",
            "audit@external.example",
        ),
        KEY_ASSISTANT,
    )
    assert resp.status_code == 202
    data = resp.json()
    return data["action_id"], data["approval_id"]


# --- 1 -------------------------------------------------------------------------


def test_agent_cannot_import_connectors():
    """Attaque : l'agent importe directement les connecteurs/stores pour agir sans le Gateway.
    Attendu : runner.py et tools.py n'importent aucun module interne du Gateway."""
    forbidden = (
        "police.connectors",
        "police.store",
        "police.evidence",
        "police.gateway.pipeline",
    )
    for name in ("runner.py", "tools.py"):
        source = (REPO / "agent" / name).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.append(node.module)
        for mod in imported:
            assert not any(
                mod == f or mod.startswith(f + ".") for f in forbidden
            ), f"{name} importe {mod}"


# --- 2 -------------------------------------------------------------------------


def test_spoofed_agent_id(ctx):
    """Attaque : usurper une identite plus privilegiee via le champ agent_id declaratif.
    Attendu : 403 R-DENY-01, l'identite reelle (cle) prime sur le champ declare."""
    body = {
        "agent_id": "agent-ops",
        "tool": "google_drive",
        "action": "delete_file",
        "resource_id": "Team_Roadmap.md",
        "parameters": {},
        "session_id": "sess-1",
        "task_id": "task-1",
    }
    resp = _post(ctx.client, body, KEY_RESEARCH)
    assert resp.status_code == 403
    assert resp.json()["rule_ids"] == ["R-DENY-01"]


# --- 3 -------------------------------------------------------------------------


def test_self_approval_forbidden(ctx):
    """Attaque : l'agent approuve lui-meme son action mise en REVIEW.
    Attendu : 403, l'approbation reste pending."""
    _, approval_id = _trigger_flagship_review(ctx.client)
    resp = ctx.client.post(
        f"/v1/approvals/{approval_id}/decide",
        json={"decision": "approve", "justification": "je m'auto-approuve"},
        headers={"X-API-Key": KEY_ASSISTANT},
    )
    assert resp.status_code == 403
    assert ctx.store.get_approval(approval_id)["status"] == "pending"


# --- 4 -------------------------------------------------------------------------


def test_params_changed_after_review(ctx):
    """Attaque : modifier les parametres apres la REVIEW pour detourner une approbation valide.
    Attendu : seule la verif du params_hash arrete l'action -> DENIED, rien n'est partage."""
    action_id, approval_id = _trigger_flagship_review(ctx.client)
    action = ctx.store.get_action(action_id)
    # Nouveau destinataire externe NON bloque : si l'action passait, elle serait
    # au pire REVIEW (R-REV-01), jamais un DENY de domaine. Seul le params_hash
    # qui ne colle plus doit la stopper (PARAMS_CHANGED).
    action["request"]["parameters"]["recipient"] = "attacker@external.example"
    ctx.store.put_action(action)

    resp = ctx.client.post(
        f"/v1/approvals/{approval_id}/decide",
        json={"decision": "approve", "justification": "approbation detournee"},
        headers={"X-API-Key": KEY_ALICE},
    )
    assert resp.status_code == 200
    assert resp.json()["action_status"] == "DENIED"
    blocked = [
        e for e in ctx.store.list_events(action_id) if e["type"] == "BLOCKED"
    ]
    assert any(
        "PARAMS_CHANGED" in (e["payload"].get("rule_ids") or []) for e in blocked
    )
    # Le fichier n'a ete partage avec PERSONNE : ni l'ancien ni le nouveau destinataire.
    shares = ctx.drive._shares.get("Confidential_Audit_Report.pdf", [])
    recipients = {s["recipient"] for s in shares}
    assert "attacker@external.example" not in recipients
    assert "audit@external.example" not in recipients


# --- 5 -------------------------------------------------------------------------


def test_expired_approval(tmp_path, env_keys):
    """Attaque : approuver une action apres l'expiration de la fenetre d'approbation.
    Attendu : 410, action EXPIRED, evenement EXPIRED journalise."""
    clock = FakeClock(datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc))
    c = _build(tmp_path, clock=clock)
    with c.client:
        action_id, approval_id = _trigger_flagship_review(c.client)
        approval = c.store.get_approval(approval_id)
        expires_at = datetime.fromisoformat(approval["expires_at"])
        clock.current = expires_at + timedelta(minutes=1)
        resp = c.client.post(
            f"/v1/approvals/{approval_id}/decide",
            json={"decision": "approve", "justification": "trop tard pour approuver"},
            headers={"X-API-Key": KEY_ALICE},
        )
        assert resp.status_code == 410
        assert c.store.get_action(action_id)["status"] == "EXPIRED"
        types = [e["type"] for e in c.store.list_events(action_id)]
        assert "EXPIRED" in types
    c.store.close()


# --- 6 -------------------------------------------------------------------------


def test_double_decide_race(ctx):
    """Attaque : deux approbations concurrentes pour executer l'action deux fois.
    Attendu : une seule execution (un seul EXECUTED), l'autre appel recoit 409."""
    action_id, approval_id = _trigger_flagship_review(ctx.client)
    codes: list[int] = []

    def worker():
        r = ctx.client.post(
            f"/v1/approvals/{approval_id}/decide",
            json={"decision": "approve", "justification": "approbation concurrente"},
            headers={"X-API-Key": KEY_ALICE},
        )
        codes.append(r.status_code)

    t1 = threading.Thread(target=worker)
    t2 = threading.Thread(target=worker)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert sorted(codes) == [200, 409]
    executed = [e for e in ctx.store.list_events(action_id) if e["type"] == "EXECUTED"]
    assert len(executed) == 1


# --- 7 -------------------------------------------------------------------------


def test_policy_changed_before_execution(ctx):
    """Attaque : l'etat change entre la REVIEW et l'execution (destinataire devenu interdit).
    Attendu : la revalidation rejoue la politique courante -> DENIED, BLOCKED R-DENY-05."""
    action_id, approval_id = _trigger_flagship_review(ctx.client)
    # external.example devient un domaine bloque dans la politique chargee.
    ctx.policy.blocked_domains.append("external.example")

    resp = ctx.client.post(
        f"/v1/approvals/{approval_id}/decide",
        json={"decision": "approve", "justification": "approuve mais domaine bloque"},
        headers={"X-API-Key": KEY_ALICE},
    )
    assert resp.status_code == 200
    assert resp.json()["action_status"] == "DENIED"
    blocked = [
        e for e in ctx.store.list_events(action_id) if e["type"] == "BLOCKED"
    ]
    assert any("R-DENY-05" in (e["payload"].get("rule_ids") or []) for e in blocked)


# --- 8 -------------------------------------------------------------------------


def test_session_switch_does_not_clear_taint(ctx):
    """Attaque : lire un document piege dans une session, puis agir dans une autre session.
    Attendu : seul le taint lie a l'identite reelle produit la REVIEW (durcissement R-REV-02)."""
    # Team_Roadmap.md : classification "internal", agent-assistant dans l'ACL
    # (data/drive_seed.json). Partage vers un destinataire @acme.example -> R-ALLOW-04.

    # 1. Temoin : session neuve, aucune lecture prealable -> ALLOW franc.
    witness = _post(
        ctx.client,
        _share(
            "agent-assistant",
            "Team_Roadmap.md",
            "colleague@acme.example",
            session="sess-witness",
        ),
        KEY_ASSISTANT,
    )
    assert witness.status_code == 200
    assert witness.json()["verdict"] == "ALLOW"
    assert witness.json()["rule_ids"] == ["R-ALLOW-04"]

    # 2. Attaque : lecture d'un document non fiable dans sess-1, puis EXACTEMENT
    #    le meme partage dans sess-2, jamais utilisee.
    _post(
        ctx.client,
        _read("vendor_notes.txt", "agent-assistant", session="sess-1"),
        KEY_ASSISTANT,
    )
    resp = _post(
        ctx.client,
        _share(
            "agent-assistant",
            "Team_Roadmap.md",
            "colleague@acme.example",
            session="sess-2",
        ),
        KEY_ASSISTANT,
    )
    assert resp.status_code == 202
    rule_ids = resp.json()["rule_ids"]
    assert resp.json()["verdict"] == "REVIEW"
    # La REVIEW vient UNIQUEMENT du durcissement : R-REV-02 present, et aucune
    # regle de stage review (qui aurait justifie la REVIEW autrement).
    assert "R-REV-02" in rule_ids
    assert not ({"R-REV-01", "R-REV-03", "R-REV-05"} & set(rule_ids))


# --- 9 -------------------------------------------------------------------------


def test_malformed_requests_are_denied_not_crashed(ctx):
    """Attaque : corps malformes pour provoquer un crash ou contourner la validation.
    Attendu : chaque cas -> 403 R-DENY-06, jamais 422/500, un DECIDED journalise."""
    base = _read("Company_Brochure.pdf", "agent-research")

    unknown = dict(base)
    unknown["unexpected"] = "boom"

    bad_action = dict(base)
    bad_action["action"] = "format_disk"

    traversal = dict(base)
    traversal["resource_id"] = "../secret"

    cases = [unknown, bad_action, traversal, ["pas", "un", "objet"]]
    for body in cases:
        resp = _post(ctx.client, body, KEY_RESEARCH)
        assert resp.status_code == 403, body
        data = resp.json()
        assert data["rule_ids"] == ["R-DENY-06"], body
        events = ctx.store.list_events(data["action_id"])
        assert any(e["type"] == "DECIDED" for e in events), body


# --- 10 ------------------------------------------------------------------------


def test_blocked_domain(ctx):
    """Attaque : exfiltrer une piece jointe confidentielle vers un domaine de depot bloque.
    Attendu : 403 R-DENY-05, rien n'est envoye par le MailMock."""
    body = {
        "agent_id": "agent-assistant",
        "tool": "mail",
        "action": "send_email",
        "resource_id": "Q3_Financials.xlsx",
        "parameters": {
            "to": "drop@pastebin.example",
            "subject": "fuite",
            "body": "voici le fichier",
        },
        "session_id": "sess-1",
        "task_id": "task-1",
    }
    resp = _post(ctx.client, body, KEY_ASSISTANT)
    assert resp.status_code == 403
    assert "R-DENY-05" in resp.json()["rule_ids"]
    assert ctx.mail.outbox == []


# --- 11 ------------------------------------------------------------------------


def test_agent_cannot_read_others_actions(ctx):
    """Attaque : un agent lit la liste globale ou l'action d'un autre agent.
    Attendu : liste -> 403 ; action d'autrui -> 404 (masquee)."""
    resp_list = ctx.client.get("/v1/actions", headers={"X-API-Key": KEY_RESEARCH})
    assert resp_list.status_code == 403

    post = _post(
        ctx.client, _read("vendor_notes.txt", "agent-assistant"), KEY_ASSISTANT
    )
    action_id = post.json()["action_id"]
    resp_get = ctx.client.get(
        f"/v1/actions/{action_id}", headers={"X-API-Key": KEY_RESEARCH}
    )
    assert resp_get.status_code == 404


# --- 12 ------------------------------------------------------------------------


def test_agent_cannot_read_evidence_or_approvals(ctx):
    """Attaque : un agent lit les preuves ou les approbations reservees aux approbateurs.
    Attendu : avec cle d'agent -> 403 ; sans cle -> 401."""
    routes = [
        "/v1/evidence",
        "/v1/evidence/verify",
        "/v1/evidence/export",
        "/v1/approvals",
    ]
    for route in routes:
        assert (
            ctx.client.get(route, headers={"X-API-Key": KEY_RESEARCH}).status_code
            == 403
        ), route
        assert ctx.client.get(route).status_code == 401, route


# --- 13 ------------------------------------------------------------------------


def test_evidence_tampering_detected(ctx):
    """Attaque : falsifier un evenement du journal de preuves directement en base.
    Attendu : vault.verify() detecte la rupture (valid False, broken_at = seq falsifie)."""
    # Au moins 5 evenements : deux actions (REQUESTED/DECIDED/EXECUTED chacune).
    _post(ctx.client, _read("Company_Brochure.pdf", "agent-research"), KEY_RESEARCH)
    _post(ctx.client, _read("Press_Release_Q3.txt", "agent-research"), KEY_RESEARCH)
    events = ctx.store.list_events()
    assert len(events) >= 5

    target_seq = events[len(events) // 2]["seq"]  # un evenement du milieu
    conn = sqlite3.connect(ctx.db_path)
    try:
        row = conn.execute(
            "SELECT data FROM events WHERE seq = ?", (target_seq,)
        ).fetchone()
        data = json.loads(row[0])
        data["payload"] = {"tampered": True}  # on NE recalcule PAS le hash
        conn.execute(
            "UPDATE events SET data = ? WHERE seq = ?",
            (json.dumps(data, ensure_ascii=False), target_seq),
        )
        conn.commit()
    finally:
        conn.close()

    result = ctx.vault.verify()
    assert result["valid"] is False
    assert result["broken_at"] == target_seq


# --- 14 ------------------------------------------------------------------------


def test_risk_scorer_failure_fails_closed(tmp_path, env_keys):
    """Attaque : faire tomber le scoreur de risque pour relacher une action sensible.
    Attendu : fail closed -> REVIEW R-REV-04, risk.source == llm_unavailable."""

    def boom(request, resource, tainted):
        raise RuntimeError("scorer down")

    c = _build(tmp_path, risk_scorer=boom)
    with c.client:
        resp = _post(
            c.client,
            _share("agent-ops", "Team_Roadmap.md", "colleague@acme.example"),
            KEY_OPS,
        )
        assert resp.status_code == 202
        data = resp.json()
        assert "R-REV-04" in data["rule_ids"]
        assert data["risk"]["source"] == "llm_unavailable"
    c.store.close()


# --- 15 ------------------------------------------------------------------------


def test_restricted_never_leaves(ctx):
    """Attaque : partager un fichier restricted a l'exterieur, meme via une approbation.
    Attendu : 403 R-DENY-04, aucune approbation creee (un humain ne peut lever ce DENY)."""
    resp = _post(
        ctx.client,
        _share("agent-ops", "HR_Salaries.xlsx", "contact@partner.example"),
        KEY_OPS,
    )
    assert resp.status_code == 403
    assert "R-DENY-04" in resp.json()["rule_ids"]
    assert ctx.store.list_approvals() == []
