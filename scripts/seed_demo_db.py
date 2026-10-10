"""Remplit une base SQLite de démonstration via SQLiteStore et EvidenceVault.

Jamais d'écriture SQL directe : tout passe par le Store et le Vault, de sorte
que la chaîne de preuves reste cohérente et vérifiable par verify().

Chemin de la base : variable d'environnement POLICE_DB_PATH si définie
(cf. .env.example), sinon "police.db". Option --reset pour repartir d'un
fichier vierge.
"""

import argparse
import os
from collections import Counter
from datetime import datetime, timedelta, timezone

from contracts.models import ActionRequest, params_hash
from police.evidence.vault import EvidenceVault
from police.store.sqlite_store import SQLiteStore

POLICY_VERSION = "demo-1"
DEFAULT_DB_PATH = "police.db"
ENV_DB_PATH = "POLICE_DB_PATH"


def _db_path_from_env() -> str:
    """Chemin de la base : POLICE_DB_PATH si défini, sinon police.db."""
    return os.environ.get(ENV_DB_PATH, DEFAULT_DB_PATH)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _compute_params_hash(tool, action, resource_id, parameters) -> str:
    """params_hash via le modèle figé de contracts/models.py (contrat 7)."""
    req = ActionRequest(
        tool=tool,
        action=action,
        resource_id=resource_id,
        parameters=parameters,
        session_id="sess-demo-hash",
        task_id="task-demo-hash",
    )
    return params_hash(req)


def _action(
    action_id,
    agent_id,
    user_id,
    session_id,
    tool,
    action,
    resource_id,
    params,
    verdict,
    status,
    rule_ids,
    reasons,
    created_at,
    approval_id=None,
    result=None,
) -> dict:
    """Construit un dict action conforme au contrat."""
    return {
        "action_id": action_id,
        "agent_id": agent_id,
        "user_id": user_id,
        "session_id": session_id,
        "tool": tool,
        "action": action,
        "resource_id": resource_id,
        "params": params,
        "params_hash": _compute_params_hash(tool, action, resource_id, params),
        "verdict": verdict,
        "status": status,
        "rule_ids": rule_ids,
        "reasons": reasons,
        "policy_version": POLICY_VERSION,
        "approval_id": approval_id,
        "result": result,
        "created_at": created_at,
    }


DEFAULT_TTL_MINUTES = 10


def seed(store: SQLiteStore, ttl_minutes: int = DEFAULT_TTL_MINUTES) -> None:
    """Insère les 6 actions, approbations, sessions et événements de démo.

    ttl_minutes contrôle l'expiration de l'approbation pending AP-0001
    (expires_at = created_at + ttl_minutes)."""
    vault = EvidenceVault(store)
    now = _now()
    ts = _iso(now)

    # ------------------------------------------------------------------ PA-0001
    # agent-research, read_file Team_Roadmap.md, ALLOW, EXECUTED.
    a1 = _action(
        "PA-0001", "agent-research", "user-claire", "sess-demo-1",
        "google_drive", "read_file", "Team_Roadmap.md", {},
        "ALLOW", "EXECUTED", ["R-ALLOW-01"],
        ["read_file autorisé : agent dans l'ACL."], ts,
        result={"content": "<contenu de Team_Roadmap.md>", "trusted": True},
    )
    store.put_action(a1)
    vault.record("REQUESTED", "PA-0001", {"request": "read_file Team_Roadmap.md"}, POLICY_VERSION)
    vault.record("DECIDED", "PA-0001", {"verdict": "ALLOW", "rule_ids": ["R-ALLOW-01"]}, POLICY_VERSION)
    vault.record("EXECUTED", "PA-0001", {"result": {"trusted": True}}, POLICY_VERSION)
    # ------------------------------------------------------------------ PA-0002
    # agent-assistant, read_file vendor_notes.txt, ALLOW, EXECUTED.
    # La session sess-demo-1 devient tainted (lecture d'une ressource non fiable).
    a2 = _action(
        "PA-0002", "agent-assistant", "user-claire", "sess-demo-1",
        "google_drive", "read_file", "vendor_notes.txt", {},
        "ALLOW", "EXECUTED", ["R-ALLOW-01"],
        ["read_file autorisé ; ressource non fiable, session marquée tainted."], ts,
        result={"content": "<contenu de vendor_notes.txt>", "trusted": False},
    )
    store.put_action(a2)
    store.set_session(
        {"session_id": "sess-demo-1", "tainted": True, "taint_sources": ["vendor_notes.txt"]}
    )
    vault.record("REQUESTED", "PA-0002", {"request": "read_file vendor_notes.txt"}, POLICY_VERSION)
    vault.record("DECIDED", "PA-0002", {"verdict": "ALLOW", "rule_ids": ["R-ALLOW-01"]}, POLICY_VERSION)
    vault.record("EXECUTED", "PA-0002", {"result": {"trusted": False}, "tainted": True}, POLICY_VERSION)

    # ------------------------------------------------------------------ PA-0003
    # agent-assistant, même session (tainted), share_file confidentiel vers
    # l'externe : REVIEW R-REV-01 (confidentiel à l'extérieur) + R-REV-02
    # (session tainted + action sensible). Approbation AP-0001 pending.
    a3_params = {"recipient": "audit@external.example", "role": "reader"}
    a3 = _action(
        "PA-0003", "agent-assistant", "user-claire", "sess-demo-1",
        "google_drive", "share_file", "Confidential_Audit_Report.pdf", a3_params,
        "REVIEW", "PENDING_REVIEW", ["R-REV-01", "R-REV-02"],
        [
            "Fichier confidentiel partagé à l'extérieur.",
            "Session tainted et action sensible.",
        ], ts,
        approval_id="AP-0001",
    )
    store.put_action(a3)
    approval = {
        "approval_id": "AP-0001",
        "action_id": "PA-0003",
        "params_hash": a3["params_hash"],
        "status": "pending",
        "created_at": ts,
        "expires_at": _iso(now + timedelta(minutes=ttl_minutes)),
        "approver_id": None,
        "decision": None,
        "justification": None,
        "decided_at": None,
    }
    store.put_approval(approval)
    vault.record("REQUESTED", "PA-0003", {"request": "share_file Confidential_Audit_Report.pdf"}, POLICY_VERSION)
    vault.record("DECIDED", "PA-0003", {"verdict": "REVIEW", "rule_ids": ["R-REV-01", "R-REV-02"], "approval_id": "AP-0001"}, POLICY_VERSION)

    # ------------------------------------------------------------------ PA-0004
    # agent-assistant, send_email vers domaine bloqué : DENY R-DENY-05, DENIED.
    a4_params = {"to": "drop@pastebin.example", "subject": "FYI", "body": "See attached."}
    a4 = _action(
        "PA-0004", "agent-assistant", "user-claire", "sess-demo-1",
        "mail", "send_email", "Q3_Financials.xlsx", a4_params,
        "DENY", "DENIED", ["R-DENY-05"],
        ["Destinataire sur un domaine bloqué (pastebin.example)."], ts,
    )
    store.put_action(a4)
    vault.record("REQUESTED", "PA-0004", {"request": "send_email Q3_Financials.xlsx"}, POLICY_VERSION)
    vault.record("DECIDED", "PA-0004", {"verdict": "DENY", "rule_ids": ["R-DENY-05"]}, POLICY_VERSION)
    vault.record("BLOCKED", "PA-0004", {"reason": "R-DENY-05"}, POLICY_VERSION)

    # ------------------------------------------------------------------ PA-0005
    # agent-ops, delete_file : REVIEW R-REV-03, approuvé par approver-alice,
    # puis EXECUTED. Approbation AP-0002 approved.
    a5 = _action(
        "PA-0005", "agent-ops", "user-claire", "sess-demo-2",
        "google_drive", "delete_file", "Team_Roadmap.md", {},
        "REVIEW", "EXECUTED", ["R-REV-03"],
        ["Toute suppression de fichier passe en REVIEW."], ts,
        approval_id="AP-0002", result={"deleted": True},
    )
    store.put_action(a5)
    approved = {
        "approval_id": "AP-0002",
        "action_id": "PA-0005",
        "params_hash": a5["params_hash"],
        "status": "approved",
        "created_at": ts,
        "expires_at": _iso(now + timedelta(minutes=10)),
        "approver_id": "approver-alice",
        "decision": "approve",
        "justification": "Roadmap obsolète, suppression validée après revue.",
        "decided_at": _iso(now + timedelta(seconds=30)),
    }
    store.put_approval(approved)
    vault.record("REQUESTED", "PA-0005", {"request": "delete_file Team_Roadmap.md"}, POLICY_VERSION)
    vault.record("DECIDED", "PA-0005", {"verdict": "REVIEW", "rule_ids": ["R-REV-03"], "approval_id": "AP-0002"}, POLICY_VERSION)
    vault.record("APPROVAL_DECIDED", "PA-0005", {"decision": "approve", "approver_id": "approver-alice"}, POLICY_VERSION)
    vault.record("EXECUTED", "PA-0005", {"result": {"deleted": True}}, POLICY_VERSION)

    # ------------------------------------------------------------------ PA-0006
    # agent-ops, share_file restricted vers l'externe : DENY R-DENY-04, DENIED.
    a6_params = {"recipient": "x@external.example", "role": "reader"}
    a6 = _action(
        "PA-0006", "agent-ops", "user-david", "sess-demo-2",
        "google_drive", "share_file", "HR_Salaries.xlsx", a6_params,
        "DENY", "DENIED", ["R-DENY-04"],
        ["Fichier restricted partagé hors de l'entreprise."], ts,
    )
    store.put_action(a6)
    vault.record("REQUESTED", "PA-0006", {"request": "share_file HR_Salaries.xlsx"}, POLICY_VERSION)
    vault.record("DECIDED", "PA-0006", {"verdict": "DENY", "rule_ids": ["R-DENY-04"]}, POLICY_VERSION)
    vault.record("BLOCKED", "PA-0006", {"reason": "R-DENY-04"}, POLICY_VERSION)


def print_summary(store: SQLiteStore) -> None:
    """Affiche un résumé : actions par statut, nombre d'événements, verify()."""
    actions = store.list_actions()
    by_status = Counter(a["status"] for a in actions)
    events = store.list_events()
    verdict = EvidenceVault(store).verify()

    print(f"Actions : {len(actions)}")
    for status, count in sorted(by_status.items()):
        print(f"  {status} : {count}")
    pending = len(store.list_approvals(status="pending"))
    print(f"Approbations pending : {pending}")
    print(f"Événements : {len(events)}")
    print(f"verify() : valid={verdict['valid']}, broken_at={verdict['broken_at']}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Remplit une base SQLite de démonstration.")
    parser.add_argument(
        "--reset", action="store_true",
        help="Supprime le fichier de base avant de le remplir.",
    )
    parser.add_argument(
        "--db-path", default=None,
        help="Chemin de la base (sinon POLICE_DB_PATH ou police.db).",
    )
    parser.add_argument(
        "--ttl-minutes", type=int, default=DEFAULT_TTL_MINUTES,
        help="Minutes avant expiration de l'approbation pending AP-0001 (défaut 10).",
    )
    args = parser.parse_args()

    db_path = args.db_path or _db_path_from_env()

    if args.reset and os.path.exists(db_path):
        os.remove(db_path)

    store = SQLiteStore(db_path)
    try:
        seed(store, ttl_minutes=args.ttl_minutes)
        print(f"Base de démonstration remplie : {db_path}")
        print_summary(store)
    finally:
        store.close()


if __name__ == "__main__":
    main()
