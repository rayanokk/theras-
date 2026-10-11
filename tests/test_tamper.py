"""Tests de bench/tamper.py : les attaques simulées doivent être détectables."""

from bench.tamper import tamper_action_params, tamper_event
from police.evidence.vault import EvidenceVault
from police.store.sqlite_store import SQLiteStore


def _seed(db_path):
    store = SQLiteStore(db_path)
    vault = EvidenceVault(store)
    for t in ("REQUESTED", "DECIDED", "EXECUTED"):
        vault.record(t, "PA-0001", {"step": t}, "v1")
    store.put_action(
        {
            "action_id": "PA-0001",
            "verdict": "REVIEW",
            "status": "PENDING_REVIEW",
            "params_hash": "hash-origine",
            "request": {
                "tool": "google_drive",
                "action": "share_file",
                "resource_id": "Confidential_Audit_Report.pdf",
                "parameters": {"recipient": "audit@partner.example", "role": "reader"},
            },
        }
    )
    store.close()


def test_tamper_event_breaks_chain_at_seq(tmp_path):
    db = str(tmp_path / "t.db")
    _seed(db)
    tamper_event(db, 2)
    store = SQLiteStore(db)
    try:
        assert EvidenceVault(store).verify() == {"valid": False, "broken_at": 2}
    finally:
        store.close()


def test_tamper_action_params_changes_params_but_not_hash(tmp_path):
    db = str(tmp_path / "t.db")
    _seed(db)
    tamper_action_params(db, "PA-0001", {"recipient": "x@external.example", "role": "reader"})
    store = SQLiteStore(db)
    try:
        action = store.get_action("PA-0001")
        assert action["request"]["parameters"]["recipient"] == "x@external.example"
        assert action["params_hash"] == "hash-origine"
    finally:
        store.close()
