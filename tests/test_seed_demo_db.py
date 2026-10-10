"""Test du script de démonstration scripts/seed_demo_db.py."""

from datetime import datetime, timedelta

from console.client import LocalClient
from scripts.seed_demo_db import seed
from police.evidence.vault import EvidenceVault
from police.store.sqlite_store import SQLiteStore


def test_seed_demo_db_populates_expected_state(tmp_path):
    db_path = str(tmp_path / "demo.db")

    store = SQLiteStore(db_path)
    try:
        seed(store)

        # 7 actions.
        assert len(store.list_actions()) == 7

        # Deux approbations pending (AP-0001 et AP-0003).
        assert len(store.list_approvals(status="pending")) == 2

        # Chaîne de preuves valide.
        assert EvidenceVault(store).verify() == {"valid": True, "broken_at": None}
    finally:
        store.close()


def test_pa_0003_decision_carries_approval_id(tmp_path):
    db_path = str(tmp_path / "demo_approval.db")

    store = SQLiteStore(db_path)
    seed(store)
    store.close()

    client = LocalClient(db_path=db_path)
    try:
        decisions = {d.action_id: d for d in client.list_actions()}
        assert decisions["PA-0003"].approval_id == "AP-0001"
        assert decisions["PA-0005"].approval_id == "AP-0002"
        assert decisions["PA-0001"].approval_id is None
    finally:
        client.close()


def test_pa_0003_decision_has_risk(tmp_path):
    db_path = str(tmp_path / "demo_risk.db")

    store = SQLiteStore(db_path)
    seed(store)
    store.close()

    client = LocalClient(db_path=db_path)
    try:
        decisions = {d.action_id: d for d in client.list_actions()}
        risk = decisions["PA-0003"].risk
        assert risk is not None
        assert risk.score == 0.82
        assert risk.source.value == "heuristics"
        assert "destinataire externe" in risk.signals
        assert risk.summary
        assert isinstance(risk.latency_ms, int)
    finally:
        client.close()


def test_ttl_minutes_sets_ap_0001_expiry(tmp_path):
    db_path = str(tmp_path / "demo_ttl.db")
    ttl = 25  # valeur non par défaut, pour prouver que l'option est honorée

    store = SQLiteStore(db_path)
    try:
        seed(store, ttl_minutes=ttl)

        ap = store.get_approval("AP-0001")
        created = datetime.fromisoformat(ap["created_at"])
        expires = datetime.fromisoformat(ap["expires_at"])
        assert expires - created == timedelta(minutes=ttl)
    finally:
        store.close()
