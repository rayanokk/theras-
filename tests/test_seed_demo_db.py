"""Test du script de démonstration scripts/seed_demo_db.py."""

from datetime import datetime, timedelta

from scripts.seed_demo_db import seed
from police.evidence.vault import EvidenceVault
from police.store.sqlite_store import SQLiteStore


def test_seed_demo_db_populates_expected_state(tmp_path):
    db_path = str(tmp_path / "demo.db")

    store = SQLiteStore(db_path)
    try:
        seed(store)

        # 6 actions.
        assert len(store.list_actions()) == 6

        # Une seule approbation pending.
        assert len(store.list_approvals(status="pending")) == 1

        # Chaîne de preuves valide.
        assert EvidenceVault(store).verify() == {"valid": True, "broken_at": None}
    finally:
        store.close()


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
