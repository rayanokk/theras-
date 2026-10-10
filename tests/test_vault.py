"""Tests de l'Evidence Vault (contrat 4), chaîne de hash append-only."""

import hashlib
import json
import sqlite3

import pytest

from contracts.models import Event, canonical_json
from police.evidence.vault import GENESIS_PREV_HASH, EvidenceVault
from police.store.sqlite_store import SQLiteStore


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "evidence.db")


@pytest.fixture
def store(db_path):
    s = SQLiteStore(db_path)
    yield s
    s.close()


@pytest.fixture
def vault(store):
    return EvidenceVault(store)


def _seed_chain(vault, n=3):
    for i in range(1, n + 1):
        vault.record(
            type="REQUESTED",
            action_id=f"PA-{i:04d}",
            payload={"i": i},
            policy_version="v1",
        )


def _recompute_hash(event: dict) -> str:
    """Recalcule le hash d'un dict d'événement (sans le champ hash)."""
    without_hash = {k: v for k, v in event.items() if k != "hash"}
    material = without_hash["prev_hash"] + canonical_json(without_hash)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def test_record_returns_event_instance(vault):
    event = vault.record(
        type="REQUESTED", action_id="PA-0001", payload={"i": 1}, policy_version="v1"
    )
    assert isinstance(event, Event)
    assert event.seq == 1
    assert event.action_id == "PA-0001"
    assert event.prev_hash == GENESIS_PREV_HASH
    # Le Store a bien reçu un dict (pas un Event).
    stored = vault._store.list_events()
    assert isinstance(stored[0], dict)


def test_prev_hash_chaining(vault):
    _seed_chain(vault, 3)
    events = vault._store.list_events()

    assert events[0]["prev_hash"] == GENESIS_PREV_HASH
    assert GENESIS_PREV_HASH == "0" * 64
    for prev, cur in zip(events, events[1:]):
        assert cur["prev_hash"] == prev["hash"]


def test_recomputed_hash_matches_stored(vault):
    _seed_chain(vault, 2)
    for event in vault._store.list_events():
        assert _recompute_hash(event) == event["hash"]


def test_verify_valid_on_intact_chain(vault):
    _seed_chain(vault, 5)
    assert vault.verify() == {"valid": True, "broken_at": None}


def test_verify_valid_on_empty_chain(vault):
    assert vault.verify() == {"valid": True, "broken_at": None}


def test_attack_tampered_payload_detected(db_path, store, vault):
    _seed_chain(vault, 3)
    store.close()  # libère le verrou fichier avant l'accès brut

    # Attaquant : modifie le payload de l'événement seq 2 en SQL direct.
    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT data FROM events WHERE seq = 2").fetchone()
    event = json.loads(row[0])
    event["payload"] = {"i": 999}  # altération, hash non recalculé
    conn.execute(
        "UPDATE events SET data = ? WHERE seq = 2",
        (json.dumps(event, ensure_ascii=False),),
    )
    conn.commit()
    conn.close()

    reopened = SQLiteStore(db_path)
    try:
        result = EvidenceVault(reopened).verify()
        assert result == {"valid": False, "broken_at": 2}
    finally:
        reopened.close()


def test_attack_tampered_and_rehashed_detected(db_path, store, vault):
    _seed_chain(vault, 3)
    store.close()

    # Attaquant plus habile : il modifie le payload de seq 2 ET recalcule
    # correctement le hash de seq 2 avec canonical_json. L'auto-cohérence de
    # seq 2 est donc rétablie...
    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT data FROM events WHERE seq = 2").fetchone()
    event2 = json.loads(row[0])
    event2["payload"] = {"i": 999}
    event2["hash"] = _recompute_hash(event2)  # hash recalculé proprement
    conn.execute(
        "UPDATE events SET data = ? WHERE seq = 2",
        (json.dumps(event2, ensure_ascii=False),),
    )
    conn.commit()
    conn.close()

    reopened = SQLiteStore(db_path)
    try:
        result = EvidenceVault(reopened).verify()
        # ...mais le nouveau hash de seq 2 diffère de l'ancien, et seq 3 n'a pas
        # été touché : son prev_hash pointe toujours vers l'ancien hash de seq 2.
        # La rupture de chaînage est donc détectée à seq 3.
        assert result == {"valid": False, "broken_at": 3}
    finally:
        reopened.close()


def test_attack_deleted_event_detected(db_path, store, vault):
    _seed_chain(vault, 3)
    store.close()

    # Attaquant : supprime l'événement seq 2 en SQL direct, laissant un trou.
    conn = sqlite3.connect(db_path)
    conn.execute("DELETE FROM events WHERE seq = 2")
    conn.commit()
    conn.close()

    reopened = SQLiteStore(db_path)
    try:
        result = EvidenceVault(reopened).verify()
        assert result["valid"] is False
        # broken_at = le premier numéro attendu manquant (seq 2 supprimé).
        assert result["broken_at"] == 2
    finally:
        reopened.close()


def test_export_jsonl_one_valid_json_per_line(vault):
    _seed_chain(vault, 4)
    export = vault.export_jsonl()
    lines = export.split("\n")
    assert len(lines) == 4
    seqs = []
    for line in lines:
        obj = json.loads(line)  # chaque ligne est du JSON valide
        seqs.append(obj["seq"])
    assert seqs == [1, 2, 3, 4]
