"""Tests du registre d'identites (police/identity.py).

Les cles vivent dans l'environnement ; les tests les posent avec monkeypatch
et ecrivent un fichier d'identites temporaire avec tmp_path. Un test
d'integration charge le vrai data/identities.json.
"""

import json
from pathlib import Path

import pytest

from police.identity import IdentityRegistry

REAL_IDENTITIES = (
    Path(__file__).resolve().parents[1] / "data" / "identities.json"
)


def _write_identities(tmp_path: Path, identities: list[dict]) -> Path:
    path = tmp_path / "identities.json"
    path.write_text(json.dumps({"identities": identities}), encoding="utf-8")
    return path


def test_valid_agent_key_resolves_to_agent(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_KEY_OPS", "secret-ops")
    path = _write_identities(
        tmp_path,
        [
            {
                "id": "agent-ops",
                "type": "agent",
                "key_env": "AGENT_KEY_OPS",
                "allowed": {"google_drive": ["read_file", "share_file"]},
            }
        ],
    )
    registry = IdentityRegistry(path)
    identity = registry.resolve("secret-ops")
    assert identity is not None
    assert identity["id"] == "agent-ops"
    assert identity["type"] == "agent"
    assert identity["allowed"] == {"google_drive": ["read_file", "share_file"]}


def test_valid_approver_key_resolves_to_approver(tmp_path, monkeypatch):
    monkeypatch.setenv("APPROVER_KEY_ALICE", "secret-alice")
    path = _write_identities(
        tmp_path,
        [{"id": "approver-alice", "type": "approver", "key_env": "APPROVER_KEY_ALICE"}],
    )
    registry = IdentityRegistry(path)
    identity = registry.resolve("secret-alice")
    assert identity is not None
    assert identity["id"] == "approver-alice"
    assert identity["type"] == "approver"


def test_unknown_key_resolves_to_none(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_KEY_OPS", "secret-ops")
    path = _write_identities(
        tmp_path,
        [{"id": "agent-ops", "type": "agent", "key_env": "AGENT_KEY_OPS", "allowed": {}}],
    )
    registry = IdentityRegistry(path)
    assert registry.resolve("wrong-key") is None


def test_none_or_empty_key_resolves_to_none(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_KEY_OPS", "secret-ops")
    path = _write_identities(
        tmp_path,
        [{"id": "agent-ops", "type": "agent", "key_env": "AGENT_KEY_OPS", "allowed": {}}],
    )
    registry = IdentityRegistry(path)
    assert registry.resolve(None) is None
    assert registry.resolve("") is None


def test_empty_env_var_means_identity_never_resolved(tmp_path, monkeypatch):
    # Variable definie mais vide : l'identite n'a pas de cle utilisable.
    monkeypatch.setenv("AGENT_KEY_OPS", "")
    path = _write_identities(
        tmp_path,
        [{"id": "agent-ops", "type": "agent", "key_env": "AGENT_KEY_OPS", "allowed": {}}],
    )
    registry = IdentityRegistry(path)
    # Meme en presentant une cle vide, aucune resolution.
    assert registry.resolve("") is None
    assert registry.resolve("secret-ops") is None


def test_user_is_never_resolved(tmp_path, monkeypatch):
    # Un user n'a pas de key_env ; meme avec une variable homonyme, pas de resolution.
    monkeypatch.setenv("USER_KEY_CLAIRE", "secret-claire")
    path = _write_identities(
        tmp_path,
        [{"id": "user-claire", "type": "user", "key_env": "USER_KEY_CLAIRE"}],
    )
    registry = IdentityRegistry(path)
    assert registry.resolve("secret-claire") is None


def test_integration_real_identities_file(monkeypatch):
    monkeypatch.setenv("AGENT_KEY_RESEARCH", "k-research")
    monkeypatch.setenv("AGENT_KEY_OPS", "k-ops")
    monkeypatch.setenv("AGENT_KEY_ASSISTANT", "k-assistant")
    monkeypatch.setenv("APPROVER_KEY_ALICE", "k-alice")
    monkeypatch.setenv("APPROVER_KEY_BOB", "k-bob")

    registry = IdentityRegistry(REAL_IDENTITIES)

    expected = {
        "k-research": ("agent-research", "agent"),
        "k-ops": ("agent-ops", "agent"),
        "k-assistant": ("agent-assistant", "agent"),
        "k-alice": ("approver-alice", "approver"),
        "k-bob": ("approver-bob", "approver"),
    }
    for key, (expected_id, expected_type) in expected.items():
        identity = registry.resolve(key)
        assert identity is not None, key
        assert identity["id"] == expected_id
        assert identity["type"] == expected_type
