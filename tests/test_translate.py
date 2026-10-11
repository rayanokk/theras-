"""Tests de la traduction outil amont -> vocabulaire du Gateway."""

from pathlib import Path

import pytest

from police.mcp_firewall.manifest import Effect, ToolSpec, load_manifest
from police.mcp_firewall.translate import (
    EFFECT_TO_ACTION,
    canonical_action,
    extract_recipient,
    extract_resource,
)

REPO = Path(__file__).resolve().parents[1]
DEMO = REPO / "police" / "mcp_firewall" / "manifests" / "demo_drive.yaml"


def test_each_effect_maps_to_canonical_action():
    assert EFFECT_TO_ACTION[Effect.READ] == "read_file"
    assert EFFECT_TO_ACTION[Effect.LIST] == "list_files"
    assert EFFECT_TO_ACTION[Effect.SHARE] == "share_file"
    assert EFFECT_TO_ACTION[Effect.DELETE] == "delete_file"
    assert EFFECT_TO_ACTION[Effect.SEND] == "send_email"
    assert EFFECT_TO_ACTION[Effect.WRITE] == "write"


def test_canonical_action_from_manifest():
    manifest = load_manifest(DEMO)
    assert canonical_action(manifest, "read_file") == "read_file"
    assert canonical_action(manifest, "share_file") == "share_file"


def test_canonical_action_unknown_is_none():
    manifest = load_manifest(DEMO)
    assert canonical_action(manifest, "inconnu") is None


# --- extract_resource ---------------------------------------------------------

_READ = ToolSpec(effect="read", resource_from="path")


def test_extract_resource_missing_argument():
    with pytest.raises(ValueError):
        extract_resource(_READ, {})


def test_extract_resource_empty():
    with pytest.raises(ValueError):
        extract_resource(_READ, {"path": ""})


def test_extract_resource_too_long():
    with pytest.raises(ValueError):
        extract_resource(_READ, {"path": "a" * 513})


def test_extract_resource_control_char():
    with pytest.raises(ValueError):
        extract_resource(_READ, {"path": "docs/a\n.txt"})


def test_extract_resource_accepts_path():
    assert extract_resource(_READ, {"path": "docs/a.txt"}) == "docs/a.txt"


# --- extract_recipient --------------------------------------------------------

_SHARE = ToolSpec(effect="share", resource_from="path", recipient_from="email")


def test_extract_recipient_valid_email():
    assert (
        extract_recipient(_SHARE, {"email": "a@acme.example"}) == "a@acme.example"
    )


def test_extract_recipient_invalid_email():
    with pytest.raises(ValueError):
        extract_recipient(_SHARE, {"email": "pas-un-email"})


def test_extract_recipient_none_when_no_recipient_from():
    assert extract_recipient(_READ, {"path": "x"}) is None
