"""Tests du format de manifeste du pare-feu MCP (police/mcp_firewall/manifest.py).

Un manifeste incomplet ou incoherent doit etre refuse au chargement (fail
closed). On verifie le manifeste reel demo_drive.yaml et une serie de cas
d'erreur construits a la main.
"""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from police.mcp_firewall.manifest import (
    Effect,
    Manifest,
    ResourceRule,
    ToolSpec,
    load_manifest,
    load_manifests,
)

REPO = Path(__file__).resolve().parents[1]
DEMO = REPO / "police" / "mcp_firewall" / "manifests" / "demo_drive.yaml"


def _valid_manifest_dict() -> dict:
    return {
        "server": "demo_drive",
        "default_classification": "internal",
        "acl": ["agent-ops"],
        "tools": {
            "read_file": {"effect": "read", "resource_from": "path"},
        },
    }


# --- Chargement du manifeste reel ---------------------------------------------


def test_demo_drive_loads():
    manifest = load_manifest(DEMO)
    assert manifest.server == "demo_drive"
    assert "share_file" in manifest.tools
    # read_file reflete la confiance du fichier (pas de forcage global).
    assert manifest.tools["read_file"].untrusted_output is False
    assert manifest.tools["share_file"].recipient_from == "email"


# --- Validations croisees des outils ------------------------------------------


def test_share_without_recipient_is_rejected():
    with pytest.raises(ValidationError):
        ToolSpec.model_validate({"effect": "share", "resource_from": "path"})


def test_send_without_recipient_is_rejected():
    with pytest.raises(ValidationError):
        ToolSpec.model_validate({"effect": "send", "resource_from": "attachment"})


# --- extra="forbid" partout ---------------------------------------------------


def test_unknown_field_in_manifest_is_rejected():
    d = _valid_manifest_dict()
    d["inconnu"] = "boom"
    with pytest.raises(ValidationError):
        Manifest.model_validate(d)


def test_unknown_field_in_toolspec_is_rejected():
    with pytest.raises(ValidationError):
        ToolSpec.model_validate(
            {"effect": "read", "resource_from": "path", "inconnu": 1}
        )


def test_unknown_field_in_resourcerule_is_rejected():
    with pytest.raises(ValidationError):
        ResourceRule.model_validate(
            {"match": "x", "classification": "public", "inconnu": 1}
        )


# --- Valeurs invalides --------------------------------------------------------


def test_unknown_effect_is_rejected():
    with pytest.raises(ValidationError):
        ToolSpec.model_validate({"effect": "format_disk", "resource_from": "path"})


def test_empty_acl_is_rejected():
    d = _valid_manifest_dict()
    d["acl"] = []
    with pytest.raises(ValidationError):
        Manifest.model_validate(d)


def test_empty_tools_is_rejected():
    d = _valid_manifest_dict()
    d["tools"] = {}
    with pytest.raises(ValidationError):
        Manifest.model_validate(d)


def test_reserved_server_names_are_rejected():
    for reserved in ("mail", "google_drive"):
        d = _valid_manifest_dict()
        d["server"] = reserved
        with pytest.raises(ValidationError):
            Manifest.model_validate(d)


def test_server_with_uppercase_is_rejected():
    d = _valid_manifest_dict()
    d["server"] = "GitHub"
    with pytest.raises(ValidationError):
        Manifest.model_validate(d)


def test_resource_rule_without_class_or_trusted_is_rejected():
    with pytest.raises(ValidationError):
        ResourceRule.model_validate({"match": "x"})


# --- tool() et resource_facts -------------------------------------------------


def test_tool_unknown_returns_none():
    manifest = load_manifest(DEMO)
    assert manifest.tool("inconnu") is None


def test_resource_facts_classification_from_rule():
    manifest = load_manifest(DEMO)
    spec = manifest.tool("share_file")
    classification, _ = manifest.resource_facts(
        "Confidential_Audit_Report.pdf", spec
    )
    assert classification.value == "confidential"


def test_resource_facts_untrusted_file():
    manifest = load_manifest(DEMO)
    spec = manifest.tool("share_file")  # pas d'untrusted_output
    _, trusted = manifest.resource_facts("vendor_notes.txt", spec)
    assert trusted is False


def test_resource_facts_defaults_for_unlisted_file():
    manifest = load_manifest(DEMO)
    spec = manifest.tool("share_file")
    classification, trusted = manifest.resource_facts("Team_Roadmap.md", spec)
    assert classification.value == "internal"
    assert trusted is True


def test_demo_drive_matches_seed():
    # Pour chaque fichier du seed, read_file doit refleter EXACTEMENT la
    # classification et la confiance declarees dans data/drive_seed.json.
    manifest = load_manifest(DEMO)
    read_spec = manifest.tool("read_file")
    seed = json.loads(
        (REPO / "data" / "drive_seed.json").read_text(encoding="utf-8")
    )
    for f in seed["files"]:
        classification, trusted = manifest.resource_facts(
            f["resource_id"], read_spec
        )
        assert classification.value == f["classification"], f["resource_id"]
        assert trusted == f["trusted"], f["resource_id"]

    # send_email sans piece jointe ("none") : classification none.
    send_spec = manifest.tool("send_email")
    classification, _ = manifest.resource_facts("none", send_spec)
    assert classification.value == "none"

    # Team_Roadmap.md lu par read_file : fichier fiable -> trusted True.
    _, trusted = manifest.resource_facts("Team_Roadmap.md", read_spec)
    assert trusted is True


# --- load_manifests -----------------------------------------------------------


def test_load_manifests_duplicate_server_is_error(tmp_path):
    body = (
        "server: demo_dup\n"
        "acl: [agent-ops]\n"
        "tools:\n"
        "  read_file: {effect: read, resource_from: path}\n"
    )
    (tmp_path / "a.yaml").write_text(body, encoding="utf-8")
    (tmp_path / "b.yaml").write_text(body, encoding="utf-8")
    with pytest.raises(ValueError) as exc:
        load_manifests(tmp_path)
    assert "demo_dup" in str(exc.value)


def test_load_manifest_invalid_yaml_names_the_file(tmp_path):
    path = tmp_path / "casse.yaml"
    path.write_text("server: [unclosed\n", encoding="utf-8")
    with pytest.raises(ValueError) as exc:
        load_manifest(path)
    assert "casse.yaml" in str(exc.value)
