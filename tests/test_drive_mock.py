"""Tests du connecteur Google Drive simulé (DriveMock, contrat 3)."""

import json

import pytest

from police.connectors.drive_mock import DATA_DIR, IDENTITIES_PATH, DriveMock


@pytest.fixture
def drive():
    return DriveMock()


def test_describe_existing_file_classification_and_acl(drive):
    info = drive.describe("read_file", "Confidential_Audit_Report.pdf", {})
    assert info.exists is True
    assert info.classification == "confidential"
    assert info.owner == "user-claire"
    assert sorted(info.acl) == ["agent-assistant", "agent-ops"]
    assert info.trusted is True


def test_describe_unknown_file(drive):
    info = drive.describe("read_file", "Ghost_File.pdf", {})
    assert info.exists is False
    assert info.classification == "none"
    assert info.acl == []


def test_describe_root(drive):
    info = drive.describe("list_files", "root", {})
    assert info.exists is True
    assert info.classification == "none"
    assert info.trusted is True
    assert sorted(info.acl) == ["agent-assistant", "agent-ops", "agent-research"]


def test_root_acl_matches_identities_agents(drive):
    """L'ACL de root contient exactement les agents (type=agent) de identities.json."""
    with open(IDENTITIES_PATH, encoding="utf-8") as fh:
        identities = json.load(fh)["identities"]
    expected_agents = sorted(
        ident["id"] for ident in identities if ident["type"] == "agent"
    )
    info = drive.describe("list_files", "root", {})
    assert sorted(info.acl) == expected_agents


def test_describe_recipient_domain_lowercased(drive):
    info = drive.describe(
        "share_file",
        "Company_Brochure.pdf",
        {"recipient": "X@Partner.Example", "role": "reader"},
    )
    assert info.recipient_email == "X@Partner.Example"
    assert info.recipient_domain == "partner.example"


def test_describe_invalid_recipient_domain_is_none(drive):
    info = drive.describe(
        "share_file", "Company_Brochure.pdf", {"recipient": "no-at-sign"}
    )
    assert info.recipient_domain is None


def test_describe_does_not_mutate_state(drive):
    before = drive.get_file("Company_Brochure.pdf")
    drive.describe("share_file", "Company_Brochure.pdf", {"recipient": "a@acme.example"})
    drive.describe("read_file", "Company_Brochure.pdf", {})
    after = drive.get_file("Company_Brochure.pdf")
    assert before == after
    # Toujours les 15 fichiers.
    assert len(drive.execute("list_files", "root", {})["files"]) == 15


def test_read_file_returns_content_and_trusted(drive):
    # Fichier fiable.
    res = drive.execute("read_file", "Team_Roadmap.md", {})
    on_disk = (DATA_DIR / "docs" / "Team_Roadmap.md").read_text(encoding="utf-8")
    assert res["content"] == on_disk
    assert res["trusted"] is True

    # Fichier non fiable.
    res_untrusted = drive.execute("read_file", "vendor_notes.txt", {})
    assert res_untrusted["trusted"] is False


def test_share_then_delete_mutate_memory_not_disk(drive):
    disk_file = DATA_DIR / "docs" / "uploaded_cv.txt"
    assert disk_file.exists()

    share = drive.execute(
        "share_file", "uploaded_cv.txt", {"recipient": "a@acme.example", "role": "reader"}
    )
    assert share == {"shared_with": "a@acme.example", "role": "reader"}

    deleted = drive.execute("delete_file", "uploaded_cv.txt", {})
    assert deleted == {"deleted": True}

    # Disparu de l'état en mémoire...
    assert drive.get_file("uploaded_cv.txt") is None
    assert drive.describe("read_file", "uploaded_cv.txt", {}).exists is False
    # ...mais toujours présent sur le disque.
    assert disk_file.exists()


def test_set_classification_changes_describe(drive):
    assert drive.describe("read_file", "Public_Pricing.csv", {}).classification == "public"
    drive.set_classification("Public_Pricing.csv", "restricted")
    assert (
        drive.describe("read_file", "Public_Pricing.csv", {}).classification == "restricted"
    )
