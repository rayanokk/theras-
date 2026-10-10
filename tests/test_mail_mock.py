"""Tests du connecteur mail simulé (MailMock, contrat 3)."""

import ast
import json
from pathlib import Path

import pytest

from police.connectors import mail_mock
from police.connectors.drive_mock import DriveMock, IDENTITIES_PATH
from police.connectors.mail_mock import MailMock


@pytest.fixture
def drive():
    return DriveMock()


@pytest.fixture
def mail(drive):
    return MailMock(drive)


def test_send_email_without_attachment(mail):
    info = mail.describe("send_email", "none", {"to": "a@acme.example"})
    assert info.exists is True
    assert info.classification == "none"
    assert info.trusted is True
    assert info.owner is None
    with open(IDENTITIES_PATH, encoding="utf-8") as fh:
        expected = sorted(
            i["id"] for i in json.load(fh)["identities"] if i["type"] == "agent"
        )
    assert sorted(info.acl) == expected


def test_confidential_attachment_reads_classification_from_drive(mail):
    info = mail.describe(
        "send_email", "Q3_Financials.xlsx", {"to": "a@acme.example"}
    )
    assert info.exists is True
    assert info.classification == "confidential"
    assert info.owner == "user-claire"
    assert sorted(info.acl) == ["agent-assistant", "agent-ops"]


def test_unknown_attachment(mail):
    info = mail.describe("send_email", "Ghost_File.pdf", {"to": "a@acme.example"})
    assert info.exists is False
    assert info.classification == "none"
    assert info.acl == []


def test_recipient_domain_lowercased(mail):
    info = mail.describe(
        "send_email", "none", {"to": "User@Partner.Example"}
    )
    assert info.recipient_email == "User@Partner.Example"
    assert info.recipient_domain == "partner.example"


def test_execute_fills_outbox_and_returns_format(mail):
    assert mail.outbox == []
    res = mail.execute(
        "send_email",
        "Public_Pricing.csv",
        {"to": "a@acme.example", "subject": "Pricing", "body": "See attached."},
    )
    assert res == {"sent_to": "a@acme.example", "attachment": "Public_Pricing.csv"}
    assert len(mail.outbox) == 1
    msg = mail.outbox[0]
    assert msg["to"] == "a@acme.example"
    assert msg["subject"] == "Pricing"
    assert msg["body"] == "See attached."
    assert msg["attachment"] == "Public_Pricing.csv"
    assert "ts" in msg


def test_execute_without_attachment_sets_attachment_none(mail):
    res = mail.execute("send_email", "none", {"to": "a@acme.example"})
    assert res == {"sent_to": "a@acme.example", "attachment": None}
    assert mail.outbox[0]["attachment"] is None


def test_set_classification_on_drive_is_seen_by_mail(drive, mail):
    before = mail.describe("send_email", "Public_Pricing.csv", {"to": "a@acme.example"})
    assert before.classification == "public"
    drive.set_classification("Public_Pricing.csv", "restricted")
    after = mail.describe("send_email", "Public_Pricing.csv", {"to": "a@acme.example"})
    assert after.classification == "restricted"


def test_deleted_file_in_drive_is_absent_for_mail(drive, mail):
    assert mail.describe("send_email", "uploaded_cv.txt", {"to": "a@acme.example"}).exists is True
    drive.execute("delete_file", "uploaded_cv.txt", {})
    info = mail.describe("send_email", "uploaded_cv.txt", {"to": "a@acme.example"})
    assert info.exists is False
    assert info.classification == "none"
    assert info.acl == []


def test_module_does_not_import_smtplib_or_socket():
    """Vérifie les imports réels via l'AST (pas une recherche de sous-chaîne)."""
    source = Path(mail_mock.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert "smtplib" not in imported, "mail_mock ne doit pas importer smtplib"
    assert "socket" not in imported, "mail_mock ne doit pas importer socket"
