"""Tests du connecteur de serveur MCP amont (manifeste demo_drive).

Le client amont est un faux en memoire qui enregistre les appels : on verifie
que le connecteur traduit fidelement, echoue ferme sur un outil inconnu, et
propage les erreurs de l'amont (le pipeline les transformera en FAILED).
"""

from pathlib import Path

import pytest

from police.mcp_firewall.connector import McpUpstreamConnector
from police.mcp_firewall.manifest import load_manifest

REPO = Path(__file__).resolve().parents[1]
DEMO = REPO / "police" / "mcp_firewall" / "manifests" / "demo_drive.yaml"


class FakeUpstreamClient:
    """Client amont factice : enregistre les appels et renvoie une valeur fixe."""

    def __init__(self, result="valeur amont", error: Exception | None = None):
        self.calls: list[tuple[str, dict]] = []
        self._result = result
        self._error = error

    def call_tool(self, name: str, arguments: dict):
        self.calls.append((name, arguments))
        if self._error is not None:
            raise self._error
        return self._result


@pytest.fixture
def manifest():
    return load_manifest(DEMO)


@pytest.fixture
def connector(manifest):
    return McpUpstreamConnector(manifest, FakeUpstreamClient())


# --- describe -----------------------------------------------------------------


def test_describe_share_to_external(manifest):
    conn = McpUpstreamConnector(manifest, FakeUpstreamClient())
    info = conn.describe(
        "share_file",
        "Confidential_Audit_Report.pdf",
        {"email": "audit@external.example"},
    )
    assert info.classification.value == "confidential"
    assert info.recipient_domain == "external.example"
    assert info.acl == manifest.acl


def test_describe_read_untrusted_and_trusted(connector):
    untrusted = connector.describe("read_file", "vendor_notes.txt", {})
    assert untrusted.trusted is False
    trusted = connector.describe("read_file", "Team_Roadmap.md", {})
    assert trusted.trusted is True


def test_describe_send_email_no_attachment(connector):
    info = connector.describe(
        "send_email", "none", {"to": "colleague@acme.example"}
    )
    assert info.classification.value == "none"
    assert info.recipient_domain == "acme.example"


def test_describe_unknown_tool_is_fail_closed(connector):
    info = connector.describe("rm_rf", "whatever", {})
    assert info.exists is False
    assert info.classification.value == "restricted"
    assert info.acl == []


# --- execute ------------------------------------------------------------------


def test_execute_read_returns_content_and_trusted(manifest):
    client = FakeUpstreamClient(result="texte du fichier")
    conn = McpUpstreamConnector(manifest, client)
    out = conn.execute("read_file", "vendor_notes.txt", {})
    assert out == {"content": "texte du fichier", "trusted": False}
    assert client.calls == [("read_file", {})]


def test_execute_unknown_tool_raises_and_never_calls_client(manifest):
    client = FakeUpstreamClient()
    conn = McpUpstreamConnector(manifest, client)
    with pytest.raises(PermissionError):
        conn.execute("rm_rf", "whatever", {})
    assert client.calls == []


def test_execute_propagates_client_error(manifest):
    client = FakeUpstreamClient(error=RuntimeError("amont indisponible"))
    conn = McpUpstreamConnector(manifest, client)
    with pytest.raises(RuntimeError):
        conn.execute("read_file", "vendor_notes.txt", {})
