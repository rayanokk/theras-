"""Tests du serveur MCP amont demo_drive (police/mcp_firewall/upstreams/theras_mocks.py).

On le lance en sous-processus stdio via StdioUpstreamClient, en pointant cwd sur
la racine du repo pour que les imports et le chargement du seed fonctionnent.
La liste attendue des outils est lue depuis le manifeste : la source de vérité.
"""

import sys
from pathlib import Path

import pytest
import yaml
from mcp import StdioServerParameters

from police.mcp_firewall.upstream import StdioUpstreamClient, UpstreamError

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "police" / "mcp_firewall" / "manifests" / "demo_drive.yaml"

PARAMS = StdioServerParameters(
    command=sys.executable,
    args=["-m", "police.mcp_firewall.upstreams.theras_mocks"],
    cwd=str(REPO_ROOT),
)


def _manifest_tools() -> set[str]:
    data = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    return set(data["tools"].keys())


@pytest.fixture(scope="module")
def client():
    with StdioUpstreamClient("demo_drive", PARAMS, timeout_s=10) as c:
        yield c


def test_list_tools_matches_manifest(client):
    exposed = {t["name"] for t in client.list_tools()}
    assert _manifest_tools() <= exposed


def test_read_seed_file_returns_content(client):
    out = client.call_tool("read_file", {"path": "Press_Release_Q3.txt"})
    assert "Acme Corp" in str(out)


def test_unknown_resource_raises(client):
    with pytest.raises(UpstreamError):
        client.call_tool("read_file", {"path": "n_existe_pas.txt"})
