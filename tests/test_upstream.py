"""Tests de police/mcp_firewall/upstream.py contre un vrai serveur MCP de test (stdio)."""

import sys

import pytest

from mcp import StdioServerParameters

from police.mcp_firewall.upstream import StdioUpstreamClient, UpstreamError

FAKE = StdioServerParameters(command=sys.executable, args=["-m", "tests.fixtures.fake_upstream"])

@pytest.fixture(scope="module")

def client():

    with StdioUpstreamClient("fake", FAKE, timeout_s=3) as c:

        yield c

def test_list_tools_returns_plain_dicts(client):

    tools = {t["name"]: t for t in client.list_tools()}

    assert {"read_file", "boom", "slow"} <= set(tools)

    assert "path" in tools["read_file"]["input_schema"]["properties"]

def test_call_tool_returns_useful_content_not_mcp_object(client):

    out = client.call_tool("read_file", {"path": "docs/a.txt"})

    assert "contenu de docs/a.txt" in str(out)

def test_tool_error_raises(client):

    with pytest.raises(UpstreamError, match="panne simulée"):

        client.call_tool("boom", {})

def test_unknown_tool_raises(client):

    with pytest.raises(UpstreamError):

        client.call_tool("n_existe_pas", {})

def test_timeout_raises_and_client_stays_usable(client):

    with pytest.raises(UpstreamError, match="timeout"):

        client.call_tool("slow", {"seconds": 5})

    assert "contenu" in str(client.call_tool("read_file", {"path": "x"}))

def test_bad_upstream_command_fails_at_start():

    bad = StdioServerParameters(command=sys.executable, args=["-c", "import sys; sys.exit(1)"])

    with pytest.raises(UpstreamError):

        StdioUpstreamClient("bad", bad).start()

def test_call_before_start_raises():

    with pytest.raises(UpstreamError, match="non démarré"):

        StdioUpstreamClient("x", FAKE).call_tool("read_file", {"path": "x"})
