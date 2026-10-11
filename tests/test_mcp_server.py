"""Tests du serveur MCP (police/gateway/mcp_server.py), sans reseau.

Le client httpx est remplace par un httpx.MockTransport qui simule le Gateway.
On verifie que le serveur MCP se comporte en PRISE : il traduit fidelement les
reponses du Gateway et echoue ferme quand le Gateway est injoignable. Une
analyse statique garantit qu'il n'importe aucun module interne du Gateway.
"""

import ast
from pathlib import Path

import httpx
import pytest

from police.gateway import mcp_server

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def agent_key(monkeypatch):
    monkeypatch.setenv("THERAS_AGENT_KEY", "k-assistant")
    # Pas d'attente reelle pendant le polling des REVIEW.
    monkeypatch.setattr(mcp_server.time, "sleep", lambda *_: None)
    yield
    mcp_server.set_client(None)


def _mock_client(handler) -> httpx.Client:
    transport = httpx.MockTransport(handler)
    return httpx.Client(transport=transport, base_url=mcp_server.GATEWAY_URL)


# --- ALLOW --------------------------------------------------------------------


def test_allow_returns_content():
    def handler(request):
        return httpx.Response(
            200,
            json={
                "action_id": "PA-0001",
                "verdict": "ALLOW",
                "status": "EXECUTED",
                "rule_ids": ["R-ALLOW-01"],
                "result": {"content": "contenu secret", "trusted": True},
            },
        )

    mcp_server.set_client(_mock_client(handler))
    assert mcp_server.do_read_file("Company_Brochure.pdf") == "contenu secret"


# --- DENY ---------------------------------------------------------------------


def test_deny_returns_refusal_with_rule():
    def handler(request):
        return httpx.Response(
            403,
            json={
                "action_id": "PA-0001",
                "verdict": "DENY",
                "status": "DENIED",
                "rule_ids": ["R-DENY-05"],
                "reasons": ["Destinataire sur un domaine bloqué"],
            },
        )

    mcp_server.set_client(_mock_client(handler))
    out = mcp_server.do_send_email(
        "drop@pastebin.example", "x", "y", attachment="Q3_Financials.xlsx"
    )
    assert "Refusé par Theras" in out
    assert "R-DENY-05" in out


# --- REVIEW puis EXECUTED -----------------------------------------------------


def test_review_then_executed_after_two_polls():
    state = {"polls": 0}

    def handler(request):
        if request.method == "POST":
            return httpx.Response(
                202,
                json={
                    "action_id": "PA-0002",
                    "verdict": "REVIEW",
                    "status": "PENDING_REVIEW",
                    "approval_id": "AP-0001",
                },
            )
        # GET /v1/actions/{id} : encore en attente au 1er appel, execute au 2e.
        state["polls"] += 1
        if state["polls"] < 2:
            return httpx.Response(200, json={"status": "PENDING_REVIEW"})
        return httpx.Response(
            200,
            json={
                "status": "EXECUTED",
                "result": {"shared_with": "colleague@acme.example", "role": "reader"},
            },
        )

    mcp_server.set_client(_mock_client(handler))
    out = mcp_server.do_share_file("Team_Roadmap.md", "colleague@acme.example")
    assert "Partagé avec colleague@acme.example" in out
    assert state["polls"] >= 2


# --- REVIEW jamais decidee ----------------------------------------------------


def test_review_never_decided_returns_waiting(monkeypatch):
    monkeypatch.setattr(mcp_server, "REVIEW_WAIT_SECONDS", 0)

    def handler(request):
        if request.method == "POST":
            return httpx.Response(
                202,
                json={
                    "action_id": "PA-0003",
                    "verdict": "REVIEW",
                    "status": "PENDING_REVIEW",
                    "approval_id": "AP-0002",
                },
            )
        return httpx.Response(200, json={"status": "PENDING_REVIEW"})

    mcp_server.set_client(_mock_client(handler))
    out = mcp_server.do_delete_file("Team_Roadmap.md")
    assert "En attente d'approbation humaine" in out
    assert "AP-0002" in out


# --- Gateway injoignable ------------------------------------------------------


def test_gateway_unreachable_fails_closed():
    def handler(request):
        raise httpx.ConnectError("connexion refusée")

    mcp_server.set_client(_mock_client(handler))
    out = mcp_server.do_read_file("Company_Brochure.pdf")
    assert out == "Theras injoignable : action non exécutée"


# --- Analyse statique : aucune dependance interne du Gateway ------------------


def test_mcp_server_does_not_import_internal_modules():
    forbidden = ("police.connectors", "police.store", "police.gateway.pipeline")
    source = (REPO / "police" / "gateway" / "mcp_server.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)
    for mod in imported:
        assert not any(
            mod == f or mod.startswith(f + ".") for f in forbidden
        ), f"mcp_server importe {mod}"
