"""Tests de la façade MCP de Theras (police/mcp_firewall/proxy.py).

On teste FacadeCore seul (sans la colle MCP ni Gateway réel) via un
httpx.MockTransport qui capture les requêtes et simule les réponses du Gateway.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from police.mcp_firewall.manifest import load_manifests
from police.mcp_firewall.proxy import STATUS_TOOL, FacadeCore, build_core_from_env

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFESTS_DIR = REPO_ROOT / "police" / "mcp_firewall" / "manifests"

AGENT_KEY = "agent-secret-key-123"
GATEWAY_URL = "http://gateway.test"


def _manifests():
    return load_manifests(MANIFESTS_DIR)


def _core(handler, **kwargs) -> FacadeCore:
    """FacadeCore branché sur un MockTransport ; sleep/monotonic injectables."""
    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport, base_url=GATEWAY_URL)
    return FacadeCore(
        gateway_url=GATEWAY_URL,
        agent_key=AGENT_KEY,
        manifests=_manifests(),
        http_client=client,
        **kwargs,
    )


# --------------------------------------------------------------- démarrage/clé


def test_no_key_refuses_to_start():
    with pytest.raises(RuntimeError):
        FacadeCore(GATEWAY_URL, "", _manifests())


def test_build_from_env_requires_key(monkeypatch):
    monkeypatch.delenv("THERAS_AGENT_KEY", raising=False)
    with pytest.raises(RuntimeError):
        build_core_from_env()


# ------------------------------------------------------------------- list_tools


def test_list_tools_exposes_server__tool_and_status():
    core = _core(lambda req: httpx.Response(200, json={}))
    names = {t["name"] for t in core.list_tools()}
    assert "demo_drive__share_file" in names
    assert "demo_drive__read_file" in names
    assert STATUS_TOOL in names
    core.close()


# --------------------------------------------------------------------- routing


def test_routing_and_contract_body():
    captured = {}

    def handler(req: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(req.content)
        captured["headers"] = dict(req.headers)
        return httpx.Response(200, json={"result": {"content": "ok"}})

    core = _core(handler)
    res = core.call("demo_drive__share_file", {"path": "Q3_Financials.xlsx", "email": "x@acme.example"})
    body = captured["body"]

    # tool = server du manifeste ; action = outil amont.
    assert body["tool"] == "demo_drive"
    assert body["action"] == "share_file"
    # resource_id extrait (resource_from = path).
    assert body["resource_id"] == "Q3_Financials.xlsx"
    # parameters bruts (inchangés).
    assert body["parameters"] == {"path": "Q3_Financials.xlsx", "email": "x@acme.example"}
    # jamais d'agent_id ; session/task présents.
    assert "agent_id" not in body
    assert body["session_id"] and body["task_id"]
    # X-API-Key présent et correct.
    assert captured["headers"].get("x-api-key") == AGENT_KEY
    assert not res.is_error
    core.close()


def test_unknown_tool_sent_with_resource_unknown():
    captured = {}

    def handler(req: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(req.content)
        return httpx.Response(403, json={"rule_ids": ["R-DENY-06"], "reasons": ["invalide"]})

    core = _core(handler)
    res = core.call("mystere__bidule", {"foo": "bar"})
    body = captured["body"]
    assert body["resource_id"] == "unknown"
    assert body["tool"] == "mystere"
    assert body["action"] == "bidule"
    assert res.is_error
    core.close()


def test_missing_resource_arg_is_local_deny_no_http():
    calls = {"n": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json={})

    core = _core(handler)
    res = core.call("demo_drive__read_file", {})  # pas de 'path'
    assert res.is_error
    assert calls["n"] == 0  # aucun appel HTTP
    core.close()


# --------------------------------------------------------------- ALLOW / DENY


def test_allow_returns_result():
    core = _core(lambda req: httpx.Response(200, json={"result": {"content": "bonjour"}}))
    res = core.call("demo_drive__read_file", {"path": "Press_Release_Q3.txt"})
    assert not res.is_error
    assert "bonjour" in res.text
    core.close()


def test_deny_is_error_with_rule_labels():
    core = _core(
        lambda req: httpx.Response(
            403, json={"rule_ids": ["R-DENY-04"], "reasons": ["hors entreprise"]}
        )
    )
    res = core.call("demo_drive__share_file", {"path": "HR_Salaries.xlsx", "email": "x@evil.com"})
    assert res.is_error
    assert "R-DENY-04" in res.text
    assert "hors entreprise" in res.text
    core.close()


# ------------------------------------------------------------------- REVIEW


def test_review_approved_in_time_returns_result():
    state = {"calls": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.method == "POST":
            return httpx.Response(202, json={"action_id": "PA-0001", "approval_id": "AP-0001"})
        # GET : d'abord en attente, puis exécuté.
        state["calls"] += 1
        if state["calls"] >= 2:
            return httpx.Response(200, json={"status": "EXECUTED", "result": {"deleted": True}})
        return httpx.Response(200, json={"status": "PENDING_REVIEW"})

    core = _core(handler, wait_s=10, poll_s=0, sleep=lambda s: None)
    res = core.call("demo_drive__delete_file", {"path": "Q3_Financials.xlsx"})
    assert not res.is_error
    assert "supprimé" in res.text
    core.close()


def test_review_not_decided_returns_exact_message():
    def handler(req: httpx.Request) -> httpx.Response:
        if req.method == "POST":
            return httpx.Response(202, json={"action_id": "PA-0042", "approval_id": "AP-0042"})
        return httpx.Response(200, json={"status": "PENDING_REVIEW"})

    # Horloge simulée : dépasse la deadline au 2e appel monotonic.
    ticks = iter([0.0, 0.0, 100.0, 200.0, 300.0])

    core = _core(
        handler,
        wait_s=5,
        poll_s=1,
        sleep=lambda s: None,
        monotonic=lambda: next(ticks),
    )
    res = core.call("demo_drive__delete_file", {"path": "Q3_Financials.xlsx"})
    expected = (
        "Approbation humaine requise (PA-0042). Si approuvée, Theras exécutera "
        "l'action lui-même. Appelle theras__get_action_status avec PA-0042. "
        "Ne relance pas l'outil."
    )
    assert res.text == expected
    assert not res.is_error
    core.close()


def test_review_rejected_is_error():
    def handler(req: httpx.Request) -> httpx.Response:
        if req.method == "POST":
            return httpx.Response(202, json={"action_id": "PA-0007", "approval_id": "AP-0007"})
        return httpx.Response(200, json={"status": "DENIED"})

    core = _core(handler, wait_s=10, poll_s=0, sleep=lambda s: None)
    res = core.call("demo_drive__delete_file", {"path": "Q3_Financials.xlsx"})
    assert res.is_error
    assert "DENIED" in res.text
    core.close()


# ------------------------------------------------------------- get_action_status


def test_get_action_status_executed():
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": "EXECUTED", "result": {"content": "fini"}})

    core = _core(handler)
    res = core.call(STATUS_TOOL, {"action_id": "PA-0001"})
    assert not res.is_error
    assert "fini" in res.text
    core.close()


def test_get_action_status_not_found():
    core = _core(lambda req: httpx.Response(404, json={"detail": "Action inconnue"}))
    res = core.call(STATUS_TOOL, {"action_id": "PA-9999"})
    assert res.is_error
    core.close()


# --------------------------------------------------------------- réseau / clé


def test_gateway_unreachable_is_error():
    def handler(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom")

    core = _core(handler)
    res = core.call("demo_drive__read_file", {"path": "Press_Release_Q3.txt"})
    assert res.is_error
    assert "injoignable" in res.text
    core.close()


def test_key_never_leaks_in_any_message():
    # Chaque branche renvoie un message : la clé ne doit apparaître dans aucun.
    def deny_handler(req):
        return httpx.Response(403, json={"rule_ids": ["R-DENY-04"], "reasons": ["x"]})

    def review_handler(req):
        if req.method == "POST":
            return httpx.Response(202, json={"action_id": "PA-1", "approval_id": "AP-1"})
        return httpx.Response(200, json={"status": "PENDING_REVIEW"})

    def unreachable(req):
        raise httpx.ConnectError("boom")

    messages = []

    core = _core(deny_handler)
    messages.append(core.call("demo_drive__share_file", {"path": "HR_Salaries.xlsx", "email": "a@b.com"}).text)
    core.close()

    core = _core(deny_handler)
    messages.append(core.call("inconnu__x", {"a": 1}).text)  # unknown -> deny
    core.close()

    core = _core(review_handler, wait_s=0, poll_s=0, sleep=lambda s: None, monotonic=iter([0.0, 1.0]).__next__)
    messages.append(core.call("demo_drive__delete_file", {"path": "Q3_Financials.xlsx"}).text)
    core.close()

    core = _core(unreachable)
    messages.append(core.call("demo_drive__read_file", {"path": "Press_Release_Q3.txt"}).text)
    messages.append(core.call("demo_drive__read_file", {}).text)  # local deny
    core.close()

    for msg in messages:
        assert AGENT_KEY not in msg
