"""API FastAPI du Gateway (contrat, partie 3 : endpoints et roles).

Regle d'or 8 : /v1/actions ne renvoie jamais un 422 automatique. On lit le corps
brut nous-memes et on le passe tel quel au pipeline, qui transforme toute
invalidite en DENY R-DENY-06 trace dans le Vault. Les autres routes appliquent
le controle d'acces par role (agent, approbateur) via le header X-API-Key.
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse

# Verdict -> code HTTP pour POST /v1/actions.
_VERDICT_STATUS = {"ALLOW": 200, "REVIEW": 202, "DENY": 403}


def create_app(pipeline, store, vault, identities) -> FastAPI:
    app = FastAPI(title="Theras Gateway")

    def _identity_or_401(api_key: str | None) -> dict:
        identity = identities.resolve(api_key)
        if identity is None:
            raise HTTPException(status_code=401, detail="Clé API inconnue")
        return identity

    def _require_approver(api_key: str | None) -> dict:
        identity = _identity_or_401(api_key)
        if identity.get("type") != "approver":
            raise HTTPException(
                status_code=403, detail="Route réservée aux approbateurs"
            )
        return identity

    # ------------------------------------------------------------------ actions

    @app.post("/v1/actions")
    async def post_action(
        request: Request,
        x_api_key: str | None = Header(default=None),
    ):
        # On relit le corps brut pour ne jamais dependre du parsing FastAPI :
        # un corps absent, non-JSON ou non-objet devient une valeur que le
        # pipeline refusera (DENY R-DENY-06), jamais un 422.
        raw = await request.body()
        if not raw:
            parsed: Any = None
        else:
            try:
                parsed = json.loads(raw)
            except (json.JSONDecodeError, ValueError):
                parsed = raw.decode("utf-8", errors="replace")

        decision = pipeline.handle(parsed, x_api_key)
        status_code = _VERDICT_STATUS.get(decision.verdict, 403)
        return JSONResponse(
            status_code=status_code, content=decision.model_dump(mode="json")
        )

    @app.get("/v1/actions/{action_id}")
    def get_action(action_id: str, x_api_key: str | None = Header(default=None)):
        _identity_or_401(x_api_key)
        action = store.get_action(action_id)
        if action is None:
            raise HTTPException(status_code=404, detail="Action inconnue")
        return action

    @app.get("/v1/actions")
    def list_actions(
        status: str | None = None, x_api_key: str | None = Header(default=None)
    ):
        _identity_or_401(x_api_key)
        return store.list_actions(status)

    # ----------------------------------------------------------------- evidence

    @app.get("/v1/evidence")
    def get_evidence(
        action_id: str | None = None, x_api_key: str | None = Header(default=None)
    ):
        _require_approver(x_api_key)
        return store.list_events(action_id)

    @app.get("/v1/evidence/verify")
    def verify_evidence(x_api_key: str | None = Header(default=None)):
        _require_approver(x_api_key)
        return vault.verify()

    @app.get("/v1/evidence/export")
    def export_evidence(x_api_key: str | None = Header(default=None)):
        _require_approver(x_api_key)
        return PlainTextResponse(vault.export_jsonl())

    # ------------------------------------------------------------------- health

    @app.get("/health")
    def health():
        return {"status": "ok"}

    return app
