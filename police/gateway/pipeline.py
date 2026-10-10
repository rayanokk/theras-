"""Pipeline du Gateway : intercept -> normalize -> authorize -> risk -> decide
-> enforce -> record.

C'est le SEUL module autorise a importer les connecteurs et a appeler
`connector.execute`. L'agent ne parle qu'au Gateway (regle d'or 1).

La decision vient toujours des regles fixes de policies.yaml (regle d'or 2).
Le scoreur de risque ne peut que durcir (ALLOW -> REVIEW) et jamais adoucir :
en pratique il n'ajoute que les faits `risk_score` / `risk_unavailable`, que la
politique interprete via R-REV-04. Un scoreur en echec ou indisponible envoie
l'action sensible en REVIEW (fail closed, regle d'or 3).

Une requete invalide ne leve jamais d'exception : elle devient un DENY
R-DENY-06 trace dans le Vault (regle d'or 8).
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from contracts.models import (
    ACTION_TOOL,
    PARAMS_MODELS,
    ActionRequest,
    Decision,
    RiskSignal,
    canonical_json,
    params_hash,
)
from police.approvals.service import new_approval
from police.connectors.base import Connector
from police.evidence.vault import EvidenceVault
from police.identity import IdentityRegistry
from police.policy.engine import Policy, evaluate, recipient_facts
from police.policy.taint import TaintTracker

SENSITIVE_ACTIONS = {"share_file", "delete_file", "send_email"}
# Couples (action, resource_id) qui dispensent du controle d'ACL (contrat 3) :
# seuls list_files/root et send_email/none sont exemptes.
EXEMPT_PAIRS = {("list_files", "root"), ("send_email", "none")}
EMPTY_HASH = ""


class Pipeline:
    """Orchestre une action d'agent de bout en bout et renvoie une Decision."""

    def __init__(
        self,
        policy: Policy,
        identities: IdentityRegistry,
        connectors: dict[str, Connector],
        store: Any,
        vault: EvidenceVault,
        taint: TaintTracker,
        risk_scorer: Any = None,
    ) -> None:
        self._policy = policy
        self._identities = identities
        self._connectors = connectors
        self._store = store
        self._vault = vault
        self._taint = taint
        self._risk_scorer = risk_scorer

    # ------------------------------------------------------------- action_id

    def _next_action_id(self) -> str:
        """PA-0001, PA-0002... compteur base sur le nombre d'actions du store."""
        count = len(self._store.list_actions())
        return f"PA-{count + 1:04d}"

    def _next_approval_id(self) -> str:
        """AP-0001, AP-0002... compteur base sur le nombre d'approbations."""
        count = len(self._store.list_approvals())
        return f"AP-{count + 1:04d}"

    # ----------------------------------------------------------------- helpers

    @staticmethod
    def _safe_params_hash(request: ActionRequest | None, raw_body: Any) -> str:
        """params_hash du request valide, sinon un hash du corps brut, sinon ""."""
        if request is not None:
            return params_hash(request)
        try:
            return hashlib.sha256(
                canonical_json(raw_body).encode("utf-8")
            ).hexdigest()
        except (TypeError, ValueError):
            return EMPTY_HASH

    def _validate(self, raw_body: Any):
        """Valide le corps. Renvoie (request|None, params_valid: bool)."""
        if not isinstance(raw_body, dict):
            return None, False
        try:
            request = ActionRequest.model_validate(raw_body)
        except Exception:
            return None, False
        action = request.action.value
        tool = request.tool.value
        # Coherence outil/action.
        if ACTION_TOOL.get(action) != tool:
            return request, False
        # Parametres stricts par action.
        model = PARAMS_MODELS.get(action)
        if model is None:
            return request, False
        try:
            model.model_validate(request.parameters)
        except Exception:
            return request, False
        return request, True

    # ------------------------------------------------------------------- handle

    def handle(self, raw_body: Any, api_key: str | None) -> Decision:
        action_id = self._next_action_id()
        policy_version = self._policy.version

        # 1. REQUESTED : on trace la demande telle que recue (sans la cle).
        self._vault.record(
            "REQUESTED",
            action_id,
            {"raw_body": raw_body if isinstance(raw_body, dict) else str(raw_body)},
            policy_version,
        )

        # 2. Validation (jamais d'exception qui remonte).
        request, params_valid = self._validate(raw_body)

        # 3. Faits d'identite et d'autorisation.
        identity = self._identities.resolve(api_key)
        identity_ok = False
        action_allowed = False
        if identity is not None and identity.get("type") == "agent":
            declared = request.agent_id if request is not None else None
            identity_ok = declared is None or declared == identity["id"]

        facts: dict[str, Any] = {
            "params_valid": params_valid,
            "identity_ok": identity_ok,
            "resource_ok": False,
            "action_allowed": False,
            "has_recipient": False,
            "recipient_internal": False,
            "recipient_partner": False,
            "recipient_blocked": False,
            "sensitive": False,
            "session_tainted": False,
            "risk_unavailable": False,
        }

        resource_info = None
        if request is not None:
            action = request.action.value
            tool = request.tool.value
            facts["action"] = action
            facts["sensitive"] = action in SENSITIVE_ACTIONS

            # action_allowed : l'action est dans les droits de l'agent pour l'outil.
            if identity_ok and identity is not None:
                allowed = identity.get("allowed", {}) or {}
                action_allowed = action in allowed.get(tool, [])
            facts["action_allowed"] = action_allowed

            # describe + faits de ressource seulement si validation et identite OK.
            if params_valid and identity_ok and action_allowed:
                connector = self._connectors.get(tool)
                if connector is not None:
                    try:
                        resource_info = connector.describe(
                            action, request.resource_id, request.parameters
                        )
                    except Exception:
                        # describe ne doit jamais faire planter le pipeline :
                        # ressource consideree indisponible -> DENY R-DENY-03.
                        resource_info = None
                        facts["resource_ok"] = False
                    if resource_info is not None:
                        facts["classification"] = resource_info.classification.value
                        in_acl = (
                            identity["id"] in resource_info.acl if identity else False
                        )
                        exempt = (action, request.resource_id) in EXEMPT_PAIRS
                        facts["resource_ok"] = resource_info.exists and (
                            exempt or in_acl
                        )
                        if resource_info.recipient_domain is not None:
                            facts["has_recipient"] = True
                            facts.update(
                                recipient_facts(
                                    resource_info.recipient_domain, self._policy
                                )
                            )
                    facts["session_tainted"] = self._taint.is_tainted(request.session_id)

        # 4. Premiere evaluation.
        verdict, rule_ids, reasons = evaluate(facts, self._policy)

        # 5. Risque : uniquement si le verdict n'est pas DENY et qu'un scoreur existe.
        risk: RiskSignal | None = None
        if verdict != "DENY" and self._risk_scorer is not None and request is not None:
            try:
                risk = self._risk_scorer(
                    request, resource_info, facts["session_tainted"]
                )
                if risk is not None and risk.score is not None:
                    facts["risk_score"] = risk.score
                if risk is not None and risk.source.value == "llm_unavailable":
                    facts["risk_unavailable"] = True
            except Exception:
                facts["risk_unavailable"] = True
                risk = None
            verdict, rule_ids, reasons = evaluate(facts, self._policy)

        # 6. params_hash + DECIDED.
        phash = self._safe_params_hash(request, raw_body)
        session_id = request.session_id if request is not None else None
        taint_sources = (
            self._taint.taint_sources(session_id) if session_id is not None else []
        )
        risk_payload = risk.model_dump(mode="json") if risk is not None else None
        self._vault.record(
            "DECIDED",
            action_id,
            {
                "verdict": verdict,
                "rule_ids": rule_ids,
                "reasons": reasons,
                "params_hash": phash,
                "facts": facts,
                "taint_sources": taint_sources,
                "risk": risk_payload,
            },
            policy_version,
        )

        # 7. Enforce.
        status = "DENIED"
        result: dict | None = None
        approval_id: str | None = None

        if verdict == "ALLOW":
            connector = self._connectors[request.tool.value]
            try:
                result = connector.execute(
                    request.action.value, request.resource_id, request.parameters
                )
                status = "EXECUTED"
                self._vault.record(
                    "EXECUTED", action_id, {"result": result}, policy_version
                )
                # Taint apres une lecture reussie d'une ressource non fiable.
                if (
                    request.action.value == "read_file"
                    and isinstance(result, dict)
                    and result.get("trusted") is False
                ):
                    self._taint.mark(request.session_id, request.resource_id)
            except Exception as exc:
                status = "FAILED"
                self._vault.record(
                    "BLOCKED", action_id, {"error": str(exc)}, policy_version
                )
        elif verdict == "REVIEW":
            status = "PENDING_REVIEW"
            # Cree l'approbation liee au params_hash de cette decision.
            approval_id = self._next_approval_id()
            approval = new_approval(
                approval_id=approval_id,
                action_id=action_id,
                params_hash=phash,
                now=datetime.now(timezone.utc),
            )
            self._store.put_approval(approval.model_dump(mode="json"))
        else:  # DENY
            status = "DENIED"
            self._vault.record(
                "BLOCKED", action_id, {"rule_ids": rule_ids}, policy_version
            )

        # 8. Persistance de l'action puis Decision.
        decision = Decision(
            action_id=action_id,
            verdict=verdict,
            status=status,
            rule_ids=rule_ids,
            reasons=reasons,
            risk=risk,
            params_hash=phash,
            policy_version=policy_version,
            approval_id=approval_id,
            result=result,
        )
        record = decision.model_dump(mode="json")
        record.update(
            agent_id=identity["id"] if identity is not None else None,
            declared_agent_id=request.agent_id if request is not None else None,
            request=request.model_dump(mode="json") if request is not None else None,
            session_id=session_id,
            created_at=datetime.now(timezone.utc).isoformat(),
            taint_sources=taint_sources,
        )
        self._store.put_action(record)
        return decision
