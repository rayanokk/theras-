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
import time
from datetime import datetime, timezone
from typing import Any

from contracts.models import (
    _NATIVE_TOOLS,
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

SENSITIVE_ACTIONS = {"share_file", "delete_file", "send_email", "write"}
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
        """Valide le corps. Renvoie (request|None, params_valid: bool).

        ActionRequest valide deja la forme (coherence outil/action et params
        stricts pour le natif ; contraintes de forme pour le MCP). Pour un outil
        non natif, on exige en plus que l'action canonique soit resolvable
        (serveur present et outil declare dans son manifeste), sinon DENY R-DENY-06.
        """
        if not isinstance(raw_body, dict):
            return None, False
        try:
            request = ActionRequest.model_validate(raw_body)
        except Exception:
            return None, False
        if request.tool not in _NATIVE_TOOLS and self._canonical_action(request) is None:
            # Serveur inconnu ou outil absent du manifeste : fail closed.
            return request, False
        return request, True

    def _canonical_action(self, request: ActionRequest) -> str | None:
        """Action canonique du contrat 1 (read_file, share_file...).

        Outil natif : l'action est deja canonique. Outil MCP : on la derive via
        le connecteur amont (canonical_action), None si serveur/outil inconnu.
        """
        if request.tool in _NATIVE_TOOLS:
            return request.action
        connector = self._connectors.get(request.tool)
        if connector is None or not hasattr(connector, "canonical_action"):
            return None
        return connector.canonical_action(request.action)

    # ------------------------------------------------------------------ facts

    def _gather_facts(
        self, request: ActionRequest | None, identity: dict | None
    ) -> tuple[dict[str, Any], Any, list[str]]:
        """Calcule les faits sur l'etat COURANT (jamais le scoreur de risque).

        `identity` est l'identite deja resolue (par la cle API, ou par get() lors
        d'une revalidation). Renvoie (facts, resource_info, taint_sources).
        `params_valid` n'est pas pose ici : c'est a l'appelant de le fixer.
        """
        identity_ok = False
        if identity is not None and identity.get("type") == "agent":
            declared = request.agent_id if request is not None else None
            identity_ok = declared is None or declared == identity["id"]

        # Explicabilite : un fait non verifie est ABSENT du dict (ni False ni
        # None), pour que le moteur ne declenche pas une regle DENY a cote. Ainsi
        # action_allowed n'est pose que si l'identite est bonne, et resource_ok
        # seulement si l'identite ET le droit le sont.
        facts: dict[str, Any] = {
            "identity_ok": identity_ok,
            "has_recipient": False,
            "recipient_internal": False,
            "recipient_partner": False,
            "recipient_blocked": False,
            "sensitive": False,
            "session_tainted": False,
            "risk_unavailable": False,
        }

        resource_info = None
        taint_sources: list[str] = []
        if request is None:
            return facts, resource_info, taint_sources

        tool = request.tool
        # Action CANONIQUE : identique a request.action pour un outil natif,
        # derivee du manifeste pour un outil MCP. C'est elle qui pilote la
        # politique, les droits et le taint ; describe() recoit le nom d'origine.
        action = self._canonical_action(request)
        facts["action"] = action
        facts["sensitive"] = action in SENSITIVE_ACTIONS

        # action_allowed n'est pose que si l'identite est verifiee ET que
        # l'action canonique est resolvable (sinon la requete est deja invalide :
        # on laisse R-DENY-06 seul, sans R-DENY-02 parasite).
        if identity_ok and identity is not None and action is not None:
            allowed = identity.get("allowed", {}) or {}
            facts["action_allowed"] = action in allowed.get(tool, [])

        # describe + resource_ok seulement si identite ET droit sont verifies.
        if facts.get("identity_ok") and facts.get("action_allowed"):
            connector = self._connectors.get(tool)
            if connector is None:
                # Connecteur introuvable : fail closed.
                facts["resource_ok"] = False
            else:
                try:
                    resource_info = connector.describe(
                        request.action, request.resource_id, request.parameters
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
                    facts["resource_ok"] = resource_info.exists and (exempt or in_acl)
                    if resource_info.recipient_domain is not None:
                        facts["has_recipient"] = True
                        facts.update(
                            recipient_facts(
                                resource_info.recipient_domain, self._policy
                            )
                        )
                # On ne pose les faits de taint QUE dans cette branche (identite
                # et droit verifies), pour respecter "un fait non verifie est
                # absent". session_tainted repose sur le session_id fourni par
                # l'agent ; agent_tainted repose sur l'identite reelle (TTL).
                facts["session_tainted"] = self._taint.is_tainted(request.session_id)
                if identity is not None:
                    facts["agent_tainted"] = self._taint.is_agent_tainted(
                        identity["id"], self._policy.agent_taint_ttl_minutes
                    )

        # Sources de contamination : union sans doublon session + agent, ordre
        # stable (sources de session d'abord, puis celles de l'agent).
        taint_sources = list(self._taint.taint_sources(request.session_id))
        if identity is not None:
            for src in self._taint.agent_taint_sources(identity["id"]):
                if src not in taint_sources:
                    taint_sources.append(src)
        return facts, resource_info, taint_sources

    # ---------------------------------------------------------------- execute

    def _execute(
        self, action_id: str, request: ActionRequest, identity: dict | None = None
    ) -> tuple[str, dict | None]:
        """Execute l'action approuvee/autorisee. Renvoie (status, result).

        Journalise EXECUTED ou BLOCKED dans le Vault et marque la session (et
        l'identite reelle si connue) si un read_file renvoie une ressource non
        fiable. N'ecrit PAS APPROVAL_DECIDED.
        """
        policy_version = self._policy.version
        connector = self._connectors[request.tool]
        canonical = self._canonical_action(request)
        try:
            result = connector.execute(
                request.action, request.resource_id, request.parameters
            )
            self._vault.record(
                "EXECUTED", action_id, {"result": result}, policy_version
            )
            # Taint apres une lecture reussie d'une ressource non fiable :
            # on contamine la session ET l'identite reelle (que l'agent ne peut
            # pas changer en basculant de session). On se base sur l'action
            # CANONIQUE (read_file), que l'outil soit natif ou MCP.
            if (
                canonical == "read_file"
                and isinstance(result, dict)
                and result.get("trusted") is False
            ):
                self._taint.mark(request.session_id, request.resource_id)
                if identity is not None:
                    self._taint.mark_agent(identity["id"], request.resource_id)
            return "EXECUTED", result
        except Exception as exc:
            self._vault.record(
                "BLOCKED", action_id, {"error": str(exc)}, policy_version
            )
            return "FAILED", None

    # -------------------------------------------------------------- approvals

    def revalidate(
        self, action: dict, approval
    ) -> tuple[bool, list[str], list[str]]:
        """Rejoue tout le controle sur l'etat courant avant d'executer un approuve.

        Renvoie (ok, rule_ids, reasons). ok=False si les parametres ont change
        depuis la demande, ou si l'etat actuel donne un verdict DENY (y compris
        le refus par defaut R-DENY-DEFAULT). Le scoreur de risque n'est jamais appele.
        """
        approval_hash = (
            approval.params_hash
            if hasattr(approval, "params_hash")
            else approval["params_hash"]
        )

        # Fail closed : une requete stockee illisible ne doit pas faire planter
        # le service d'approbation, elle est refusee proprement.
        try:
            request = ActionRequest.model_validate(action["request"])
        except Exception:
            return False, ["INVALID_REQUEST"], ["Requête stockée illisible"]

        if params_hash(request) != approval_hash:
            return (
                False,
                ["PARAMS_CHANGED"],
                ["Les paramètres ont changé depuis la demande d'approbation"],
            )

        identity = self._identities.get(action.get("agent_id"))
        facts, _resource_info, _taint_sources = self._gather_facts(request, identity)
        facts["params_valid"] = True

        verdict, rule_ids, reasons = evaluate(facts, self._policy)
        if verdict == "DENY":
            return False, rule_ids, reasons
        return True, [], []

    def execute_approved(self, action: dict) -> tuple[str, dict | None]:
        """Execute une action approuvee et revalidee. Renvoie (status, result).

        Les evenements APPROVAL_DECIDED relevent du service d'approbation, pas
        d'ici : cette methode ne journalise que EXECUTED ou BLOCKED via _execute.
        """
        request = ActionRequest.model_validate(action["request"])
        # Identite reelle retrouvee par l'agent_id stocke, pour contaminer aussi
        # l'identite si l'action approuvee est un read_file non fiable.
        identity = self._identities.get(action.get("agent_id"))
        return self._execute(action["action_id"], request, identity)

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

        # 3. Faits : identite resolue par la cle, puis faits sur l'etat courant.
        identity = self._identities.resolve(api_key)
        facts, resource_info, taint_sources = self._gather_facts(request, identity)
        facts["params_valid"] = params_valid

        # 4. Premiere evaluation.
        verdict, rule_ids, reasons = evaluate(facts, self._policy)

        # 5. Risque : uniquement si le verdict n'est pas DENY et qu'un scoreur existe.
        risk: RiskSignal | None = None
        if verdict != "DENY" and self._risk_scorer is not None and request is not None:
            started = time.monotonic()
            try:
                risk = self._risk_scorer(
                    request, resource_info, facts["session_tainted"]
                )
                if risk is not None and risk.score is not None:
                    facts["risk_score"] = risk.score
                if risk is not None and risk.source.value == "llm_unavailable":
                    facts["risk_unavailable"] = True
            except Exception as exc:
                # Fail closed : un scoreur qui plante devient "indisponible", ce
                # qui durcit toute action sensible en REVIEW (R-REV-04).
                elapsed_ms = int((time.monotonic() - started) * 1000)
                risk = RiskSignal(
                    score=None,
                    signals=[f"scorer_error: {type(exc).__name__}"],
                    source="llm_unavailable",
                    summary=None,
                    latency_ms=elapsed_ms,
                )
                facts["risk_unavailable"] = True
            verdict, rule_ids, reasons = evaluate(facts, self._policy)

        # 6. params_hash + DECIDED.
        phash = self._safe_params_hash(request, raw_body)
        session_id = request.session_id if request is not None else None
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
            status, result = self._execute(action_id, request, identity)
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
