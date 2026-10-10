"""Service d'approbation (contrat 5), etape 3.1 : creation d'une approbation.

Deux responsabilites :

- `new_approval` : cree une approbation pending liee a un `params_hash`, valable
  10 minutes (contrat 5).
- `ApprovalService` : service de decision. Il expire les approbations trop
  anciennes (fail closed), applique la decision d'un approbateur authentifie
  (approve / reject / request_info), rejoue tout le controle via
  `pipeline.revalidate` avant d'executer, et journalise chaque etape dans
  l'Evidence Vault. Une REVIEW ne leve jamais un DENY (regle d'or 6).

Le modele ApprovalRequest vient de contracts/models.py : on ne le redefinit pas.
"""

from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from contracts.models import ApprovalDecisionIn, ApprovalRequest, ApprovalStatus

# Duree de vie d'une approbation (contrat 5 : expires_at = created_at + 10 min).
APPROVAL_TTL = timedelta(minutes=10)


def new_approval(
    approval_id: str, action_id: str, params_hash: str, now: datetime
) -> ApprovalRequest:
    """Cree une approbation pending liee a un params_hash, valable APPROVAL_TTL."""
    return ApprovalRequest(
        approval_id=approval_id,
        action_id=action_id,
        params_hash=params_hash,
        status=ApprovalStatus.PENDING,
        created_at=now.isoformat(),
        expires_at=(now + APPROVAL_TTL).isoformat(),
        approver_id=None,
        decision=None,
        justification=None,
        decided_at=None,
    )


# --- Service de decision (etape 3.2) ------------------------------------------


class ApprovalError(Exception):
    """Erreur metier d'approbation, portant un code HTTP et un message."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


# Statuts terminaux (plus modifiables) et statuts encore ouverts.
_OPEN_STATUSES = ("pending", "info_requested")
_FINAL_DECIDED = ("approved", "rejected")


class ApprovalService:
    """Gere la decision d'une approbation : expiration, decision, revalidation.

    Regle d'or 6 : une approbation est liee a un params_hash, expire apres 10
    minutes, et le Gateway rejoue tout le controle (via pipeline.revalidate)
    avant d'executer. Une REVIEW ne leve jamais un DENY. L'identite qui decide
    vient toujours de la cle (identities.resolve), jamais du corps de la requete.
    """

    def __init__(
        self,
        store,
        vault,
        pipeline,
        identities,
        now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self._store = store
        self._vault = vault
        self._pipeline = pipeline
        self._identities = identities
        self._now = now
        # RLock : list()/get() prennent le verrou et appellent expire_if_needed,
        # qui lui-meme reste serialise avec decide(). Un RLock permet de prendre
        # le verrou de maniere reentrante sans se bloquer soi-meme.
        self._lock = threading.RLock()

    # ---------------------------------------------------------------- helpers

    @staticmethod
    def _policy_version(action: dict | None) -> str:
        """policy_version de l'action, ou "" si l'action est absente."""
        if not action:
            return ""
        return action.get("policy_version", "")

    def expire_if_needed(self, approval: dict) -> dict:
        """Expire l'approbation si elle a depasse expires_at et est encore ouverte.

        Met a jour l'approbation (status expired), l'action (status EXPIRED) et
        journalise EXPIRED. Sinon renvoie l'approbation inchangee.
        """
        if approval.get("status") not in _OPEN_STATUSES:
            return approval
        try:
            expires_at = datetime.fromisoformat(approval["expires_at"])
        except (KeyError, TypeError, ValueError):
            return approval
        if self._now() <= expires_at:
            return approval

        approval["status"] = "expired"
        self._store.put_approval(approval)

        action = self._store.get_action(approval["action_id"])
        if action is not None:
            action["status"] = "EXPIRED"
            self._store.put_action(action)
        self._vault.record(
            "EXPIRED",
            approval["action_id"],
            {"approval_id": approval["approval_id"]},
            self._policy_version(action),
        )
        return approval

    def _enrich(self, approval: dict) -> dict:
        """Copie de l'approbation enrichie des faits de l'action correspondante."""
        enriched = dict(approval)
        action = self._store.get_action(approval["action_id"])
        if action is None:
            return enriched

        enriched.update(
            agent_id=action.get("agent_id"),
            rule_ids=action.get("rule_ids"),
            reasons=action.get("reasons"),
            risk=action.get("risk"),
            taint_sources=action.get("taint_sources"),
            action_status=action.get("status"),
        )
        request = action.get("request") or {}
        enriched.update(
            tool=request.get("tool"),
            action=request.get("action"),
            resource_id=request.get("resource_id"),
            parameters=request.get("parameters"),
            user_id=request.get("user_id"),
            reason=request.get("reason"),
        )
        return enriched

    # ------------------------------------------------------------------ reads

    def list(self, status: str | None = None) -> list[dict]:
        """Liste les approbations (apres expiration), filtrees et enrichies."""
        with self._lock:
            result = []
            for approval in self._store.list_approvals():
                approval = self.expire_if_needed(approval)
                if status is not None and approval.get("status") != status:
                    continue
                result.append(self._enrich(approval))
            return result

    def get(self, approval_id: str) -> dict:
        """Renvoie une approbation enrichie. 404 si inconnue."""
        with self._lock:
            approval = self._store.get_approval(approval_id)
            if approval is None:
                raise ApprovalError(404, "Approbation inconnue")
            approval = self.expire_if_needed(approval)
            return self._enrich(approval)

    # ---------------------------------------------------------------- decide

    def decide(
        self, approval_id: str, approver_key: str | None, body: ApprovalDecisionIn
    ) -> dict:
        """Decide d'une approbation (approve / reject / request_info).

        Le controle d'identite se fait hors verrou ; toute la lecture-ecriture de
        l'etat se fait sous verrou pour serialiser deux decisions concurrentes.
        """
        # Hors verrou : authentification et role.
        identity = self._identities.resolve(approver_key)
        if identity is None:
            raise ApprovalError(401, "Clé API inconnue")
        if identity.get("type") != "approver":
            raise ApprovalError(403, "Route réservée aux approbateurs")

        decision = body.decision.value
        justification = body.justification

        with self._lock:
            approval = self._store.get_approval(approval_id)
            if approval is None:
                raise ApprovalError(404, "Approbation inconnue")

            approval = self.expire_if_needed(approval)
            if approval.get("status") == "expired":
                raise ApprovalError(410, "Approbation expirée")
            if approval.get("status") in _FINAL_DECIDED:
                raise ApprovalError(409, "Approbation déjà décidée")

            action = self._store.get_action(approval["action_id"])
            action_id = approval["action_id"]
            # L'action liee doit exister : sinon on refuse avant de rien ecrire.
            if action is None:
                raise ApprovalError(404, "Action liée introuvable")
            policy_version = self._policy_version(action)

            # Decision portee par l'approbateur authentifie (jamais le corps).
            approval["approver_id"] = identity["id"]
            approval["decision"] = decision
            approval["justification"] = justification
            approval["decided_at"] = self._now().isoformat()

            self._vault.record(
                "APPROVAL_DECIDED",
                action_id,
                {
                    "approval_id": approval_id,
                    "approver_id": identity["id"],
                    "decision": decision,
                    "justification": justification,
                },
                policy_version,
            )

            action_status = action.get("status")
            result = None

            if decision == "request_info":
                approval["status"] = "info_requested"
                # L'action reste en attente de revue.
                action_status = action.get("status")

            elif decision == "reject":
                approval["status"] = "rejected"
                self._vault.record(
                    "BLOCKED",
                    action_id,
                    {"reason": "rejected_by_approver"},
                    policy_version,
                )
                action["status"] = "DENIED"
                action_status = "DENIED"

            else:  # approve
                approval["status"] = "approved"
                try:
                    ok, rule_ids, reasons = self._pipeline.revalidate(
                        action, approval
                    )
                    if not ok:
                        self._vault.record(
                            "BLOCKED",
                            action_id,
                            {
                                "reason": "revalidation_failed",
                                "rule_ids": rule_ids,
                                "reasons": reasons,
                            },
                            policy_version,
                        )
                        action["status"] = "DENIED"
                        action_status = "DENIED"
                    else:
                        # execute_approved journalise EXECUTED ou BLOCKED.
                        exec_status, result = self._pipeline.execute_approved(action)
                        action["status"] = exec_status
                        action["result"] = result
                        action_status = exec_status
                except Exception as exc:
                    # Fail closed : toute erreur interne bloque l'action.
                    self._vault.record(
                        "BLOCKED",
                        action_id,
                        {"reason": "internal_error", "error": type(exc).__name__},
                        policy_version,
                    )
                    action["status"] = "DENIED"
                    action_status = "DENIED"
                    result = None

            self._store.put_approval(approval)
            self._store.put_action(action)

            return {
                "approval": self._enrich(approval),
                "action_status": action_status,
                "result": result,
            }
