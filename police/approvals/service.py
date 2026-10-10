"""Service d'approbation (contrat 5), etape 3.1 : creation d'une approbation.

Une approbation est liee a un `params_hash` precis et expire 10 minutes apres sa
creation. Ici on ne gere que la creation ; la decision, l'expiration et la
revalidation viennent aux etapes suivantes.

Le modele ApprovalRequest vient de contracts/models.py : on ne le redefinit pas.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from contracts.models import ApprovalRequest, ApprovalStatus

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
