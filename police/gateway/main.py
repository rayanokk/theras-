"""Point d'entree de l'API : construit toutes les pieces et expose `app`.

Lancement :
    uvicorn police.gateway.main:app --reload

Les cles d'agent et d'approbateur sont lues depuis l'environnement (.env),
jamais ecrites dans le repo (regle d'or 10). Le scoreur de risque est None ici :
l'API tourne sans Bedrock par defaut (le pipeline fail-close sur action
sensible via R-REV-04 uniquement si un scoreur indisponible est branche).
"""

from __future__ import annotations

import os

from dotenv import load_dotenv

from police.connectors.drive_mock import DriveMock
from police.connectors.mail_mock import MailMock
from police.evidence.vault import EvidenceVault
from police.gateway.api import create_app
from police.gateway.pipeline import Pipeline
from police.identity import IdentityRegistry
from police.policy.engine import load_policy
from police.policy.taint import TaintTracker
from police.store.sqlite_store import SQLiteStore

load_dotenv()

policy = load_policy("policies/policies.yaml")
identities = IdentityRegistry("data/identities.json")
store = SQLiteStore(os.getenv("POLICE_DB_PATH", "./police.db"))

drive = DriveMock()
mail = MailMock(drive)
vault = EvidenceVault(store)
taint = TaintTracker(store)
connectors = {"google_drive": drive, "mail": mail}

pipeline = Pipeline(
    policy=policy,
    identities=identities,
    connectors=connectors,
    store=store,
    vault=vault,
    taint=taint,
    risk_scorer=None,
)

app = create_app(pipeline, store, vault, identities)
