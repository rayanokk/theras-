---
inclusion: always
---

# Structure du repo et propriétaires

L = Lead / Core, D = Data et Preuves, A = Agent et Attaque.
Chacun ne modifie que ses dossiers ; pour un changement ailleurs, on écrit au propriétaire.

```
<racine du repo>/
├── README.md                 (L) problème, architecture, démo en 3 commandes, limites
├── requirements.txt          (L)
├── .env.example              (L) valeurs factices uniquement ; .env n'est jamais commité
├── .gitignore                (L)
├── Makefile                  (L) make api / make console / make bench / make demo
├── .kiro/steering/           (L) product.md, contracts.md, structure.md
│
├── contracts/                (L, figé)
│   ├── models.py             modèles Pydantic, canonical_json, params_hash
│   ├── export_schema.py      génère action_contract.schema.json
│   └── action_contract.schema.json
│
├── policies/
│   └── policies.yaml         (L) règles DENY/REVIEW/ALLOW, domaines, policy_version
│
├── data/                     (D) tout est fictif
│   ├── identities.json       agents, users, approbateurs (nom de variable de clé, jamais la clé)
│   ├── drive_seed.json       15 fichiers : classification, trusted, owner, ACL
│   └── docs/                 contenus texte, dont 3 documents piégés
│
├── police/                   le cœur
│   ├── gateway/
│   │   ├── api.py            (L) endpoints FastAPI
│   │   ├── pipeline.py       (L) intercept → normalize → authorize → risk → decide → enforce → record
│   │   └── mcp_server.py     (L, bonus) mêmes outils exposés en MCP, via le pipeline
│   ├── identity.py           (L) clé API → identité réelle
│   ├── policy/
│   │   ├── engine.py         (L) évalue policies.yaml, renvoie Decision et rule_ids
│   │   └── taint.py          (L) état tainted des sessions
│   ├── risk/
│   │   ├── heuristics.py     (A) signaux sans LLM
│   │   └── bedrock_risk.py   (A) Haiku → RiskSignal validé, timeout 5 s
│   ├── approvals/
│   │   └── service.py        (L) création, expiration, décision, revalidation, 409
│   ├── evidence/
│   │   └── vault.py          (D) chaîne SHA-256, verify(), export JSONL
│   ├── store/
│   │   ├── base.py           (D) interface Store
│   │   ├── sqlite_store.py   (D)
│   │   └── dynamo_store.py   (D, bonus)
│   └── connectors/
│       ├── base.py           (L écrit l'interface, puis D) Protocol Connector
│       ├── drive_mock.py     (D) read / list / share / delete
│       └── mail_mock.py      (D) send_email
│
├── agent/                    (A) ne connaît que l'URL du Gateway et sa clé
│   ├── runner.py             boucle Bedrock Converse + tool use
│   ├── tools.py              définitions d'outils → appels HTTP au Gateway
│   └── unprotected_runner.py même agent branché directement sur les mocks (démo « sans »)
│
├── console/                  (D) Streamlit
│   ├── app.py
│   └── pages/                1_Approvals.py, 2_Actions.py, 3_Evidence.py, 4_Benchmark.py
│
├── bench/                    (A)
│   ├── scenarios.yaml        30 cas avec verdict et règle attendus, écrits avant le code
│   ├── run_bench.py          rejoue les scénarios, calcule les métriques, écrit results.json
│   └── results/
│
└── tests/                    chacun teste son module
    └── test_contracts.py, test_policy.py, test_vault.py, test_approvals.py, test_connectors.py
```

## Points de sécurité liés à la structure

- Les mocks de connecteurs ne sont importés que par `pipeline.py`. L'agent n'a ni import ni credentials
  vers eux : c'est ce qui rend le contournement impossible, et ce qu'on montre au jury.
- `unprotected_runner.py` est la seule exception, volontaire : il sert à montrer la démo « sans Theras ».

## Branches Git

- Une branche par personne : `lead/...`, `data/...`, `agent/...`.
- Merge sur `main` uniquement aux synchros (15h30, 20h30, 01h30, 08h30, 10h00).
- Avant chaque merge : vérifier qu'aucun secret n'est présent (`git grep -i "aws_secret\|api_key="`).
