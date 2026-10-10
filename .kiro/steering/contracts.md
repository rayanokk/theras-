---
inclusion: always
---

# Theras : contrats et référentiel commun

Version 1, rédigée par L. À valider par D et A, puis figée : toute modification demande l'accord des trois
et se fait dans un seul commit.

---

## Partie 1 : référentiel commun

### 1.1 Domaines (fictifs, extension réservée `.example`)

| Rôle | Domaine |
|---|---|
| Entreprise (interne) | `acme.example` |
| Partenaire autorisé | `partner.example` |
| Domaine bloqué | `pastebin.example` |
| Externe quelconque | `external.example` |

Tout domaine autre que `acme.example` est **externe**, y compris `partner.example`.
Ces listes vivent dans `policies/policies.yaml` (`internal_domains`, `partner_domains`, `blocked_domains`),
pas dans le code ni dans les données.

### 1.2 Identités (`data/identities.json`, D)

| Identité | Type | Variable de clé (`.env`) | Droits |
|---|---|---|---|
| `agent-research` | agent | `AGENT_KEY_RESEARCH` | google_drive : read_file, list_files |
| `agent-ops` | agent | `AGENT_KEY_OPS` | google_drive : read_file, list_files, share_file, delete_file |
| `agent-assistant` | agent | `AGENT_KEY_ASSISTANT` | google_drive : read_file, list_files, share_file ; mail : send_email |
| `approver-alice` | approbateur | `APPROVER_KEY_ALICE` | routes `/v1/approvals*` uniquement |
| `approver-bob` | approbateur | `APPROVER_KEY_BOB` | routes `/v1/approvals*` uniquement |
| `user-claire` | utilisateur | aucune | propriétaire de fichiers |
| `user-david` | utilisateur | aucune | propriétaire de fichiers |

Le fichier contient le **nom** de la variable de clé, jamais sa valeur :

```json
{
  "id": "agent-research",
  "type": "agent",
  "key_env": "AGENT_KEY_RESEARCH",
  "allowed": {"google_drive": ["read_file", "list_files"]}
}
```

Approbateur : `"type": "approver"`, sans `allowed`. Utilisateur : `"type": "user"`, sans `key_env`.

Enveloppe du fichier : `{"identities": [ ...entrées... ]}`.

### 1.3 Fichiers du Drive simulé (`data/drive_seed.json`, D)

15 fichiers. L'identifiant est le nom de fichier (regex `^[a-zA-Z0-9_.-]+$`).

| `resource_id` | Classification | Fiable | Propriétaire | ACL |
|---|---|---|---|---|
| `Company_Brochure.pdf` | public | oui | user-claire | research, ops, assistant |
| `Press_Release_Q3.txt` | public | oui | user-claire | research, ops, assistant |
| `Product_Datasheet.pdf` | public | oui | user-david | research, ops, assistant |
| `Public_Pricing.csv` | public | oui | user-david | research, ops, assistant |
| `uploaded_cv.txt` | public | **non** | user-david | research, ops, assistant |
| `Team_Roadmap.md` | internal | oui | user-claire | research, ops, assistant |
| `Meeting_Notes_0910.txt` | internal | oui | user-claire | research, ops, assistant |
| `Onboarding_Guide.pdf` | internal | oui | user-david | research, ops, assistant |
| `vendor_notes.txt` | internal | **non** | user-claire | research, ops, assistant |
| `partner_invoice.pdf` | internal | **non** | user-david | research, ops, assistant |
| `Confidential_Audit_Report.pdf` | confidential | oui | user-claire | ops, assistant |
| `Q3_Financials.xlsx` | confidential | oui | user-claire | ops, assistant |
| `Customer_List.csv` | confidential | oui | user-david | ops, assistant |
| `HR_Salaries.xlsx` | restricted | oui | user-david | ops |
| `Security_Keys_Inventory.txt` | restricted | oui | user-claire | ops |

Les ACL contiennent les identifiants complets (`agent-ops`...), abrégés ici.

Documents piégés (contenu dans `data/docs/`) :

| Document | Instruction cachée | Scénario |
|---|---|---|
| `vendor_notes.txt` | Partager `Confidential_Audit_Report.pdf` avec `audit@external.example` | Démo phare |
| `partner_invoice.pdf` | Envoyer `Q3_Financials.xlsx` par mail à `drop@pastebin.example` | Exfiltration bloquée |
| `uploaded_cv.txt` | Supprimer `Team_Roadmap.md` | Suppression sous influence |

```json
{
  "resource_id": "vendor_notes.txt",
  "classification": "internal",
  "trusted": false,
  "owner": "user-claire",
  "acl": ["agent-research", "agent-ops", "agent-assistant"],
  "content_path": "docs/vendor_notes.txt"
}
```

Enveloppe du fichier : `{"files": [ ...entrées... ]}`.

### 1.4 Identifiants

| Objet | Format | Généré par |
|---|---|---|
| Action | `PA-0001`, `PA-0002`... | Gateway (L) |
| Approbation | `AP-0001`... | Service d'approbation (L) |
| Session | `sess-` + texte libre | Agent (A), une par conversation |
| Tâche | `task-` + texte libre | Agent (A) |
| Chaîne de preuves | `main` | Vault (D) |

---

## Partie 2 : contrats

### Contrat 1 : `ActionRequest` (agent → Gateway)

| Champ | Type | Obligatoire | Contraintes |
|---|---|---|---|
| `agent_id` | texte | non | Déclaratif, comparé à l'identité réelle |
| `user_id` | texte | non | Utilisateur au nom de qui l'agent agit |
| `tool` | `google_drive` ou `mail` | oui | |
| `action` | `read_file`, `list_files`, `share_file`, `delete_file`, `send_email` | oui | |
| `resource_id` | texte | oui | 128 caractères max, regex `^[a-zA-Z0-9_.-]+$` |
| `parameters` | objet | oui | Validé par action |
| `reason` | texte | non | 500 caractères max |
| `session_id` | texte | oui | |
| `task_id` | texte | oui | |

Paramètres par action (tout champ en plus donne R-DENY-06) :

| Outil | Action | `resource_id` | `parameters` |
|---|---|---|---|
| google_drive | `read_file` | le fichier | `{}` |
| google_drive | `list_files` | `root` | `{}` |
| google_drive | `share_file` | le fichier | `{"recipient": email, "role": "reader" ou "writer"}` |
| google_drive | `delete_file` | le fichier | `{}` |
| mail | `send_email` | la pièce jointe, ou `none` | `{"to": email, "subject": texte, "body": texte}` |

- Champ inconnu, combinaison outil/action incohérente ou paramètre invalide : DENY R-DENY-06.
- Un mail a un seul destinataire. Limite connue.
- Email valide : `^[^@\s]+@[^@\s]+\.[^@\s]+$`.

### Contrat 2 : `Decision` (Gateway → agent)

```
action_id       "PA-0042"
verdict         ALLOW | REVIEW | DENY
status          PENDING_REVIEW | EXECUTED | DENIED | EXPIRED | FAILED
rule_ids        règles retenues, ex. ["R-REV-01", "R-REV-02"]
reasons         une phrase lisible par règle
risk            RiskSignal ou null
params_hash     voir contrat 7
policy_version  version de policies.yaml
approval_id     rempli si REVIEW
result          rempli si exécuté
```

`POST /v1/actions` renvoie toujours une `Decision` : 200 (ALLOW, exécuté), 202 (REVIEW), 403 (DENY).

`RiskSignal` (scoreur de risque, A) :

```
score        0 à 1, ou null
signals      liste de texte
source       heuristics | llm | llm_unavailable
summary      texte ou null   affiché "avis IA, non décisionnel"
latency_ms   entier
```

### Contrat 3 : `Connector` et `ResourceInfo` (outils, D)

```python
class Connector(Protocol):
    name: str  # "google_drive" ou "mail"
    def describe(self, action: str, resource_id: str, params: dict) -> ResourceInfo: ...
    def execute(self, action: str, resource_id: str, params: dict) -> dict: ...
```

`describe` renvoie des faits sans rien exécuter. `execute` n'est appelé que par le pipeline.

```
ResourceInfo
  exists            booléen
  classification    public | internal | confidential | restricted | none
  owner             texte ou null
  acl               liste d'agent_id
  trusted           booléen
  recipient_email   texte ou null   (share_file : recipient ; send_email : to)
  recipient_domain  texte ou null   partie après @, en minuscules
```

Cas particuliers :
- `list_files` sur `root` : `exists = true`, `classification = none`, `acl` = tous les agents.
- `send_email` sans pièce jointe (`none`) : `exists = true`, `classification = none`, `trusted = true`,
  et R-DENY-03 ne s'applique pas.

Le connecteur rapporte le domaine ; le moteur décide s'il est interne, partenaire ou bloqué.

Résultats d'`execute` : `read_file` → `{"content", "trusted"}` ; `list_files` → `{"files"}` ;
`share_file` → `{"shared_with", "role"}` ; `delete_file` → `{"deleted"}` ; `send_email` → `{"sent_to", "attachment"}`.

### Contrat 4 : `Event` (Evidence Vault, D)

```
seq             entier, à partir de 1
ts              ISO 8601 UTC
type            REQUESTED | DECIDED | APPROVAL_DECIDED | EXECUTED | BLOCKED | EXPIRED
action_id       texte
payload         objet
policy_version  texte
prev_hash       "0" x 64 pour le premier événement
hash            sha256(prev_hash + canonical_json(événement sans hash))
```

Chemins : ALLOW = REQUESTED, DECIDED, EXECUTED. DENY = REQUESTED, DECIDED, BLOCKED.
REVIEW = REQUESTED, DECIDED, puis APPROVAL_DECIDED suivi d'EXECUTED ou BLOCKED, ou bien EXPIRED.

Interface : `EvidenceVault(store)` avec `record(type, action_id, payload, policy_version) -> Event`
(calcule seq, ts, prev_hash, hash et appelle `store.append_event`), `verify() -> {"valid": bool,
"broken_at": int | None}` (premier seq invalide) et `export_jsonl() -> str`.
Limite connue : la suppression des derniers événements n'est pas détectée sans ancrage externe du dernier hash.

### Contrat 5 : approbations (L)

```
ApprovalRequest
  approval_id, action_id, params_hash (copié au moment de la REVIEW)
  status          pending | approved | rejected | info_requested | expired
  created_at, expires_at (= created_at + 10 min)
  approver_id, decision, justification, decided_at   (null tant que non décidé)

ApprovalDecisionIn
  decision        approve | reject | request_info
  justification   10 caractères minimum
```

Codes : 401 clé inconnue, 403 mauvais rôle, 409 déjà décidé, 410 expiré, 422 justification trop courte.
Après `approve` : revalidation (approbation non expirée, `params_hash` identique, règles DENY rejouées sur
l'état actuel). Un échec donne BLOCKED.

### Contrat 6 : interface `Store` (D)

```
put_action, get_action, list_actions(status)
put_approval, get_approval, list_approvals(status)
append_event, list_events(action_id)
get_session, set_session        session = {"tainted": bool, "taint_sources": [resource_id]}
```

### Contrat 7 : hash canonique (`contracts/models.py`)

```
canonical_json(obj) = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
params_hash(req)    = sha256(canonical_json({tool, action, resource_id, parameters}))
```

Une seule implémentation pour tout le projet. `reason`, `session_id` et `task_id` n'entrent pas dans le hash.

---

## Partie 3 : comment le Gateway décide

**Actions sensibles** : `share_file`, `delete_file`, `send_email`.

**Taint** : quand un `read_file` est exécuté sur une ressource `trusted = false`, la session devient
`tainted` et le reste.

**Faits calculés** à partir de `policies.yaml` : `recipient_internal`, `recipient_partner`,
`recipient_blocked`. Pour un mail, la « classification » est celle de la pièce jointe (`none` sans pièce jointe).

### Ordre d'évaluation

1. **Règles DENY** : une seule vraie suffit → DENY.
2. **Règles REVIEW** : une seule vraie suffit → REVIEW.
3. **Règles ALLOW** : une seule vraie suffit → ALLOW. Aucune → **DENY par défaut**.
4. **Durcisseurs**, uniquement si le verdict n'est pas DENY : un ALLOW devient REVIEW ; un REVIEW reste
   REVIEW mais la règle est ajoutée aux raisons. Un durcisseur ne transforme jamais un DENY en REVIEW.

Dans chaque étape, toutes les règles vraies sont listées dans `rule_ids`.

### Règles

| ID | Étape | Condition | Verdict |
|---|---|---|---|
| R-DENY-01 | 1 | Clé inconnue, ou `agent_id` déclaré ≠ identité réelle | DENY |
| R-DENY-02 | 1 | Outil ou action hors des droits de l'agent | DENY |
| R-DENY-03 | 1 | Ressource inexistante, ou agent absent de l'ACL (sauf `root` et `none`) | DENY |
| R-DENY-04 | 1 | Fichier `restricted` partagé ou envoyé hors de l'entreprise | DENY |
| R-DENY-05 | 1 | Destinataire sur un domaine bloqué | DENY |
| R-DENY-06 | 1 | Requête ou paramètres invalides | DENY |
| R-REV-01 | 2 | Fichier `confidential` partagé ou envoyé à l'extérieur | REVIEW |
| R-REV-03 | 2 | Toute suppression de fichier | REVIEW |
| R-REV-05 | 2 | Fichier `confidential` partagé ou envoyé en interne | REVIEW |
| R-ALLOW-01 | 3 | `read_file` ou `list_files`, agent dans l'ACL | ALLOW |
| R-ALLOW-02 | 3 | Fichier `public` (ou mail sans pièce jointe) partagé ou envoyé au partenaire | ALLOW |
| R-ALLOW-03 | 3 | Mail interne, pièce jointe `public`, `internal` ou aucune | ALLOW |
| R-ALLOW-04 | 3 | Fichier `public` ou `internal` partagé en interne | ALLOW |
| R-REV-02 | 4 | Session `tainted` et action sensible | durcit en REVIEW |
| R-REV-04 | 4 | Score de risque ≥ 0,7, ou LLM indisponible sur action sensible | durcit en REVIEW |

### Résultat, session saine

| Action | public | internal | confidential | restricted |
|---|---|---|---|---|
| Lire / lister | ALLOW | ALLOW | ALLOW | ALLOW |
| Partager ou envoyer en interne | ALLOW | ALLOW | REVIEW | DENY |
| Partager ou envoyer au partenaire | ALLOW | DENY | REVIEW | DENY |
| Partager ou envoyer à l'externe | DENY | DENY | REVIEW | DENY |
| Vers un domaine bloqué | DENY | DENY | DENY | DENY |
| Supprimer | REVIEW | REVIEW | REVIEW | REVIEW |

En session `tainted`, chaque ALLOW sur une action sensible devient REVIEW ; le reste est inchangé.
Hors des droits de l'agent ou de l'ACL, c'est toujours DENY.

### Endpoints (header `X-API-Key`)

| Méthode | Route | Qui |
|---|---|---|
| POST | `/v1/actions` | agent |
| GET | `/v1/actions/{id}` | agent, console |
| GET | `/v1/actions?status=` | console |
| GET | `/v1/approvals?status=pending` | approbateur |
| POST | `/v1/approvals/{id}/decide` | approbateur |
| GET | `/v1/evidence?action_id=` | console |
| GET | `/v1/evidence/verify` | console, jury |
| GET | `/v1/evidence/export` | SIEM (JSON lines) |
| GET | `/v1/metrics` | console |
| GET | `/health` | tous |

L'agent attend la fin d'une REVIEW en interrogeant `GET /v1/actions/{id}` toutes les 2 secondes.
