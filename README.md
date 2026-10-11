# Theras

Theras n'empêche pas un agent d'être manipulé, il empêche un agent manipulé de nuire.

Un agent IA qui lit un contenu piégé (injection indirecte : une instruction cachée dans un CV,
une facture, des notes) peut être retourné contre l'entreprise et ordonné d'exfiltrer ou de
supprimer des données. Le modèle refuse parfois, mais pas toujours. Theras garantit le refus : un
Gateway déterministe placé entre les agents et leurs outils, qui regarde l'action demandée et la
provenance des données, jamais le texte, et décide **ALLOW**, **REVIEW** ou **DENY**.

## 1. Architecture

```
agent natif (HTTP)  ─┐
                     ├─>  Gateway Theras  ─>  connecteurs natifs (Drive, Mail)
agent client MCP  ─> façade MCP           └─>  amont MCP (demo_drive = theras_mocks)
 (proxy)             │
                     ├── identité (clé X-API-Key -> identité réelle)
                     ├── validation (dans le pipeline, jamais de 422)
                     ├── action canonique (effet manifeste -> action du contrat)
                     ├── faits vérifiés (un fait non vérifié est absent)
                     ├── taint (session + agent, 15 min)
                     ├── moteur de règles (policies/policies.yaml)
                     ├── scoreur de risque (durcit seulement, fail closed)
                     └── approbations (scellées sur params_hash, TTL 10 min)
```

- La façade MCP (`police.mcp_firewall.proxy`) est la prise que voit un client MCP : elle ne décide
  rien, chaque appel devient un `POST /v1/actions` vers le Gateway.
- Chaque décision est scellée dans un **registre chaîné SHA-256** (Evidence Vault).
- Une **console Streamlit** affiche les actions, les preuves et traite les approbations.

## 2. Le pipeline, étape par étape

1. **Identité** : la clé `X-API-Key` résout l'identité réelle de l'agent. Un `agent_id` déclaré qui
   ne correspond pas est refusé (R-DENY-01).
2. **Validation** : la requête et ses paramètres sont validés **dans le pipeline**, jamais par
   FastAPI. Une requête invalide devient un DENY tracé (R-DENY-06), jamais une 422.
3. **Faits vérifiés** : droits de l'agent, ACL, classification, destinataire. Un fait non vérifié
   est **absent** du dictionnaire (ni `false`, ni `null`) : une condition sur un fait absent est
   fausse. Défaillance fermée par construction.
4. **Taint** : lire un fichier `trusted = false` marque la **session** (`session_id` déclaré) et
   l'**identité réelle de l'agent** (clé API, TTL `agent_taint_ttl_minutes`, 15 min). Changer de
   `session_id` entre la lecture et l'action ne lave pas la contamination.
5. **Décision** : règles fixes et versionnées, jamais un LLM, dans l'ordre
   **DENY > REVIEW > ALLOW > R-DENY-DEFAULT** (refus par défaut si rien n'autorise).
6. **Durcisseurs** : le taint ou le scoreur de risque transforment un ALLOW en REVIEW. Jamais
   l'inverse, et jamais un DENY en REVIEW.
7. **Approbations** : une REVIEW crée une approbation **scellée sur le `params_hash`**, TTL 10 min.
   Avant d'exécuter, le Gateway **rejoue tout le contrôle** sur l'état courant (revalidation). Un
   `params_hash` différent ou un DENY au recalcul bloque l'action (fail closed).
8. **Registre** : chaque chemin (bloqué, approuvé, exécuté, expiré) est écrit dans l'Evidence Vault,
   chaque événement chaîné au précédent par `sha256(prev_hash + canonical_json(event))`.

## 3. Tableau des règles

Source : `policies/policies.yaml` (`policy_version: "2026-10-10.1"`).

| ID | Étape | Explication |
|---|---|---|
| R-DENY-01 | deny | Clé API inconnue, ou `agent_id` déclaré différent de l'identité réelle. |
| R-DENY-02 | deny | Outil ou action hors des droits de cet agent. |
| R-DENY-03 | deny | Ressource inexistante, ou agent absent de la liste d'accès. |
| R-DENY-04 | deny | Fichier `restricted` partagé ou envoyé hors de l'entreprise. |
| R-DENY-05 | deny | Destinataire sur un domaine bloqué. |
| R-DENY-06 | deny | Requête ou paramètres invalides. |
| R-REV-01 | review | Fichier `confidential` partagé ou envoyé hors de l'entreprise. |
| R-REV-03 | review | Suppression de fichier (action irréversible). |
| R-REV-05 | review | Fichier `confidential` partagé ou envoyé en interne. |
| R-ALLOW-01 | allow | Lecture ou liste par un agent présent dans l'ACL. |
| R-ALLOW-02 | allow | Contenu `public` (ou mail sans pièce jointe) partagé ou envoyé au partenaire autorisé. |
| R-ALLOW-03 | allow | Mail interne, pièce jointe `public`, `internal` ou absente. |
| R-ALLOW-04 | allow | Fichier `public` ou `internal` partagé en interne. |
| R-REV-02 | harden | Action sensible et session **ou** agent contaminé par un document non fiable : durcit en REVIEW. |
| R-REV-04 | harden | Score de risque ≥ 0,7, ou évaluation du risque indisponible sur action sensible : durcit en REVIEW. |
| R-DENY-DEFAULT | — | Aucune règle n'autorise explicitement l'action : refus par défaut. |

Domaines (dans `policies.yaml`, pas dans le code) : interne `acme.example`, partenaire
`partner.example`, bloqué `pastebin.example`. Tout le reste est externe.

## 4. Pare-feu MCP (v2)

Theras peut se placer devant des serveurs MCP tiers sans code spécifique à chacun. Un **manifeste
YAML** par serveur amont déclare l'effet de ses outils ; le Gateway applique la même politique que
pour les outils natifs.

Un manifeste (`police/mcp_firewall/manifests/*.yaml`, modèle `manifest.py`, `extra="forbid"`
partout) déclare :

- `server`, `default_classification`, `acl` (non vide) ;
- `resources` : règles `match` (motif `fnmatch`), `classification`, `trusted` ;
- `tools` : par outil, `effect`, `resource_from`, `recipient_from` (requis pour `share`/`send`),
  `untrusted_output`, `classification`.

**Traduction** (`translate.py`) : l'effet devient l'action canonique du contrat
(`read -> read_file`, `list -> list_files`, `share -> share_file`, `delete -> delete_file`,
`send -> send_email`, `write -> write`). La politique s'applique à l'action canonique, inchangée.
`write` n'a aucune règle ALLOW : il tombe donc sur R-DENY-DEFAULT (fail closed).

**Défenses contre le tool poisoning** (`proxy.py`) :

- les descriptions exposées sont **reconstruites depuis le manifeste**, jamais reprises de l'amont ;
- le schéma d'entrée amont passe par une **liste blanche** de mots-clés structurels ; tout texte
  libre (description, title, examples, default…) est supprimé, les noms d'arguments et les valeurs
  d'enum sont validés, un schéma suspect écarte l'outil (fail closed) ;
- la **fiabilité (`trusted`) vient toujours du manifeste**, jamais de la réponse de l'amont.

**Activation** : `THERAS_MCP_FIREWALL=true` charge les manifestes et les amonts. À `false` (défaut),
le Gateway est strictement identique à la v1 : aucun manifeste, aucun sous-processus. Les droits par
serveur amont vivent dans `data/identities.json` (ex. `demo_drive` dans `allowed`).

## 5. Démarrage rapide

Une seule machine. Instructions pour **Windows (Git Bash)** et **macOS**. Prérequis : Python 3.11+.

### Installation

```bash
python -m venv .venv
. .venv/bin/activate            # Windows : . .venv/Scripts/activate
pip install -r requirements.txt
cp .env.example .env
```

Les clés de `.env.example` sont des valeurs **fictives** de développement. Aucune donnée réelle,
aucun secret : les domaines sont en `.example`, Drive et Mail sont des mocks.

### Gateway

Dans un terminal :

```bash
set -a; source .env; set +a
unset RISK_LLM_ENABLED
THERAS_MCP_FIREWALL=true RISK_LLM_ENABLED=false uvicorn police.gateway.main:app --host 127.0.0.1 --port 8000
```

`RISK_LLM_ENABLED=false` lance le scoreur en mode heuristiques seules, sans Bedrock.

### Console

Dans un second terminal :

```bash
set -a; source .env; set +a
export CONSOLE_MODE=http GATEWAY_URL=http://127.0.0.1:8000
PYTHONPATH=. python -m streamlit run console/app.py
```

### Remise à zéro

Arrêter le Gateway (Ctrl-C), puis supprimer la base SQLite `police.db` (variable `POLICE_DB_PATH`,
défaut `./police.db`).

### Dépannage

- Utiliser `127.0.0.1`, pas `localhost`, sous Windows.
- Erreur `10048` : un ancien Gateway occupe déjà le port 8000.

  ```bash
  netstat -ano | grep :8000
  taskkill //PID <pid> //F
  ```

- `401` : le `.env` n'est pas chargé dans le terminal du Gateway **ou** de la console. Rejouer
  `set -a; source .env; set +a` dans le bon terminal.
- Sous Windows, ne pas cliquer dans le terminal `uvicorn` : le mode sélection de la console fige le
  processus. Appuyer sur Entrée pour le relancer si c'est arrivé.

## 6. Brancher un client MCP

La façade `police.mcp_firewall.proxy` expose les outils amont sous le nom `server__tool`. Ajouter
**uniquement** ce bloc au fichier de configuration MCP existant du client (ne pas écraser le reste) :

```json
{
  "mcpServers": {
    "theras": {
      "command": "C:\\Users\\...\\thesar\\.venv\\Scripts\\python.exe",
      "args": ["-m", "police.mcp_firewall.proxy"],
      "env": {
        "THERAS_GATEWAY_URL": "http://127.0.0.1:8000",
        "THERAS_AGENT_KEY": "dev-agent-assistant-key",
        "PYTHONPATH": "C:\\Users\\...\\thesar"
      }
    }
  }
}
```

- `command` : chemin **absolu** du Python du venv.
- Sous Windows, séparer les chemins par `\\` ; sous macOS, par `/`
  (`/chemin/vers/thesar/.venv/bin/python`, `PYTHONPATH` = racine du repo).
- `THERAS_AGENT_KEY` est le nom donné dans `.env` à la clé de l'agent choisi ; ne jamais y écrire de
  vrai secret. Le Gateway déduit l'identité de la clé : pas d'`agent_id`.

## 7. Scénarios de démo

1. **Lecture d'un document piégé** : l'agent lit `vendor_notes.txt` → **ALLOW**. Le contenu est
   marqué non fiable, la session et l'identité de l'agent deviennent contaminées.
2. **Partage détourné** : l'agent, retourné par l'instruction cachée, tente de partager
   `Confidential_Audit_Report.pdf` vers `audit@external.example` → **REVIEW**
   (R-REV-01 confidentiel vers l'externe, R-REV-02 contamination + action sensible, R-REV-04
   durcissement du risque). Une carte apparaît dans la console :
   - refus de l'approbateur → l'action passe **DENIED**, rien n'est partagé ;
   - approbation → revalidation complète, puis **EXECUTED**.
3. **Exfiltration bloquée** : partage ou envoi vers un domaine d'exfiltration
   (`drop@pastebin.example`) → **DENY** (R-DENY-05), avant toute approbation.
4. **Action non couverte** : un partage qu'aucune règle n'autorise (ex. fichier `internal` vers le
   partenaire) → **DENY** par refus par défaut (R-DENY-DEFAULT).

## 8. Tests et mesures

Tests unitaires :

```bash
pytest -q
```

Banc (sans Bedrock), depuis la racine du repo :

```bash
RISK_LLM_ENABLED=false python -m bench.run_bench            # 30 scénarios manuels
RISK_LLM_ENABLED=false python -m bench.run_bench --dataset <dataset.json>   # dataset Forge
```

Le banc reconstruit un Gateway neuf et isolé par scénario (store jetable, Drive et taint vierges) et
l'appelle via le `TestClient` de FastAPI (en processus, pas de serveur HTTP). Résultats observés en
mode **sans LLM** sur le dataset Forge enregistré (`bench/results/results_no-llm.json`, 20
scénarios, 25 étapes) :

- blocage des actions malveillantes : **15/15 arrêtées** ;
- règles exactes : **22/25** ;
- faux positifs : **0** (sur 5 scénarios légitimes) ;
- chaîne de preuves : valide ;
- latences en processus : **p50 ≈ 53 ms**, p95 ≈ 82 ms (mesure `TestClient`, pas HTTP réseau).

Les 3 écarts de règles sont tous le même cas **G-ABU-03 / G-ABU-15 / G-ABU-19** : l'oracle Forge
attend `R-DENY-02` **et** `R-DENY-03`, mais `R-DENY-03` ne se déclenche pas. C'est voulu : dès que
`R-DENY-02` établit que l'action est hors des droits de l'agent, le fait d'ACL n'est pas vérifié et
reste **absent** (principe « un fait non vérifié est absent »), donc `R-DENY-03` ne peut pas
s'ajouter. La décision **DENY** est correcte ; seule la liste des règles diffère de l'oracle.

## 9. Limites connues et pistes

- L'injection n'est pas empêchée : Theras en contrôle les conséquences, pas la cause.
- La protection repose sur l'étiquetage des fichiers (`classification`, `trusted`) ; un fichier mal
  classé est jugé selon son étiquette.
- Le corps des emails n'est pas inspecté ; la décision porte sur l'action et la pièce jointe.
- Un mail n'a qu'un seul destinataire (limite assumée du contrat).
- La suppression des tout derniers événements du registre n'est pas détectable sans ancrage externe
  du dernier hash (la falsification d'un événement existant, elle, l'est).
- Point unique de passage : si le Gateway est indisponible, plus aucune action ne passe (fail
  closed), mais plus rien ne passe non plus.
- Piste : ancrage externe du dernier hash, inspection du corps des mails, destinataires multiples.

## 10. Versions et équipe

- Tag **`v1-demo`** : Gateway natif (agents en HTTP, connecteurs Drive et Mail).
- Tag **`v2-demo`** : pare-feu MCP (manifestes, façade, amont `demo_drive`).

Équipe (trois) :

- **L** : Gateway, moteur de règles, approbations, pare-feu MCP.
- **D** : données, store, connecteurs, registre de preuves, console, client et façade MCP.
- **A** : agent Bedrock, documents piégés, scoreur de risque, banc, Forge.

---

### Vérifications

**Commandes ou chemins non vérifiés dans le repo :**

- Section 6 : le bloc `mcpServers`. La façade `proxy.py` lit bien `THERAS_GATEWAY_URL` (et non
  `GATEWAY_URL`) et `THERAS_AGENT_KEY` ; j'ai donc écrit `THERAS_GATEWAY_URL` dans l'exemple, à la
  place du `GATEWAY_URL` indiqué dans la consigne. `PYTHONPATH` n'est pas lu par `proxy.py` lui-même
  mais reste nécessaire pour que `python -m police.mcp_firewall.proxy` trouve le paquet depuis un
  répertoire quelconque ; je l'ai conservé.
- Section 8 : la commande `pytest -q` est générique ; je n'ai pas ouvert le dossier `tests/` ni
  exécuté la suite, donc je ne garantis pas les noms de fichiers de test.
- `GET /v1/metrics` : mentionné par le contrat mais **absent** de `police/gateway/api.py`. Je ne
  l'ai donc pas documenté. À signaler au propriétaire du Gateway.

**Chiffres repris tels quels (non recalculés par moi) :**

- Les métriques du banc (15/15 arrêtées, 22/25 règles exactes, 0 faux positif sur 5 légitimes,
  p50 ≈ 53 ms, p95 ≈ 82 ms, 20 scénarios / 25 étapes) proviennent **directement** du fichier
  `bench/results/results_no-llm.json` présent dans le repo (mode `no-llm`, dataset Forge).
- Je **n'ai pas pu confirmer** les chiffres demandés dans la consigne : « 30/30 décisions, 37/37
  règles exactes, 100 % des attaques arrêtées, p50 ≈ 3 ms (~20 ms HTTP, ~36 ms via la façade),
  Forge 8/8 et 12/13 ». Aucun fichier de résultats du repo ne les contient. Les seuls résultats
  présents (`results_no-llm.json` et `results_forge_20261011-084501.json`) portent sur 20 scénarios
  Forge avec 15/15 et 22/25, et un p50 de 53 ms. Le fichier `scenarios.yaml` contient bien 30
  scénarios manuels, mais aucun fichier de résultats correspondant n'est enregistré. J'ai donc écrit
  les chiffres réellement présents plutôt que ceux de la consigne.
