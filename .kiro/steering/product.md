---
inclusion: always
---

# Theras : produit et règles d'or

## Le produit

Theras est un Gateway placé entre des agents IA et leurs outils (Drive simulé, Mail simulé).
Chaque action d'un agent passe par lui : il l'intercepte, la normalise, l'autorise avec des règles fixes,
évalue un risque, décide (ALLOW, REVIEW ou DENY), applique la décision et écrit une preuve.

On ne cherche pas à empêcher l'agent d'être manipulé (prompt injection) : on empêche un agent manipulé
de nuire. Le système regarde les actions et la provenance des données, jamais le texte pour décider.

Contexte : hackathon Secure Horizons, Track 2 (AI for Security & Secure AI), équipe de trois.
Fonctions NIST CSF visées : Detect et Respond. Risques OWASP agentiques visés : ASI01 (détournement
d'objectif), ASI02 (mauvais usage d'outils), ASI03 (abus d'identité et de privilèges).

## Stack

Python 3.11+, FastAPI, Pydantic v2, SQLite derrière une interface Store, Streamlit pour la console,
boto3 (Bedrock Converse) pour l'agent et le scoreur de risque, pytest pour les tests.

## Règles d'or (non négociables)

1. L'agent ne parle qu'au Gateway. Il n'a ni credentials ni import Python vers les connecteurs.
   Les connecteurs ne sont importés que par `police/gateway/pipeline.py`.
2. La décision vient de règles fixes et versionnées (`policies/policies.yaml`), jamais d'un LLM.
3. Le LLM de risque peut seulement durcir une décision (ALLOW vers REVIEW), jamais l'adoucir.
   S'il répond mal, en retard ou pas du tout, l'action sensible part en REVIEW (fail closed).
4. Refus par défaut : une action qu'aucune règle n'autorise explicitement est refusée.
   Ordre d'évaluation : DENY, puis REVIEW, puis ALLOW, puis DENY par défaut.
5. Taint tracking : quand l'agent lit un document non fiable, la session est marquée tainted et toute
   action sensible qui aurait été autorisée passe en REVIEW, quel que soit le texte de l'injection.
   Lire un document douteux ne peut que rendre le système plus prudent, jamais plus permissif.
6. Une approbation est liée à un `params_hash` précis, expire après 10 minutes, et le Gateway rejoue
   tout le contrôle avant d'exécuter. Une REVIEW ne lève jamais un DENY.
7. Chaque chemin (bloqué, approuvé, exécuté) est écrit dans l'Evidence Vault (chaîne SHA-256).
8. Une requête invalide n'est jamais rejetée par FastAPI (pas de 422 automatique sur `/v1/actions`) :
   la validation se fait dans le pipeline, qui produit un DENY R-DENY-06 tracé dans le Vault.
9. Le mode `--no-llm` est obligatoire : le benchmark doit tourner sans Bedrock.
10. Aucun secret dans le repo. Données fictives uniquement (domaines en `.example`).

## Méthode de travail

- Une tâche à la fois, relue avant la suivante. Pas d'autopilot sur tout le repo.
- Expliquer avant de coder, écrire le test avant l'implémentation.
- Chacun ne modifie que les dossiers dont il est propriétaire (voir `structure.md`).
- `contracts.md` est figé : il ne change qu'avec l'accord des trois.
- Tout script long (benchmark) affiche sa progression et son temps d'exécution (rich ou tqdm).
