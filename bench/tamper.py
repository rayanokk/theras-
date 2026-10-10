"""Simulation d'un attaquant qui a accès au fichier SQLite et contourne le système.

⚠️  Ce module SIMULE UNE ATTAQUE, pour le benchmark uniquement.
    - Il écrit directement dans la base en SQL brut, sans passer par SQLiteStore
      ni EvidenceVault : c'est précisément ce qu'un attaquant ferait.
    - Il ne doit JAMAIS être importé par police/ ni console/.
    - Le Store et le Vault restent append-only : aucune méthode de modification
      n'y est ajoutée pour les besoins du bench.

Utilisé par :
    S-FAL-01 : tamper_event         -> verify() doit renvoyer broken_at == seq
    S-APP-02 : tamper_action_params -> la revalidation de L voit un params_hash
                                       différent et bloque (BLOCKED)

La base visée doit être celle du Gateway : variable POLICE_DB_PATH.
Note : set_classification (S-APP-05) n'est PAS ici. L'état du Drive vit en
mémoire dans le processus du Gateway ; il faut passer par l'app en interne
(TestClient) ou par une route d'admin réservée au bench (à voir avec L).
"""

import json
import os
import sqlite3

DEFAULT_DB_PATH = "police.db"


def db_path_from_env() -> str:
    """Chemin de la base du Gateway : POLICE_DB_PATH, sinon police.db."""
    return os.environ.get("POLICE_DB_PATH", DEFAULT_DB_PATH)


def tamper_event(db_path: str, seq: int, new_payload: dict | None = None) -> None:
    """Remplace le payload de la preuve `seq` SANS recalculer son hash.

    Ensuite, EvidenceVault.verify() (ou GET /v1/evidence/verify) doit renvoyer
    {"valid": False, "broken_at": seq}.
    """
    payload = {"tampered": True} if new_payload is None else new_payload
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute("SELECT data FROM events WHERE seq = ?", (seq,)).fetchone()
        if row is None:
            raise ValueError(f"Aucune preuve avec seq={seq}")
        event = json.loads(row[0])
        event["payload"] = payload  # le champ "hash" n'est volontairement pas touché
        conn.execute(
            "UPDATE events SET data = ? WHERE seq = ?",
            (json.dumps(event, ensure_ascii=False), seq),
        )
        conn.commit()
    finally:
        conn.close()


def tamper_action_params(db_path: str, action_id: str, new_parameters: dict) -> None:
    """Remplace request.parameters de l'action, sans toucher au reste.

    Le params_hash enregistré dans l'action et dans l'approbation reste l'ancien :
    à la décision, la revalidation doit détecter l'écart et bloquer.
    """
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            "SELECT data FROM actions WHERE action_id = ?", (action_id,)
        ).fetchone()
        if row is None:
            raise ValueError(f"Aucune action avec action_id={action_id}")
        action = json.loads(row[0])
        if isinstance(action.get("request"), dict):
            action["request"]["parameters"] = new_parameters  # format du Gateway
        else:
            action["params"] = new_parameters  # ancien format à plat
        conn.execute(
            "UPDATE actions SET data = ? WHERE action_id = ?",
            (json.dumps(action, ensure_ascii=False), action_id),
        )
        conn.commit()
    finally:
        conn.close()
