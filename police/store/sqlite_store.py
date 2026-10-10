# TODO: remplacer dict par les modèles de contracts/models.py quand ils existeront.
"""Implémentation SQLite du contrat `Store` (module standard sqlite3).

Chaque entité est stockée avec ses colonnes de recherche (clé primaire,
statut ou action_id) et son dict complet sérialisé en JSON dans la colonne
`data`. Le journal d'événements est append-only : aucune méthode de
modification ou de suppression n'est exposée, et un `seq` en double lève
une erreur plutôt que d'écraser.
"""

import json
import sqlite3
import threading

from police.store.base import Store


def _dumps(obj: dict) -> str:
    """Sérialise un dict en JSON stable (ensure_ascii=False)."""
    return json.dumps(obj, ensure_ascii=False)


class SQLiteStore(Store):
    """Stockage SQLite des actions, approbations, événements et sessions."""

    def __init__(self, db_path: str = "police.db") -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self) -> None:
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS actions (
                    action_id TEXT PRIMARY KEY,
                    status    TEXT,
                    data      TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS approvals (
                    approval_id TEXT PRIMARY KEY,
                    status      TEXT,
                    data        TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events (
                    seq       INTEGER PRIMARY KEY,
                    action_id TEXT,
                    data      TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    data       TEXT NOT NULL
                );
                """
            )
            self._conn.commit()

    def close(self) -> None:
        """Ferme la connexion sous-jacente."""
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------ actions

    def put_action(self, action: dict) -> None:
        """Crée ou remplace (upsert) une action. Champs : action_id, agent_id, user_id, session_id, tool, action, resource_id, params, params_hash, verdict, status, rule_ids, risk, created_at."""
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO actions (action_id, status, data)
                VALUES (?, ?, ?)
                ON CONFLICT(action_id) DO UPDATE SET
                    status = excluded.status,
                    data   = excluded.data
                """,
                (action["action_id"], action.get("status"), _dumps(action)),
            )
            self._conn.commit()

    def get_action(self, action_id: str) -> dict | None:
        """Retourne l'action d'identifiant action_id, ou None si absente."""
        row = self._conn.execute(
            "SELECT data FROM actions WHERE action_id = ?", (action_id,)
        ).fetchone()
        return json.loads(row["data"]) if row is not None else None

    def list_actions(self, status: str | None = None) -> list[dict]:
        """Liste les actions, filtrées par status si fourni."""
        if status is None:
            rows = self._conn.execute("SELECT data FROM actions").fetchall()
        else:
            rows = self._conn.execute(
                "SELECT data FROM actions WHERE status = ?", (status,)
            ).fetchall()
        return [json.loads(row["data"]) for row in rows]

    # --------------------------------------------------------------- approvals

    def put_approval(self, approval: dict) -> None:
        """Crée ou remplace (upsert) une approbation. Champs : approval_id, action_id, params_hash, status, expires_at, approver_id, decision, justification, decided_at."""
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO approvals (approval_id, status, data)
                VALUES (?, ?, ?)
                ON CONFLICT(approval_id) DO UPDATE SET
                    status = excluded.status,
                    data   = excluded.data
                """,
                (approval["approval_id"], approval.get("status"), _dumps(approval)),
            )
            self._conn.commit()

    def get_approval(self, approval_id: str) -> dict | None:
        """Retourne l'approbation d'identifiant approval_id, ou None si absente."""
        row = self._conn.execute(
            "SELECT data FROM approvals WHERE approval_id = ?", (approval_id,)
        ).fetchone()
        return json.loads(row["data"]) if row is not None else None

    def list_approvals(self, status: str | None = None) -> list[dict]:
        """Liste les approbations, filtrées par status si fourni."""
        if status is None:
            rows = self._conn.execute("SELECT data FROM approvals").fetchall()
        else:
            rows = self._conn.execute(
                "SELECT data FROM approvals WHERE status = ?", (status,)
            ).fetchall()
        return [json.loads(row["data"]) for row in rows]

    # ----------------------------------------------------------------- events

    def append_event(self, event: dict) -> None:
        """Ajoute un événement au journal append-only. Champs : seq, ts, type, action_id, payload, policy_version, prev_hash, hash. Un seq déjà présent lève sqlite3.IntegrityError."""
        with self._lock:
            self._conn.execute(
                "INSERT INTO events (seq, action_id, data) VALUES (?, ?, ?)",
                (event["seq"], event.get("action_id"), _dumps(event)),
            )
            self._conn.commit()

    def list_events(self, action_id: str | None = None) -> list[dict]:
        """Liste les événements triés par seq croissant, filtrés par action_id si fourni."""
        if action_id is None:
            rows = self._conn.execute(
                "SELECT data FROM events ORDER BY seq ASC"
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT data FROM events WHERE action_id = ? ORDER BY seq ASC",
                (action_id,),
            ).fetchall()
        return [json.loads(row["data"]) for row in rows]

    # ---------------------------------------------------------------- sessions

    def get_session(self, session_id: str) -> dict | None:
        """Retourne la session d'identifiant session_id, ou None. Champs : session_id, tainted, taint_sources."""
        row = self._conn.execute(
            "SELECT data FROM sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
        return json.loads(row["data"]) if row is not None else None

    def set_session(self, session: dict) -> None:
        """Crée ou met à jour une session. Champs : session_id, tainted, taint_sources."""
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO sessions (session_id, data)
                VALUES (?, ?)
                ON CONFLICT(session_id) DO UPDATE SET
                    data = excluded.data
                """,
                (session["session_id"], _dumps(session)),
            )
            self._conn.commit()
