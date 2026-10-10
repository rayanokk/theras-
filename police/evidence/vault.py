"""Contrat 4 : Evidence Vault, journal d'événements chaîné par hash.

Append-only : aucune méthode de modification ou de suppression. Chaque
événement est lié au précédent par `prev_hash`, et son `hash` couvre tout
l'événement (sauf le champ `hash` lui-même). Toute altération ou tout trou
dans la chaîne est détecté par `verify()`.

Le hash canonique vient de `contracts/models.py` (contrat 7) : une seule
implémentation pour tout le projet, jamais réécrite ici.
"""

import hashlib
import json
import threading
from datetime import datetime, timezone

from contracts.models import Event, canonical_json
from police.store.base import Store

GENESIS_PREV_HASH = "0" * 64


def _event_hash(event_without_hash: dict) -> str:
    """sha256(prev_hash + canonical_json(événement sans le champ hash))."""
    prev_hash = event_without_hash["prev_hash"]
    material = prev_hash + canonical_json(event_without_hash)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class EvidenceVault:
    """Journal d'événements append-only, chaîné par hash, adossé à un Store."""

    def __init__(self, store: Store) -> None:
        self._store = store
        self._lock = threading.Lock()

    def record(
        self, type: str, action_id: str, payload: dict, policy_version: str
    ) -> Event:
        """Ajoute un événement chaîné et renvoie un Event. seq et prev_hash sont
        calculés sous verrou pour éviter deux appels concurrents sur le même numéro.
        Le Store reçoit un dict (model_dump()) ; la méthode renvoie l'Event typé."""
        with self._lock:
            events = self._store.list_events()
            if events:
                last = events[-1]
                seq = last["seq"] + 1
                prev_hash = last["hash"]
            else:
                seq = 1
                prev_hash = GENESIS_PREV_HASH

            event = {
                "seq": seq,
                "ts": datetime.now(timezone.utc).isoformat(),
                "type": type,
                "action_id": action_id,
                "payload": payload,
                "policy_version": policy_version,
                "prev_hash": prev_hash,
            }
            event["hash"] = _event_hash(event)

            # Le Store reçoit un dict ; on repasse par Event pour typer et
            # garantir une forme stable (mode="json" sérialise l'enum en str,
            # ce qui correspond exactement à ce qui a été haché).
            event_obj = Event.model_validate(event)
            self._store.append_event(event_obj.model_dump(mode="json"))
            return event_obj

    def verify(self) -> dict:
        """Relit la chaîne et vérifie seq contigus (à partir de 1), prev_hash
        chaîné et hash recalculé. Une chaîne vide est valide."""
        events = self._store.list_events()
        expected_prev = GENESIS_PREV_HASH
        for index, event in enumerate(events):
            # broken_at = le premier numéro attendu qui n'est pas valide.
            expected_seq = index + 1
            # seq contigus à partir de 1 (pas de trou).
            if event["seq"] != expected_seq:
                return {"valid": False, "broken_at": expected_seq}
            # prev_hash chaîné sur le hash précédent.
            if event["prev_hash"] != expected_prev:
                return {"valid": False, "broken_at": expected_seq}
            # hash recalculé == hash stocké.
            without_hash = {k: v for k, v in event.items() if k != "hash"}
            if _event_hash(without_hash) != event.get("hash"):
                return {"valid": False, "broken_at": expected_seq}
            expected_prev = event["hash"]
        return {"valid": True, "broken_at": None}

    def export_jsonl(self) -> str:
        """Export SIEM : un événement JSON par ligne, dans l'ordre des seq."""
        events = self._store.list_events()
        return "\n".join(json.dumps(event, ensure_ascii=False) for event in events)
