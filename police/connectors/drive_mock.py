"""Connecteur Google Drive simulé (contrat 3).

Charge `data/drive_seed.json` en mémoire au démarrage. `describe` renvoie des
faits sans jamais modifier l'état ; `execute` applique l'action sur l'état en
mémoire uniquement (jamais sur le disque) et ne vérifie aucune permission —
c'est le rôle du pipeline.
"""

import json
from pathlib import Path

from police.connectors.base import ResourceInfo

# Racine du repo : police/connectors/drive_mock.py -> remonter de 3 niveaux.
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = REPO_ROOT / "data"
SEED_PATH = DATA_DIR / "drive_seed.json"
IDENTITIES_PATH = DATA_DIR / "identities.json"


def _extract_domain(email: str | None) -> str | None:
    """Renvoie la partie après @ en minuscules, ou None si absente/invalide."""
    if not isinstance(email, str):
        return None
    parts = email.split("@")
    if len(parts) != 2:
        return None
    local, domain = parts
    if not local or not domain:
        return None
    return domain.lower()


class DriveMock:
    """Drive simulé : chaque fichier est un dict issu de drive_seed.json."""

    name = "google_drive"

    def __init__(
        self,
        seed_path: str | Path = SEED_PATH,
        identities_path: str | Path = IDENTITIES_PATH,
    ) -> None:
        with open(seed_path, encoding="utf-8") as fh:
            seed = json.load(fh)
        # État en mémoire : resource_id -> fiche fichier (copie).
        self._files: dict[str, dict] = {
            f["resource_id"]: dict(f) for f in seed["files"]
        }
        # Partages simulés : resource_id -> liste de (recipient, role).
        self._shares: dict[str, list[dict]] = {}
        # Les agents sont les identités de type "agent" de identities.json.
        with open(identities_path, encoding="utf-8") as fh:
            identities = json.load(fh)["identities"]
        self._agents = sorted(
            ident["id"] for ident in identities if ident.get("type") == "agent"
        )

    # ------------------------------------------------------------------ lecture

    @property
    def agents(self) -> list[str]:
        """Liste des identités de type agent (depuis identities.json)."""
        return list(self._agents)

    def get_file(self, resource_id: str) -> dict | None:
        """Renvoie la fiche du fichier (copie), ou None s'il est inconnu."""
        f = self._files.get(resource_id)
        return dict(f) if f is not None else None

    # ----------------------------------------------------------------- describe

    def describe(self, action: str, resource_id: str, params: dict) -> ResourceInfo:
        """Renvoie un ResourceInfo. Ne modifie jamais l'état."""
        recipient_email = None
        recipient_domain = None
        if action == "share_file":
            recipient_email = params.get("recipient")
            recipient_domain = _extract_domain(recipient_email)

        # Cas root pour list_files.
        if action == "list_files" and resource_id == "root":
            return ResourceInfo(
                exists=True,
                classification="none",
                owner=None,
                acl=list(self._agents),
                trusted=True,
                recipient_email=recipient_email,
                recipient_domain=recipient_domain,
            )

        f = self._files.get(resource_id)
        if f is None:
            # Fichier inconnu.
            return ResourceInfo(
                exists=False,
                classification="none",
                owner=None,
                acl=[],
                trusted=False,
                recipient_email=recipient_email,
                recipient_domain=recipient_domain,
            )

        return ResourceInfo(
            exists=True,
            classification=f["classification"],
            owner=f.get("owner"),
            acl=list(f.get("acl", [])),
            trusted=f.get("trusted", False),
            recipient_email=recipient_email,
            recipient_domain=recipient_domain,
        )

    # ------------------------------------------------------------------ execute

    def execute(self, action: str, resource_id: str, params: dict) -> dict:
        """Exécute l'action sur l'état en mémoire. Ne vérifie aucune permission."""
        if action == "read_file":
            f = self._files[resource_id]
            content_path = DATA_DIR / f["content_path"]
            content = content_path.read_text(encoding="utf-8")
            return {"content": content, "trusted": f.get("trusted", False)}

        if action == "list_files":
            return {"files": list(self._files.keys())}

        if action == "share_file":
            recipient = params["recipient"]
            role = params.get("role")
            self._shares.setdefault(resource_id, []).append(
                {"recipient": recipient, "role": role}
            )
            return {"shared_with": recipient, "role": role}

        if action == "delete_file":
            self._files.pop(resource_id, None)
            self._shares.pop(resource_id, None)
            return {"deleted": True}

        raise ValueError(f"Action inconnue pour google_drive : {action}")

    # --------------------------------------------------------------- admin sim

    def set_classification(self, resource_id: str, classification: str) -> None:
        """Simule un administrateur qui reclasse un fichier (scénario S-APP-05)."""
        if resource_id in self._files:
            self._files[resource_id]["classification"] = classification
