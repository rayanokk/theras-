"""Tests de cohérence du jeu de données de gouvernance d'agents.

Charge data/identities.json et data/drive_seed.json puis vérifie l'intégrité
des ACL, des classifications, des chemins de contenu et l'absence de secrets.

Tous les chemins sont résolus par rapport à la racine du repo, afin que la
suite fonctionne quel que soit le répertoire courant.
"""

import json
import re
from pathlib import Path

import pytest

# Racine du repo = parent du dossier tests/ (ce fichier est tests/test_seed.py).
REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = REPO_ROOT / "data"
IDENTITIES_PATH = DATA_DIR / "identities.json"
DRIVE_SEED_PATH = DATA_DIR / "drive_seed.json"

# Motifs ressemblant à des clés / secrets.
KEY_PATTERNS = [
    re.compile(r"\bsk-[A-Za-z0-9]{16,}"),   # clé type OpenAI/Anthropic
    re.compile(r"AKIA[0-9A-Z]{16}"),        # clé d'accès AWS
    re.compile(r"secret\s*=\s*\S+"),        # secret=valeur
]


def _load_json(path: Path):
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def identities():
    return _load_json(IDENTITIES_PATH)


@pytest.fixture(scope="module")
def drive_seed():
    return _load_json(DRIVE_SEED_PATH)


@pytest.fixture(scope="module")
def agent_ids(identities):
    return {agent["id"] for agent in identities["agents"]}


@pytest.fixture(scope="module")
def files(drive_seed):
    return drive_seed["files"]


def test_acl_agents_exist_in_identities(files, agent_ids):
    """Chaque agent cité dans une ACL doit exister dans identities.json."""
    for file in files:
        for agent in file["acl"]:
            assert agent in agent_ids, (
                f"ACL du fichier '{file['id']}' référence un agent inconnu : {agent}"
            )


def test_content_files_exist_on_disk(files):
    """Chaque content_file doit pointer vers un fichier présent sur le disque."""
    for file in files:
        content_path = REPO_ROOT / file["content_file"]
        assert content_path.is_file(), (
            f"content_file manquant pour '{file['id']}' : {content_path}"
        )


def test_classification_counts(files):
    """Répartition attendue : 5 public, 5 internal, 3 confidential, 2 restricted."""
    counts = {}
    for file in files:
        counts[file["classification"]] = counts.get(file["classification"], 0) + 1

    assert counts.get("public") == 5, f"public attendu 5, obtenu {counts.get('public')}"
    assert counts.get("internal") == 5, f"internal attendu 5, obtenu {counts.get('internal')}"
    assert counts.get("confidential") == 3, f"confidential attendu 3, obtenu {counts.get('confidential')}"
    assert counts.get("restricted") == 2, f"restricted attendu 2, obtenu {counts.get('restricted')}"


def test_untrusted_file_count(files):
    """Il doit y avoir exactement 3 fichiers trusted: false."""
    untrusted = [file["id"] for file in files if file["trusted"] is False]
    assert len(untrusted) == 3, f"3 fichiers non fiables attendus, obtenu {untrusted}"


def test_research_agent_absent_from_restricted_acls(files):
    """research-agent-01 ne doit figurer dans aucune ACL de fichier restricted."""
    for file in files:
        if file["classification"] == "restricted":
            assert "research-agent-01" not in file["acl"], (
                f"research-agent-01 ne doit pas être dans l'ACL du fichier restricted '{file['id']}'"
            )


def test_file_ids_are_unique(files):
    """Les ids de fichiers doivent être uniques."""
    ids = [file["id"] for file in files]
    duplicates = {fid for fid in ids if ids.count(fid) > 1}
    assert not duplicates, f"ids de fichiers dupliqués : {duplicates}"


def test_no_key_like_strings_in_data():
    """Aucun fichier sous data/ ne doit contenir de chaîne ressemblant à une clé."""
    offenders = []
    for path in DATA_DIR.rglob("*"):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for pattern in KEY_PATTERNS:
            if pattern.search(text):
                rel = path.relative_to(REPO_ROOT)
                offenders.append(f"{rel} (motif: {pattern.pattern})")
    assert not offenders, "Chaîne(s) ressemblant à une clé détectée(s) : " + ", ".join(offenders)
