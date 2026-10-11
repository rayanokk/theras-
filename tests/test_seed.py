"""Tests de conformité du jeu de données à .kiro/steering/contracts.md.

Vérifie les identités (section 1.2), le Drive simulé (section 1.3), le format
des resource_id, la correspondance exacte avec data/docs/, et l'absence de
secrets dans data/.

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
DOCS_DIR = DATA_DIR / "docs"
IDENTITIES_PATH = DATA_DIR / "identities.json"
DRIVE_SEED_PATH = DATA_DIR / "drive_seed.json"

# Regex de validité d'un resource_id (contrat 1.3 / contrat 1).
RESOURCE_ID_RE = re.compile(r"^[a-zA-Z0-9_.-]+$")

# Motifs ressemblant à des clés / secrets.
KEY_PATTERNS = [
    re.compile(r"\bsk-[A-Za-z0-9]{16,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"secret\s*=\s*\S+"),
]

# Table attendue du Drive simulé (section 1.3), figée en dur.
# resource_id -> (classification, trusted, owner, acl triée)
RESEARCH, OPS, ASSISTANT = "agent-research", "agent-ops", "agent-assistant"
ALL_AGENTS = sorted([RESEARCH, OPS, ASSISTANT])
CONF_ACL = sorted([OPS, ASSISTANT])
REST_ACL = [OPS]

EXPECTED_FILES = {
    "Company_Brochure.pdf": ("public", True, "user-claire", ALL_AGENTS),
    "Press_Release_Q3.txt": ("public", True, "user-claire", ALL_AGENTS),
    "Product_Datasheet.pdf": ("public", True, "user-david", ALL_AGENTS),
    "Public_Pricing.csv": ("public", True, "user-david", ALL_AGENTS),
    "uploaded_cv.txt": ("public", False, "user-david", ALL_AGENTS),
    "Team_Roadmap.md": ("internal", True, "user-claire", ALL_AGENTS),
    "Meeting_Notes_0910.txt": ("internal", True, "user-claire", ALL_AGENTS),
    "Onboarding_Guide.pdf": ("internal", True, "user-david", ALL_AGENTS),
    "vendor_notes.txt": ("internal", False, "user-claire", ALL_AGENTS),
    "partner_invoice.pdf": ("internal", False, "user-david", ALL_AGENTS),
    "Confidential_Audit_Report.pdf": ("confidential", True, "user-claire", CONF_ACL),
    "Q3_Financials.xlsx": ("confidential", True, "user-claire", CONF_ACL),
    "Customer_List.csv": ("confidential", True, "user-david", CONF_ACL),
    "HR_Salaries.xlsx": ("restricted", True, "user-david", REST_ACL),
    "Security_Keys_Inventory.txt": ("restricted", True, "user-claire", REST_ACL),
}

GHOST_FILE = "Ghost_File.pdf"


def _load_json(path: Path):
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def identities():
    return _load_json(IDENTITIES_PATH)["identities"]


@pytest.fixture(scope="module")
def identity_ids(identities):
    return {ident["id"] for ident in identities}


@pytest.fixture(scope="module")
def _drive():
    return _load_json(DRIVE_SEED_PATH)["files"]


def test_identities_fields_match_type(identities):
    """Chaque identité porte les champs attendus selon son type (section 1.2)."""
    for ident in identities:
        itype = ident["type"]
        if itype == "agent":
            assert "key_env" in ident, f"{ident['id']} (agent) doit avoir key_env"
            assert "allowed" in ident, f"{ident['id']} (agent) doit avoir allowed"
        elif itype == "approver":
            assert "key_env" in ident, f"{ident['id']} (approver) doit avoir key_env"
            assert "allowed" not in ident, f"{ident['id']} (approver) ne doit pas avoir allowed"
        elif itype == "user":
            assert "key_env" not in ident, f"{ident['id']} (user) ne doit pas avoir key_env"
            assert "allowed" not in ident, f"{ident['id']} (user) ne doit pas avoir allowed"
        else:
            pytest.fail(f"Type d'identité inconnu pour {ident['id']} : {itype}")


def _allowed_by_id(identities):
    return {
        ident["id"]: ident.get("allowed", {})
        for ident in identities
        if ident["type"] == "agent"
    }


def test_demo_drive_rights_match_existing_rights(identities):
    """Chaque agent a sur demo_drive les mêmes droits (actions canoniques) que
    ceux qu'il possède déjà via google_drive / mail. Aucun droit en plus."""
    allowed = _allowed_by_id(identities)
    expected = {
        "agent-research": ["list_files", "read_file"],
        "agent-ops": ["delete_file", "list_files", "read_file", "share_file"],
        "agent-assistant": ["list_files", "read_file", "send_email", "share_file"],
    }
    for agent_id, expected_tools in expected.items():
        demo = allowed[agent_id].get("demo_drive")
        assert demo is not None, f"{agent_id} doit avoir des droits sur demo_drive"
        assert sorted(demo) == expected_tools, (
            f"{agent_id} : droits demo_drive {sorted(demo)}, attendu {expected_tools}"
        )


def test_agent_research_denied_sensitive_demo_drive_tools(identities):
    """agent-research n'a NI share_file, NI delete_file, NI send_email sur demo_drive."""
    allowed = _allowed_by_id(identities)
    demo = allowed["agent-research"].get("demo_drive", [])
    for forbidden in ("share_file", "delete_file", "send_email"):
        assert forbidden not in demo, (
            f"agent-research ne doit pas avoir '{forbidden}' sur demo_drive"
        )


def test_seed_matches_expected_table(_drive):
    """Le seed contient exactement les 15 resource_id attendus, avec les bons attributs."""
    actual = {
        f["resource_id"]: (
            f["classification"],
            f["trusted"],
            f["owner"],
            sorted(f["acl"]),
        )
        for f in _drive
    }
    assert set(actual) == set(EXPECTED_FILES), (
        f"resource_id en trop : {set(actual) - set(EXPECTED_FILES)} ; "
        f"manquants : {set(EXPECTED_FILES) - set(actual)}"
    )
    for rid, expected in EXPECTED_FILES.items():
        assert actual[rid] == expected, (
            f"'{rid}' attendu {expected}, obtenu {actual[rid]}"
        )


def test_resource_ids_match_regex(_drive):
    """Chaque resource_id respecte la regex ^[a-zA-Z0-9_.-]+$."""
    for f in _drive:
        rid = f["resource_id"]
        assert RESOURCE_ID_RE.match(rid), f"resource_id invalide : {rid!r}"


def test_docs_dir_matches_resource_ids_exact_case(_drive):
    """Les fichiers de data/docs/ correspondent exactement (casse comprise) aux resource_id."""
    import os

    on_disk = set(os.listdir(DOCS_DIR))
    seed_ids = {f["resource_id"] for f in _drive}
    assert on_disk == seed_ids, (
        f"en trop sur disque : {on_disk - seed_ids} ; "
        f"manquants sur disque : {seed_ids - on_disk}"
    )


def test_ghost_file_absent_from_seed_and_disk(_drive):
    """Ghost_File.pdf n'existe ni dans le seed ni sur disque."""
    seed_ids = {f["resource_id"] for f in _drive}
    assert GHOST_FILE not in seed_ids, f"{GHOST_FILE} ne doit pas figurer dans le seed"
    assert not (DOCS_DIR / GHOST_FILE).exists(), f"{GHOST_FILE} ne doit pas exister sur disque"


def test_acl_agents_and_owners_exist(_drive, identity_ids):
    """Chaque agent d'une ACL et chaque owner existent dans identities.json."""
    for f in _drive:
        for agent in f["acl"]:
            assert agent in identity_ids, (
                f"ACL de '{f['resource_id']}' référence une identité inconnue : {agent}"
            )
        assert f["owner"] in identity_ids, (
            f"owner de '{f['resource_id']}' inconnu : {f['owner']}"
        )


def test_no_key_like_strings_in_data():
    """Aucun fichier sous data/ ne contient de chaîne ressemblant à une clé."""
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
