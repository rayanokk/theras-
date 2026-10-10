"""Tests du moteur de politique (police/policy/engine.py, pas encore ecrit).

Le moteur lit policies/policies.yaml et evalue un dict de faits selon l'ordre
DENY -> REVIEW -> ALLOW -> DENY par defaut -> durcisseurs (contrat, partie 3).

API attendue :
    policy = load_policy(path)                 -> objet Policy
    verdict, rule_ids, reasons = evaluate(facts, policy)
        verdict  : "ALLOW" | "REVIEW" | "DENY"
        rule_ids : list[str]  (toutes les regles vraies retenues)
        reasons  : list[str]  (une phrase par regle retenue)
    recipient_facts(domain, policy) -> dict
        {recipient_internal, recipient_partner, recipient_blocked}

base_facts() decrit une lecture normale et valide. Chaque test part de ces faits
et ne modifie que le strict necessaire pour declencher une regle.
"""

from pathlib import Path

import pytest

from police.policy.engine import evaluate, load_policy, recipient_facts

POLICIES_PATH = (
    Path(__file__).resolve().parents[1] / "policies" / "policies.yaml"
)


@pytest.fixture(scope="module")
def policy():
    return load_policy(POLICIES_PATH)


def base_facts() -> dict:
    """Faits d'une lecture normale et valide : attendue ALLOW via R-ALLOW-01."""
    return {
        "identity_ok": True,
        "action_allowed": True,
        "resource_ok": True,
        "params_valid": True,
        "action": "read_file",
        "classification": "internal",
        "has_recipient": False,
        "recipient_internal": False,
        "recipient_partner": False,
        "recipient_blocked": False,
        "sensitive": False,
        "session_tainted": False,
        "risk_unavailable": False,
    }


def _share(facts: dict, classification: str, **recipient) -> dict:
    """Prepare un share_file sensible avec un destinataire."""
    facts.update(
        action="share_file",
        classification=classification,
        has_recipient=True,
        sensitive=True,
    )
    facts.update(recipient)
    return facts


# --- 1. DENY ------------------------------------------------------------------


def test_r_deny_01_identity(policy):
    facts = base_facts()
    facts["identity_ok"] = False
    verdict, rule_ids, _ = evaluate(facts, policy)
    assert verdict == "DENY"
    assert "R-DENY-01" in rule_ids


def test_r_deny_02_action_not_allowed(policy):
    facts = base_facts()
    facts["action_allowed"] = False
    verdict, rule_ids, _ = evaluate(facts, policy)
    assert verdict == "DENY"
    assert "R-DENY-02" in rule_ids


def test_r_deny_03_resource(policy):
    facts = base_facts()
    facts["resource_ok"] = False
    verdict, rule_ids, _ = evaluate(facts, policy)
    assert verdict == "DENY"
    assert "R-DENY-03" in rule_ids


def test_r_deny_04_restricted_external(policy):
    facts = _share(base_facts(), "restricted", recipient_internal=False)
    verdict, rule_ids, _ = evaluate(facts, policy)
    assert verdict == "DENY"
    assert "R-DENY-04" in rule_ids


def test_r_deny_05_blocked_domain(policy):
    facts = _share(base_facts(), "public", recipient_blocked=True)
    verdict, rule_ids, _ = evaluate(facts, policy)
    assert verdict == "DENY"
    assert "R-DENY-05" in rule_ids


def test_r_deny_06_invalid_params(policy):
    facts = base_facts()
    facts["params_valid"] = False
    verdict, rule_ids, _ = evaluate(facts, policy)
    assert verdict == "DENY"
    assert "R-DENY-06" in rule_ids


# --- 2. REVIEW ----------------------------------------------------------------


def test_r_rev_01_confidential_external(policy):
    facts = _share(base_facts(), "confidential", recipient_internal=False)
    verdict, rule_ids, _ = evaluate(facts, policy)
    assert verdict == "REVIEW"
    assert "R-REV-01" in rule_ids


def test_r_rev_03_delete(policy):
    facts = base_facts()
    facts.update(action="delete_file", sensitive=True)
    verdict, rule_ids, _ = evaluate(facts, policy)
    assert verdict == "REVIEW"
    assert "R-REV-03" in rule_ids


def test_r_rev_05_confidential_internal(policy):
    facts = _share(base_facts(), "confidential", recipient_internal=True)
    verdict, rule_ids, _ = evaluate(facts, policy)
    assert verdict == "REVIEW"
    assert "R-REV-05" in rule_ids


# --- 3. ALLOW -----------------------------------------------------------------


def test_r_allow_01_read(policy):
    verdict, rule_ids, _ = evaluate(base_facts(), policy)
    assert verdict == "ALLOW"
    assert "R-ALLOW-01" in rule_ids


def test_r_allow_02_public_to_partner(policy):
    facts = _share(base_facts(), "public", recipient_partner=True)
    verdict, rule_ids, _ = evaluate(facts, policy)
    assert verdict == "ALLOW"
    assert "R-ALLOW-02" in rule_ids


def test_r_allow_03_internal_mail(policy):
    facts = base_facts()
    facts.update(
        action="send_email",
        classification="internal",
        has_recipient=True,
        recipient_internal=True,
        sensitive=True,
    )
    verdict, rule_ids, _ = evaluate(facts, policy)
    assert verdict == "ALLOW"
    assert "R-ALLOW-03" in rule_ids


def test_r_allow_04_internal_share(policy):
    facts = _share(base_facts(), "internal", recipient_internal=True)
    verdict, rule_ids, _ = evaluate(facts, policy)
    assert verdict == "ALLOW"
    assert "R-ALLOW-04" in rule_ids


# --- 4. HARDEN ----------------------------------------------------------------


def test_r_rev_02_tainted_sensitive(policy):
    # Partage public en interne : ALLOW (R-ALLOW-04) durci en REVIEW par R-REV-02.
    facts = _share(base_facts(), "public", recipient_internal=True)
    facts["session_tainted"] = True
    verdict, rule_ids, _ = evaluate(facts, policy)
    assert verdict == "REVIEW"
    assert "R-REV-02" in rule_ids


def test_r_rev_02_agent_tainted_sensitive(policy):
    # Agent contamine (session saine) : R-REV-02 se declenche aussi via agent_tainted.
    facts = _share(base_facts(), "public", recipient_internal=True)
    facts["session_tainted"] = False
    facts["agent_tainted"] = True
    verdict, rule_ids, _ = evaluate(facts, policy)
    assert verdict == "REVIEW"
    assert "R-REV-02" in rule_ids


def test_r_rev_02_any_of_requires_sensitive_too(policy):
    # any_of combine a sensitive: agent contamine mais action NON sensible
    # (read_file) -> R-REV-02 ne se declenche pas (la condition sensible echoue).
    facts = base_facts()  # read_file, non sensible
    facts["agent_tainted"] = True
    verdict, rule_ids, _ = evaluate(facts, policy)
    assert "R-REV-02" not in rule_ids
    # Et sans aucun taint ni risque, une lecture reste ALLOW.
    assert verdict == "ALLOW"


def test_r_rev_04_risk_unavailable_sensitive(policy):
    # LLM indisponible sur action sensible : ALLOW durci en REVIEW.
    facts = _share(base_facts(), "public", recipient_internal=True)
    facts["risk_unavailable"] = True
    verdict, rule_ids, _ = evaluate(facts, policy)
    assert verdict == "REVIEW"
    assert "R-REV-04" in rule_ids


# --- Regles transverses -------------------------------------------------------


def test_default_deny_when_no_rule_matches(policy):
    # share_file public vers l'externe : aucune ALLOW ne s'applique.
    facts = _share(
        base_facts(),
        "public",
        recipient_internal=False,
        recipient_partner=False,
    )
    verdict, rule_ids, _ = evaluate(facts, policy)
    assert verdict == "DENY"
    assert rule_ids == ["R-DENY-DEFAULT"]


def test_default_deny_returns_explicit_id_and_reason(policy):
    # share_file d'un fichier internal vers external.example : identite et
    # ressource OK, mais aucune ALLOW ne couvre ce cas -> refus par defaut
    # explicite (verdict, rule_ids et reasons precis).
    facts = _share(
        base_facts(),
        "internal",
        recipient_internal=False,
        recipient_partner=False,
    )
    verdict, rule_ids, reasons = evaluate(facts, policy)
    assert verdict == "DENY"
    assert rule_ids == ["R-DENY-DEFAULT"]
    assert reasons == [
        "Aucune règle n'autorise explicitement cette action (refus par défaut)"
    ]


def test_deny_wins_over_review(policy):
    # delete_file (R-REV-03) mais ressource KO (R-DENY-03) : les deux conditions
    # sont vraies, mais le verdict final est DENY.
    facts = base_facts()
    facts.update(action="delete_file", sensitive=True, resource_ok=False)
    verdict, rule_ids, _ = evaluate(facts, policy)
    assert verdict == "DENY"
    assert "R-DENY-03" in rule_ids


def test_harden_never_turns_deny_into_review(policy):
    # restricted vers l'externe (R-DENY-04) + session tainted sensible :
    # le durcisseur R-REV-02 ne doit PAS requalifier le DENY en REVIEW.
    facts = _share(base_facts(), "restricted", recipient_internal=False)
    facts["session_tainted"] = True
    verdict, rule_ids, _ = evaluate(facts, policy)
    assert verdict == "DENY"
    assert "R-DENY-04" in rule_ids
    assert "R-REV-02" not in rule_ids


def test_harden_adds_reason_to_existing_review(policy):
    # confidential en interne (R-REV-05) + session tainted : reste REVIEW,
    # mais R-REV-02 s'ajoute aux regles retenues.
    facts = _share(base_facts(), "confidential", recipient_internal=True)
    facts["session_tainted"] = True
    verdict, rule_ids, _ = evaluate(facts, policy)
    assert verdict == "REVIEW"
    assert "R-REV-05" in rule_ids
    assert "R-REV-02" in rule_ids


def test_missing_fact_makes_condition_false_without_error(policy):
    # Aucun fait de recipient/classification fourni : R-ALLOW-01 ne matche pas
    # (action share_file), aucune autre regle non plus -> DENY par defaut,
    # et surtout aucune exception levee.
    facts = {
        "identity_ok": True,
        "action_allowed": True,
        "resource_ok": True,
        "params_valid": True,
        "action": "share_file",
    }
    verdict, rule_ids, _ = evaluate(facts, policy)
    assert verdict == "DENY"
    assert rule_ids == ["R-DENY-DEFAULT"]


# --- Demo phare ---------------------------------------------------------------


def test_flagship_demo_confidential_external_tainted(policy):
    # Partage de Confidential_Audit_Report.pdf vers audit@external.example,
    # session contaminee par vendor_notes.txt : REVIEW, avec R-REV-01 et R-REV-02.
    facts = _share(base_facts(), "confidential", recipient_internal=False)
    facts["session_tainted"] = True
    verdict, rule_ids, _ = evaluate(facts, policy)
    assert verdict == "REVIEW"
    assert "R-REV-01" in rule_ids
    assert "R-REV-02" in rule_ids


# --- recipient_facts ----------------------------------------------------------


def test_recipient_facts_internal_domain(policy):
    facts = recipient_facts("acme.example", policy)
    assert facts["recipient_internal"] is True
    assert facts["recipient_blocked"] is False


def test_recipient_facts_blocked_domain(policy):
    facts = recipient_facts("pastebin.example", policy)
    assert facts["recipient_blocked"] is True
    assert facts["recipient_internal"] is False
