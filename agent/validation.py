"""Validation d'un ActionRequest contre le schéma de L (contracts/schemas/).

But : repérer côté agent un ActionRequest malformé AVANT de l'envoyer au Gateway.
Ce n'est pas un contrôle de sécurité (c'est le rôle du Gateway), juste un garde-fou
de développement et une preuve qu'agent et Gateway partagent le même contrat.

Dégradé propre : si le schéma est absent (repo pas encore mergé) ou jsonschema non
installé, on n'empêche rien, on prévient.
"""
import json
import os

try:
    from jsonschema import Draft202012Validator
    _HAS_JSONSCHEMA = True
except ImportError:
    _HAS_JSONSCHEMA = False

SCHEMA_DIR = os.getenv("SCHEMA_DIR", "contracts/schemas")
_ENVELOPE_NAMES = ["action_request.schema.json", "ActionRequest.json", "action_request.json"]

_validator = None  # chargé une seule fois


def _load_validator():
    global _validator
    if _validator is not None or not _HAS_JSONSCHEMA:
        return _validator
    for name in _ENVELOPE_NAMES:
        path = os.path.join(SCHEMA_DIR, name)
        if os.path.isfile(path):
            schema = json.load(open(path, encoding="utf-8"))
            _validator = Draft202012Validator(schema)
            return _validator
    return None


def validate_action_request(req):
    """Renvoie une liste de messages d'erreur (vide = conforme, ou validation indisponible)."""
    v = _load_validator()
    if v is None:
        return []  # pas de schéma ou pas de lib : on ne bloque pas
    return [f"{'/'.join(map(str, e.path)) or '(racine)'} : {e.message}" for e in v.iter_errors(req)]
