"""Exporte les schemas JSON des contrats dans contracts/schemas/.

Usage :
    python -m contracts.export_schema

Ecrit :
  - action_request.schema.json  (depuis ActionRequest)
  - <action>.params.schema.json pour chaque action de PARAMS_MODELS
    (ex. share_file.params.schema.json)

Les schemas sont indentes de 2 espaces et termines par un retour a la ligne.
"""

from __future__ import annotations

import json
from pathlib import Path

from contracts.models import PARAMS_MODELS, ActionRequest

SCHEMAS_DIR = Path(__file__).parent / "schemas"


def _write_schema(path: Path, schema: dict) -> None:
    path.write_text(
        json.dumps(schema, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def export() -> list[Path]:
    """Genere tous les schemas et renvoie les chemins ecrits."""
    SCHEMAS_DIR.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    action_request_path = SCHEMAS_DIR / "action_request.schema.json"
    _write_schema(action_request_path, ActionRequest.model_json_schema())
    written.append(action_request_path)

    for action, model in PARAMS_MODELS.items():
        params_path = SCHEMAS_DIR / f"{action}.params.schema.json"
        _write_schema(params_path, model.model_json_schema())
        written.append(params_path)

    return written


def main() -> None:
    written = export()
    print(f"{len(written)} schema(s) ecrit(s) dans {SCHEMAS_DIR} :")
    for path in written:
        print(f"  - {path.name}")


if __name__ == "__main__":
    main()
