"""Orchestration d'un benchmark « Forge » : génération, vérification oracle, rejeu.

Toute la logique vit ici, SANS Streamlit, pour être testable avec un faux
``subprocess.run`` (aucun vrai sous-processus dans les tests).

On appelle uniquement en sous-processus, et jamais avec ``shell=True`` :
  1. génération : ``python -m datagen.cli build --count N --out <fichier> [--no-llm]``
  2. vérification oracle : ``python -m datagen.cli verify --dataset <fichier>``
     (seulement si la CLI accepte ``--dataset`` ; sinon on saute en l'annonçant)
  3. rejeu : ``python -m bench.run_bench --dataset <fichier> --mode no-llm``
     puis copie de ``bench/results/results_no-llm.json`` (sortie figée de
     run_bench) vers ``bench/results/results_forge_<horodatage>.json``.

On n'écrit JAMAIS dans ``datagen/cache/`` : chaque run a son propre dossier
``bench/results/forge_<horodatage>/`` (dataset + documents).

Règles d'environnement des sous-processus : ``RISK_LLM_ENABLED=false`` et on
retire ``APPROVAL_TTL_SECONDS`` s'il est défini. On ne logue jamais de secret.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

# Bornes du nombre de scénarios (bornées CÔTÉ CODE, pas seulement dans l'UI).
N_MIN = 5
N_MAX = 100
N_DEFAULT = 20

# Timeout global de la chaîne (secondes).
TOTAL_TIMEOUT_S = 300

# Emplacements (relatifs à la racine du repo = cwd du processus Streamlit).
RESULTS_DIR = Path("bench/results")
RUN_BENCH_OUTPUT = RESULTS_DIR / "results_no-llm.json"  # sortie figée de run_bench

# Nombre de lignes de stderr conservées pour un message d'erreur.
STDERR_TAIL_LINES = 20


def clamp_n(value) -> int:
    """Borne N dans [N_MIN, N_MAX]. Toute valeur non entière -> N_DEFAULT."""
    try:
        n = int(value)
    except (TypeError, ValueError):
        return N_DEFAULT
    return max(N_MIN, min(N_MAX, n))


def subprocess_env(base_env: dict | None = None) -> dict:
    """Environnement des sous-processus : RISK_LLM_ENABLED=false, sans
    APPROVAL_TTL_SECONDS. Ne copie jamais de secret ajouté par nous."""
    env = dict(os.environ if base_env is None else base_env)
    env["RISK_LLM_ENABLED"] = "false"
    env.pop("APPROVAL_TTL_SECONDS", None)
    # Windows : les sous-processus Forge/bench impriment des emojis ; sans UTF-8
    # forcé, stdout tombe sur cp1252 et lève UnicodeEncodeError. On force l'I/O
    # en UTF-8 pour tous les sous-processus (n'affecte pas le code de A).
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    return env


def timestamp() -> str:
    """Horodatage de run, sûr pour un nom de fichier (UTC)."""
    return time.strftime("%Y%m%d-%H%M%S", time.gmtime())


def tail_stderr(text, limit: int = STDERR_TAIL_LINES) -> str:
    """Les `limit` dernières lignes de stderr, en texte brut (NON échappé ici :
    l'échappement HTML est fait par l'appelant au moment de l'injection)."""
    if not text:
        return ""
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="replace")
    lines = str(text).splitlines()
    return "\n".join(lines[-limit:])


# --- Commandes (listes d'arguments, jamais de chaîne shell) -------------------


def build_cmd(n: int, out_path: Path, use_llm: bool) -> list[str]:
    """Commande de génération. `--no-llm` sauf si le mode LLM est demandé."""
    cmd = [
        sys.executable,
        "-m",
        "datagen.cli",
        "build",
        "--count",
        str(n),
        "--out",
        str(out_path),
    ]
    if not use_llm:
        cmd.append("--no-llm")
    return cmd


def verify_cmd(dataset_path: Path) -> list[str]:
    """Commande de vérification oracle sur un dataset précis."""
    return [sys.executable, "-m", "datagen.cli", "verify", "--dataset", str(dataset_path)]


def verify_help_cmd() -> list[str]:
    return [sys.executable, "-m", "datagen.cli", "verify", "--help"]


def run_bench_cmd(dataset_path: Path) -> list[str]:
    """Commande de rejeu d'un dataset en mode sans LLM."""
    return [
        sys.executable,
        "-m",
        "bench.run_bench",
        "--dataset",
        str(dataset_path),
        "--mode",
        "no-llm",
    ]


def verify_supports_dataset(runner=subprocess.run, env: dict | None = None) -> bool:
    """Détecte si `datagen.cli verify` accepte `--dataset` (lecture de --help)."""
    try:
        proc = runner(
            verify_help_cmd(),
            shell=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            env=env if env is not None else subprocess_env(),
        )
    except Exception:
        return False
    blob = f"{getattr(proc, 'stdout', '') or ''}{getattr(proc, 'stderr', '') or ''}"
    return "--dataset" in blob


# --- Résultat structuré de la chaîne ------------------------------------------


@dataclass
class BenchRunResult:
    ok: bool
    n: int
    use_llm: bool
    timestamp: str
    dataset_path: Path | None = None
    results_path: Path | None = None  # copie results_forge_<ts>.json
    verify_skipped: bool = False      # verify indisponible (pas de --dataset)
    error_step: str | None = None     # "génération" | "vérification" | "rejeu" | "copie"
    error_message: str = ""
    stderr_tail: str = ""
    steps_done: list[str] = field(default_factory=list)


def _mode_label(use_llm: bool) -> str:
    return "LLM" if use_llm else "sans LLM"


def run_new_benchmark(
    n,
    use_llm: bool = False,
    *,
    runner=subprocess.run,
    results_dir: Path | str = RESULTS_DIR,
    env: dict | None = None,
    total_timeout_s: int = TOTAL_TIMEOUT_S,
    on_progress=None,
) -> BenchRunResult:
    """Exécute génération -> (vérification) -> rejeu, en sous-processus.

    `runner` est injectable (tests). `on_progress(step_name)` est appelé avant
    chaque étape si fourni. Renvoie un BenchRunResult ; ne lève jamais pour une
    erreur de sous-processus (timeout inclus) : tout est porté par le résultat.
    """
    n = clamp_n(n)
    ts = timestamp()
    results_dir = Path(results_dir)
    run_dir = results_dir / f"forge_{ts}"
    dataset_path = run_dir / "dataset.json"
    proc_env = env if env is not None else subprocess_env()

    result = BenchRunResult(ok=False, n=n, use_llm=use_llm, timestamp=ts, dataset_path=dataset_path)

    deadline = time.monotonic() + total_timeout_s

    def _remaining() -> float:
        return max(1.0, deadline - time.monotonic())

    def _notify(step: str) -> None:
        if on_progress is not None:
            on_progress(step)

    def _fail(step: str, message: str, stderr: str = "") -> BenchRunResult:
        result.ok = False
        result.error_step = step
        result.error_message = message
        result.stderr_tail = tail_stderr(stderr)
        return result

    # 1. Génération ----------------------------------------------------------
    _notify("génération")
    run_dir.mkdir(parents=True, exist_ok=True)
    try:
        proc = runner(
            build_cmd(n, dataset_path, use_llm),
            shell=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_remaining(),
            env=proc_env,
        )
    except subprocess.TimeoutExpired as exc:
        return _fail("génération", "Délai dépassé pendant la génération.", getattr(exc, "stderr", ""))
    except Exception as exc:  # noqa: BLE001
        return _fail("génération", f"Échec du lancement de la génération : {exc}")
    if proc.returncode != 0:
        return _fail("génération", "La génération a échoué.", proc.stderr)
    result.steps_done.append("génération")

    # 2. Vérification oracle (si verify accepte --dataset) -------------------
    _notify("vérification")
    if verify_supports_dataset(runner=runner, env=proc_env):
        try:
            proc = runner(
                verify_cmd(dataset_path),
                shell=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=_remaining(),
                env=proc_env,
            )
        except subprocess.TimeoutExpired as exc:
            return _fail("vérification", "Délai dépassé pendant la vérification oracle.", getattr(exc, "stderr", ""))
        except Exception as exc:  # noqa: BLE001
            return _fail("vérification", f"Échec du lancement de la vérification : {exc}")
        # verify (datagen/cli.py) sort avec le code 1 en cas de fichier
        # introuvable ou d'incohérence oracle, 0 sinon : on se fie au returncode.
        if proc.returncode != 0:
            # Un échec de verify arrête la chaîne AVANT le rejeu.
            stderr = proc.stderr or proc.stdout
            return _fail("vérification", "La vérification oracle a échoué.", stderr)
        result.steps_done.append("vérification")
    else:
        result.verify_skipped = True

    # 3. Rejeu ---------------------------------------------------------------
    _notify("rejeu")
    try:
        proc = runner(
            run_bench_cmd(dataset_path),
            shell=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_remaining(),
            env=proc_env,
        )
    except subprocess.TimeoutExpired as exc:
        return _fail("rejeu", "Délai dépassé pendant le rejeu.", getattr(exc, "stderr", ""))
    except Exception as exc:  # noqa: BLE001
        return _fail("rejeu", f"Échec du lancement du rejeu : {exc}")
    if proc.returncode != 0:
        return _fail("rejeu", "Le rejeu du benchmark a échoué.", proc.stderr)
    result.steps_done.append("rejeu")

    # 4. Copie de la sortie figée de run_bench vers results_forge_<ts>.json --
    src = results_dir / "results_no-llm.json"
    dst = results_dir / f"results_forge_{ts}.json"
    try:
        shutil.copy2(src, dst)
    except OSError as exc:
        return _fail("copie", f"Résultats introuvables après le rejeu : {exc}")
    result.results_path = dst
    result.ok = True
    return result
