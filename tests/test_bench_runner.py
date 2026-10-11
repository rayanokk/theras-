"""Tests de l'orchestration du benchmark Forge (console/bench_runner.py).

Aucun vrai sous-processus : subprocess.run est remplacé par un faux configurable.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from console import bench_runner as br


# --- Faux subprocess.run ------------------------------------------------------


class FakeProc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class FakeRunner:
    """Enregistre les appels et renvoie une réponse par « rôle » de commande.

    responses : dict rôle -> FakeProc | Exception. Rôles : 'verify_help',
    'build', 'verify', 'run_bench'. Une Exception est levée (ex. TimeoutExpired).
    """

    def __init__(self, responses=None, verify_help_has_dataset=True):
        self.calls: list[list[str]] = []
        self.kwargs: list[dict] = []
        self._responses = responses or {}
        self._verify_help_has_dataset = verify_help_has_dataset

    def _role(self, cmd: list[str]) -> str:
        # Éléments EXACTS : les chemins (tmp_path pytest) peuvent contenir
        # 'verify'/'build', donc on ne fait pas de recherche en sous-chaîne.
        if "verify" in cmd and "--help" in cmd:
            return "verify_help"
        if "build" in cmd:
            return "build"
        if "verify" in cmd:
            return "verify"
        if "bench.run_bench" in cmd:
            return "run_bench"
        return "unknown"

    def __call__(self, cmd, **kwargs):
        self.calls.append(list(cmd))
        self.kwargs.append(kwargs)
        role = self._role(cmd)
        if role == "verify_help":
            text = "options: --dataset FILE" if self._verify_help_has_dataset else "options: --help"
            return FakeProc(0, stdout=text)
        resp = self._responses.get(role, FakeProc(0))
        if isinstance(resp, Exception):
            raise resp
        return resp


def _has(cmd: list[str], token: str) -> bool:
    """Vrai si `token` est un élément EXACT de la commande (jamais un bout de
    chemin : les tmp_path de pytest peuvent contenir 'verify', etc.).

    Pour run_bench, le token est le module 'bench.run_bench'.
    """
    aliases = {"run_bench": "bench.run_bench"}
    needle = aliases.get(token, token)
    return needle in cmd


def _find(calls, token: str):
    return next(c for c in calls if _has(c, token))


def _tmp_results(tmp_path) -> Path:
    d = tmp_path / "results"
    d.mkdir()
    return d


def _seed_run_bench_output(results_dir: Path, payload='{"ok": true}'):
    """Simule la sortie figée de run_bench pour la copie finale."""
    (results_dir / "results_no-llm.json").write_text(payload, encoding="utf-8")


# --- 1. Bornes de N -----------------------------------------------------------


def test_clamp_n_bounds():
    assert br.clamp_n(0) == br.N_MIN == 5
    assert br.clamp_n(4) == 5
    assert br.clamp_n(1000) == br.N_MAX == 100
    assert br.clamp_n(20) == 20
    assert br.clamp_n("abc") == br.N_DEFAULT  # non entier -> défaut


def test_run_clamps_n_in_commands(tmp_path):
    rdir = _tmp_results(tmp_path)
    _seed_run_bench_output(rdir)
    runner = FakeRunner()
    res = br.run_new_benchmark(1000, results_dir=rdir, runner=runner)
    assert res.n == 100
    build = _find(runner.calls, "build")
    assert build[build.index("--count") + 1] == "100"

    runner2 = FakeRunner()
    _seed_run_bench_output(rdir)
    res2 = br.run_new_benchmark(0, results_dir=rdir, runner=runner2)
    assert res2.n == 5


# --- 2. Commandes = listes, jamais shell=True ---------------------------------


def test_commands_are_lists_without_shell(tmp_path):
    rdir = _tmp_results(tmp_path)
    _seed_run_bench_output(rdir)
    runner = FakeRunner()
    br.run_new_benchmark(10, results_dir=rdir, runner=runner)

    assert runner.calls, "aucun sous-processus appelé"
    for cmd, kw in zip(runner.calls, runner.kwargs):
        assert isinstance(cmd, list)
        assert all(isinstance(part, str) for part in cmd)
        assert cmd[0] == sys.executable
        assert kw.get("shell") is False  # jamais shell=True

    build = _find(runner.calls, "build")
    assert build[:4] == [sys.executable, "-m", "datagen.cli", "build"]
    assert "--count" in build and "--out" in build and "--no-llm" in build
    run_bench = _find(runner.calls, "run_bench")
    assert run_bench[1:] == ["-m", "bench.run_bench", "--dataset",
                             run_bench[run_bench.index("--dataset") + 1],
                             "--mode", "no-llm"]


# --- 3. Mode LLM refusé sans FORGE_LLM_ENABLED --------------------------------


def test_llm_mode_adds_no_no_llm_flag(tmp_path):
    # bench_runner lui-même ne lit pas FORGE_LLM_ENABLED (c'est la page qui gère
    # l'affichage). Ici on vérifie l'effet de use_llm sur la commande build.
    rdir = _tmp_results(tmp_path)
    _seed_run_bench_output(rdir)
    runner = FakeRunner()
    br.run_new_benchmark(10, use_llm=True, results_dir=rdir, runner=runner)
    build = _find(runner.calls, "build")
    assert "--no-llm" not in build  # mode LLM demandé


def test_no_llm_mode_forces_no_llm_flag(tmp_path):
    rdir = _tmp_results(tmp_path)
    _seed_run_bench_output(rdir)
    runner = FakeRunner()
    br.run_new_benchmark(10, use_llm=False, results_dir=rdir, runner=runner)
    build = _find(runner.calls, "build")
    assert "--no-llm" in build


# --- 4. Échec de verify arrête la chaîne avant le rejeu -----------------------


def test_verify_nonzero_stops_before_run_bench(tmp_path):
    rdir = _tmp_results(tmp_path)
    runner = FakeRunner(responses={"verify": FakeProc(1, stderr="oracle KO")})
    res = br.run_new_benchmark(10, results_dir=rdir, runner=runner)
    assert not res.ok
    assert res.error_step == "vérification"
    assert not any(_has(c, "run_bench") for c in runner.calls)  # rejeu non lancé


def test_verify_divergence_exit1_stops_before_run_bench(tmp_path):
    # verify sort avec code 1 (divergence oracle) : on se fie au returncode,
    # la chaîne s'arrête avant le rejeu. Une sortie « ❌ » avec code 0 serait un
    # succès (plus de détection de « ❌ »), cas que verify ne produit plus.
    rdir = _tmp_results(tmp_path)
    runner = FakeRunner(
        responses={"verify": FakeProc(1, stdout="❌ Le dataset n'est plus cohérent")}
    )
    res = br.run_new_benchmark(10, results_dir=rdir, runner=runner)
    assert not res.ok
    assert res.error_step == "vérification"
    assert not any(_has(c, "run_bench") for c in runner.calls)


def test_verify_cross_mark_with_exit0_is_not_failure(tmp_path):
    # Garde-fou anti-régression : on ne se base PLUS sur « ❌ » dans la sortie.
    # Un code 0 (même avec un ❌ parasite) laisse la chaîne continuer.
    rdir = _tmp_results(tmp_path)
    _seed_run_bench_output(rdir)
    runner = FakeRunner(responses={"verify": FakeProc(0, stdout="❌ bruit")})
    res = br.run_new_benchmark(10, results_dir=rdir, runner=runner)
    assert res.ok
    assert any(_has(c, "run_bench") for c in runner.calls)


# --- 5. verify avec / sans --dataset ------------------------------------------


def test_verify_called_when_help_supports_dataset(tmp_path):
    rdir = _tmp_results(tmp_path)
    _seed_run_bench_output(rdir)
    runner = FakeRunner(verify_help_has_dataset=True)
    res = br.run_new_benchmark(10, results_dir=rdir, runner=runner)
    assert res.ok
    assert not res.verify_skipped
    verify = next(c for c in runner.calls if _has(c, "verify") and "--help" not in c)
    assert "--dataset" in verify


def test_verify_skipped_when_help_lacks_dataset(tmp_path):
    rdir = _tmp_results(tmp_path)
    _seed_run_bench_output(rdir)
    runner = FakeRunner(verify_help_has_dataset=False)
    res = br.run_new_benchmark(10, results_dir=rdir, runner=runner)
    assert res.ok
    assert res.verify_skipped is True
    # verify (hors --help) n'a jamais été appelé ; le rejeu, oui.
    assert not any(_has(c, "verify") and "--help" not in c for c in runner.calls)
    assert any(_has(c, "run_bench") for c in runner.calls)


# --- 6. Timeout -> message d'erreur sans exception ----------------------------


def test_timeout_returns_error_without_raising(tmp_path):
    rdir = _tmp_results(tmp_path)
    runner = FakeRunner(
        responses={"build": subprocess.TimeoutExpired(cmd="build", timeout=1)}
    )
    res = br.run_new_benchmark(10, results_dir=rdir, runner=runner)
    assert not res.ok
    assert res.error_step == "génération"
    assert "dépassé" in res.error_message.lower()


# --- 7. Environnement : APPROVAL_TTL_SECONDS retiré, RISK_LLM_ENABLED=false ----


def test_subprocess_env_strips_approval_ttl_and_forces_no_llm():
    base = {"APPROVAL_TTL_SECONDS": "5", "RISK_LLM_ENABLED": "true", "PATH": "x"}
    env = br.subprocess_env(base)
    assert "APPROVAL_TTL_SECONDS" not in env
    assert env["RISK_LLM_ENABLED"] == "false"
    assert env["PATH"] == "x"  # le reste est préservé


def test_env_passed_to_subprocesses_has_no_approval_ttl(tmp_path, monkeypatch):
    monkeypatch.setenv("APPROVAL_TTL_SECONDS", "9")
    rdir = _tmp_results(tmp_path)
    _seed_run_bench_output(rdir)
    runner = FakeRunner()
    br.run_new_benchmark(10, results_dir=rdir, runner=runner)
    for kw in runner.kwargs:
        env = kw.get("env") or {}
        assert "APPROVAL_TTL_SECONDS" not in env
        assert env.get("RISK_LLM_ENABLED") == "false"


# --- 8. Sortie : dossier par run + copie results_forge_<ts>.json --------------


def test_success_copies_results_and_sets_paths(tmp_path):
    rdir = _tmp_results(tmp_path)
    _seed_run_bench_output(rdir, payload='{"metrics": {}}')
    runner = FakeRunner()
    res = br.run_new_benchmark(10, results_dir=rdir, runner=runner)
    assert res.ok
    # dataset dans un dossier dédié forge_<ts>/dataset.json
    assert res.dataset_path.parent.name.startswith("forge_")
    assert res.dataset_path.name == "dataset.json"
    build = _find(runner.calls, "build")
    out = build[build.index("--out") + 1]
    assert out.endswith("dataset.json") and "forge_" in out
    # copie finale présente et nommée results_forge_<ts>.json
    assert res.results_path.exists()
    assert res.results_path.name.startswith("results_forge_")


def test_missing_run_bench_output_is_copy_error(tmp_path):
    rdir = _tmp_results(tmp_path)
    # pas de results_no-llm.json : la copie finale échoue proprement
    runner = FakeRunner()
    res = br.run_new_benchmark(10, results_dir=rdir, runner=runner)
    assert not res.ok
    assert res.error_step == "copie"


# --- stderr tronqué -----------------------------------------------------------


def test_tail_stderr_keeps_last_lines():
    text = "\n".join(str(i) for i in range(50))
    out = br.tail_stderr(text, limit=20)
    assert out.splitlines() == [str(i) for i in range(30, 50)]
