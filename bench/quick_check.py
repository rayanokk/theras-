"""Rejoue bench/scenarios.yaml contre le VRAI Gateway et compare aux verdicts attendus (A).

Version "avant approbations" de run_bench.py : joue toutes les étapes d'action
(POST /v1/actions) et saute les étapes qui exigent les approbations ou l'accès
à la base (decide, wait_seconds, tamper_*, set_classification, verify).

N'utilise PAS l'agent ni Bedrock : envoie directement les ActionRequest.
Résultat déterministe, rapide, sans quota.

Usage (Gateway lancé sur 127.0.0.1:8000) :
    python -m bench.quick_check
    python -m bench.quick_check --only S-INJ-01
"""
import argparse
import json
import os
import time
import uuid
from pathlib import Path

import httpx
import yaml
from dotenv import load_dotenv

load_dotenv(override=True)

GATEWAY_URL = os.getenv("GATEWAY_URL", "http://127.0.0.1:8000")
SCENARIOS = Path(__file__).parent / "scenarios.yaml"
RESULTS = Path(__file__).parent / "results" / "quick_check.json"
KEY_ENV = {"agent-research": "AGENT_KEY_RESEARCH",
           "agent-ops": "AGENT_KEY_OPS",
           "agent-assistant": "AGENT_KEY_ASSISTANT"}
ACTION_FIELDS = ("tool", "action", "resource_id")
SKIP_KEYS = ("decide", "wait_seconds", "tamper_params", "tamper_event", "set_classification", "verify")


def play_scenario(sc):
    agent = sc.get("agent")
    api_key = sc.get("api_key") or os.getenv(KEY_ENV.get(agent, ""), "")
    run = uuid.uuid4().hex[:6]           # session neuve à chaque exécution : pas de taint hérité
    session_id, task_id = f"sess-bench-{sc['id']}-{run}", f"task-bench-{sc['id']}-{run}"
    rows = []

    for i, step in enumerate(sc["steps"], 1):
        skipped = next((k for k in SKIP_KEYS if k in step), None)
        if skipped:
            rows.append({"id": sc["id"], "step": i, "result": "SKIP", "note": f"{skipped} (approbations/Phase 4)"})
            break  # la suite du scénario dépend de cette étape

        req = {"agent_id": step.get("agent_id", agent), "user_id": "user-claire",
               **{k: step[k] for k in ACTION_FIELDS},
               "parameters": step.get("parameters", {}),
               "session_id": session_id, "task_id": task_id}
        t0 = time.perf_counter()
        try:
            r = httpx.post(f"{GATEWAY_URL}/v1/actions", json=req, headers={"X-API-Key": api_key}, timeout=30)
            d = r.json()
        except Exception as exc:
            rows.append({"id": sc["id"], "step": i, "result": "ERREUR", "note": str(exc)[:80]})
            break
        ms = int((time.perf_counter() - t0) * 1000)

        got_v, got_rules = d.get("verdict"), d.get("rule_ids", [])
        exp_v, exp_rules = step.get("attendu"), step.get("regles", [])
        problems = []
        if exp_v and got_v != exp_v:
            problems.append(f"verdict {got_v} au lieu de {exp_v}")
        missing = [x for x in exp_rules if x not in got_rules]
        if missing:
            problems.append(f"règles manquantes {missing}")
        if "attendu_http" in step and r.status_code != step["attendu_http"]:
            problems.append(f"HTTP {r.status_code} au lieu de {step['attendu_http']}")

        rows.append({"id": sc["id"], "step": i, "action": req["action"], "resource": req["resource_id"],
                     "attendu": exp_v, "obtenu": got_v, "http": r.status_code,
                     "regles_attendues": exp_rules, "regles_obtenues": got_rules,
                     "ms": ms, "result": "KO" if problems else "OK", "note": "; ".join(problems)})
    return rows


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--only", help="ne jouer qu'un scénario (ex. S-INJ-01)")
    args = p.parse_args()

    scenarios = yaml.safe_load(SCENARIOS.read_text(encoding="utf-8"))
    if args.only:
        scenarios = [s for s in scenarios if s["id"] == args.only]

    rows = [row for sc in scenarios for row in play_scenario(sc)]

    print(f"\n{'Scénario':<11}{'ét.':<4}{'attendu':<8}{'obtenu':<8}{'HTTP':<6}{'ms':<6}{'':<4}règles obtenues / note")
    print("-" * 100)
    for x in rows:
        if x["result"] in ("SKIP", "ERREUR"):
            print(f"{x['id']:<11}{x['step']:<4}{'':<28}{x['result']:<4}  {x['note']}")
            continue
        mark = "✅" if x["result"] == "OK" else "❌"
        info = x["note"] if x["result"] == "KO" else ",".join(x["regles_obtenues"])
        print(f"{x['id']:<11}{x['step']:<4}{x['attendu'] or '-':<8}{x['obtenu'] or '-':<8}"
              f"{x['http']:<6}{x['ms']:<6}{mark:<4}{info}")

    played = [x for x in rows if x["result"] in ("OK", "KO")]
    ko = [x for x in played if x["result"] == "KO"]
    lat = sorted(x["ms"] for x in played)
    print("-" * 100)
    print(f"Étapes jouées : {len(played)}  |  OK : {len(played) - len(ko)}  |  KO : {len(ko)}  |  "
          f"sautées : {sum(x['result'] == 'SKIP' for x in rows)}  |  erreurs : {sum(x['result'] == 'ERREUR' for x in rows)}")
    if lat:
        print(f"Latence Gateway : p50 = {lat[len(lat) // 2]} ms, max = {lat[-1]} ms")

    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Détail enregistré dans {RESULTS}")


if __name__ == "__main__":
    main()
