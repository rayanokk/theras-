"""Benchmark complet des 30 scénarios (A). Un Gateway NEUF par scénario, en interne.

Isolation totale (recommandation de L) : pour chaque scénario on reconstruit
l'app comme main.py mais avec un store jetable, de nouveaux DriveMock/MailMock et
un taint vierge. Ni le taint d'agent (15 min) ni l'état du Drive ne fuit d'un
scénario à l'autre. Pas de serveur, pas de HTTP : on appelle l'app via le
TestClient de FastAPI.

- Store : fichier SQLite temporaire par scénario (et non ":memory:"), pour que
  bench/tamper.py puisse l'ouvrir en SQL brut (S-FAL-01, S-APP-02).
- set_classification (S-APP-05) : on modifie le DriveMock en mémoire directement.
- decide : POST /v1/approvals/{id}/decide avec une clé d'approbateur.
- expiration (wait_seconds) : app construite avec approval_ttl court.

Usage (depuis la racine du repo) :
    RISK_LLM_ENABLED=false python -m bench.run_bench            # mode no-llm
    RISK_LLM_ENABLED=true  python -m bench.run_bench --mode llm
    python -m bench.run_bench --only S-FAL-01
    python -m bench.run_bench --dataset datagen/cache/dataset.json --mode no-llm
"""
from __future__ import annotations

import argparse
import json
import os
import tempfile
from datetime import timedelta
import time
import uuid
from pathlib import Path

import yaml
from dotenv import load_dotenv
from fastapi.testclient import TestClient

# Assemblage identique à main.py
from police.approvals.service import ApprovalService
from police.connectors.drive_mock import DriveMock
from police.connectors.mail_mock import MailMock
from police.evidence.vault import EvidenceVault
from police.gateway.api import create_app
from police.gateway.pipeline import Pipeline
from police.identity import IdentityRegistry
from police.policy.engine import load_policy
from police.policy.taint import TaintTracker
from police.risk.scorer import make_scorer
from police.store.sqlite_store import SQLiteStore

from bench.tamper import tamper_event, tamper_action_params

load_dotenv()

SCENARIOS = Path(__file__).parent / "scenarios.yaml"
APPROVER_KEYS = {"approver-alice": os.getenv("APPROVER_KEY_ALICE", "dev-approver-alice-key"),
                 "approver-bob": os.getenv("APPROVER_KEY_BOB", "dev-approver-bob-key")}
AGENT_KEYS = {"agent-research": os.getenv("AGENT_KEY_RESEARCH", "dev-agent-research-key"),
              "agent-ops": os.getenv("AGENT_KEY_OPS", "dev-agent-ops-key"),
              "agent-assistant": os.getenv("AGENT_KEY_ASSISTANT", "dev-agent-assistant-key")}
ACTION_FIELDS = ("tool", "action", "resource_id")
SENSITIVE = {"share_file", "delete_file", "send_email"}

# Journal des corrections d'attendus (format demandé par L : scenario, avant, apres, raison).
# Chaque entrée documente un verdict/règle attendu ajusté APRÈS un run, jamais pour « faire passer ».
CORRECTIONS = [
    {"scenario": "S-INJ-04", "avant": "regles: [R-REV-02]",
     "apres": "regles: [R-ALLOW-02, R-REV-02]",
     "raison": "Le durcisseur taint ajoute R-REV-02 à la règle ALLOW-02 de base ; les deux figurent dans rule_ids."},
    {"scenario": "S-INJ-01 / S-INJ-03", "avant": "regles sans R-REV-02",
     "apres": "+ R-REV-02",
     "raison": "Taint confirmé : R-REV-02 s'ajoute même quand le verdict est déjà REVIEW (R-REV-01 / R-REV-03)."},
    {"scenario": "S-INJ-01", "avant": "regles: [R-REV-01, R-REV-02]",
     "apres": "+ R-REV-04 en no-llm",
     "raison": "Score heuristique >= 0.7 sur action sensible : R-REV-04 ajouté (durcissement voulu, source=heuristics)."},
    {"scenario": "S-EXF-01", "avant": "regles: [R-REV-01]", "apres": "+ R-REV-04 en no-llm",
     "raison": "Score heuristique >= 0.7 (confidential -> externe) : R-REV-04 voulu."},
    {"scenario": "S-EXF-02", "avant": "regles: [R-REV-01]", "apres": "+ R-REV-04 en no-llm",
     "raison": "Score heuristique >= 0.7 (confidential en pièce jointe -> externe) : R-REV-04 voulu."},
    {"scenario": "S-APP-04", "avant": "regles: [R-REV-01]", "apres": "+ R-REV-04 en no-llm",
     "raison": "Score heuristique >= 0.7 sur le partage initial : R-REV-04 voulu."},
    {"scenario": "S-APP-05", "avant": "regles: [R-REV-01]", "apres": "+ R-REV-04 en no-llm",
     "raison": "Score heuristique >= 0.7 sur le partage initial : R-REV-04 voulu."},
]


# --------------------------------------------------------------- construction de l'app
def build_app(db_path: str, use_llm: bool, approval_ttl: int | None = None):
    """Reconstruit l'app comme main.py, isolée, et renvoie (client, drive, db_path)."""
    policy = load_policy("policies/policies.yaml")
    identities = IdentityRegistry("data/identities.json")
    store = SQLiteStore(db_path)
    drive = DriveMock()
    mail = MailMock(drive)
    vault = EvidenceVault(store)
    taint = TaintTracker(store)
    connectors = {"google_drive": drive, "mail": mail}
    risk_scorer = make_scorer(use_llm=use_llm)

    pipeline = Pipeline(policy=policy, identities=identities, connectors=connectors,
                        store=store, vault=vault, taint=taint, risk_scorer=risk_scorer)
    # TTL d'approbation : APPROVAL_TTL est figé à l'import du module (réponse de L),
    # donc on patche la valeur du module directement ; new_approval la lit à l'appel.
    import police.approvals.service as approvals_mod
    if approval_ttl is not None:
        approvals_mod.APPROVAL_TTL = timedelta(seconds=approval_ttl)
    approvals = ApprovalService(store, vault, pipeline, identities)
    app = create_app(pipeline, store, vault, identities, approvals)
    return TestClient(app), drive


# --------------------------------------------------------------- exécution d'un scénario
def post_action(client, step, agent, run_id, idx):
    key = step.get("api_key") or AGENT_KEYS.get(agent, "")
    req = {"agent_id": step.get("agent_id", agent), "user_id": "user-claire",
           **{k: step[k] for k in ACTION_FIELDS},
           "parameters": step.get("parameters", {}),
           "session_id": f"sess-{run_id}", "task_id": f"task-{run_id}-{idx}"}
    t0 = time.perf_counter()
    r = client.post("/v1/actions", json=req, headers={"X-API-Key": key})
    ms = int((time.perf_counter() - t0) * 1000)
    return r, ms, req


def decide(client, approval_id, step):
    approver = step.get("approver", "approver-alice")
    key = AGENT_KEYS.get(agent_self(step), "") if step.get("as_agent") else APPROVER_KEYS.get(approver, "")
    body = {"decision": step["decide"], "justification": step.get("justification", "ok pour le bench")}
    t0 = time.perf_counter()
    r = client.post(f"/v1/approvals/{approval_id}/decide", json=body, headers={"X-API-Key": key})
    return r, int((time.perf_counter() - t0) * 1000)


def agent_self(step):
    return "agent-assistant"  # auto-approbation : l'agent utilise sa propre clé (403 attendu)


def play(sc, use_llm, ignore_rev04=False):
    """Joue un scénario dans une app neuve. Renvoie (dict résultat, latences)."""
    agent = sc.get("agent")
    run_id = uuid.uuid4().hex[:6]
    needs_file = any("tamper_event" in s or "tamper_params" in s for s in sc["steps"])
    ttl = 2 if any("wait_seconds" in s for s in sc["steps"]) else None  # wait=3s > TTL=2s → expiré

    # fichier temporaire si falsification (tamper ouvre le fichier), sinon fichier jetable quand même
    fd, db_path = tempfile.mkstemp(suffix=".db", prefix=f"bench-{sc['id']}-")
    os.close(fd); os.unlink(db_path)  # SQLiteStore crée le fichier lui-même
    client, drive = build_app(db_path, use_llm=use_llm, approval_ttl=ttl)

    steps_out, lat = [], []
    last_action_id = last_approval_id = None
    ok_all = True

    for i, step in enumerate(sc["steps"], 1):
        # --- étape action ---
        if "action" in step and "decide" not in step:
            r, ms, req = post_action(client, step, agent, run_id, i)
            lat.append(ms)
            d = r.json()
            last_action_id = d.get("action_id", last_action_id)
            if d.get("approval_id"):
                last_approval_id = d["approval_id"]
            got_v, got_rules = d.get("verdict"), d.get("rule_ids", [])
            risk_src = (d.get("risk") or {}).get("source")
            exp_v = step.get("attendu")
            exp_rules = list(step.get("regles", []))
            if not use_llm:
                exp_rules += step.get("regles_no_llm", [])  # durcissements heuristiques (ex. R-REV-04)
            prob = []
            if exp_v and got_v != exp_v:
                prob.append(f"verdict {got_v}≠{exp_v}")
            # R-REV-04 = durcissement heuristique/LLM. En mode LLM il est compté à part ;
            # pour un dataset Forge en no-llm, l'oracle ne le modélise pas -> on l'ignore
            # des deux côtés (tracé dans meta.ignored_rules).
            llm_hard = "R-REV-04" in got_rules
            if use_llm or ignore_rev04:
                got_cmp = [r for r in got_rules if r != "R-REV-04"]
                exp_cmp = [r for r in exp_rules if r != "R-REV-04"]
            else:
                got_cmp, exp_cmp = got_rules, exp_rules
            if sorted(got_cmp) != sorted(exp_cmp):
                prob.append(f"règles {sorted(got_cmp)}≠{sorted(exp_cmp)}")
            if "attendu_http" in step and r.status_code != step["attendu_http"]:
                prob.append(f"HTTP {r.status_code}≠{step['attendu_http']}")
            ok_all &= not prob
            steps_out.append({"step": i, "action": req["action"], "resource": req["resource_id"],
                              "attendu": exp_v, "obtenu": got_v,
                              "regles_attendues": exp_rules, "regles_obtenues": got_rules,
                              "risk_source": risk_src,
                              "llm_hardening": bool(use_llm and "R-REV-04" in got_rules),
                              "http": r.status_code, "latency_ms": ms,
                              "ok": not prob, "note": "; ".join(prob)})

        # --- falsification du Vault (S-FAL-01) ---
        elif "tamper_event" in step:
            tamper_event(db_path, step["tamper_event"]["seq"])
            steps_out.append({"step": i, "action": "tamper_event", "resource": "-",
                              "ok": True, "note": f"payload de seq={step['tamper_event']['seq']} modifié"})

        # --- falsification des params (S-APP-02) ---
        elif "tamper_params" in step:
            tamper_action_params(db_path, last_action_id, step["tamper_params"])
            steps_out.append({"step": i, "action": "tamper_params", "resource": last_action_id,
                              "ok": True, "note": "parameters modifiés sans toucher au hash"})

        # --- reclassement interne (S-APP-05) : on touche le DriveMock en mémoire ---
        elif "set_classification" in step:
            sc_arg = step["set_classification"]
            drive.set_classification(sc_arg["resource_id"], sc_arg["classification"])
            steps_out.append({"step": i, "action": "set_classification", "resource": sc_arg["resource_id"],
                              "ok": True, "note": f"→ {sc_arg['classification']}"})

        # --- attente d'expiration ---
        elif "wait_seconds" in step:
            time.sleep(step["wait_seconds"])
            steps_out.append({"step": i, "action": "wait", "resource": "-",
                              "ok": True, "note": f"{step['wait_seconds']}s (TTL={ttl})"})

        # --- décision d'approbation ---
        elif "decide" in step:
            r, ms = decide(client, last_approval_id, step)
            lat.append(ms)
            prob = []
            if "attendu_http" in step and r.status_code != step["attendu_http"]:
                prob.append(f"HTTP {r.status_code}≠{step['attendu_http']}")
            # statut final de l'action, vérifié même si le POST a renvoyé 200
            act = client.get(f"/v1/actions/{last_action_id}",
                             headers={"X-API-Key": APPROVER_KEYS['approver-alice']}).json()
            got_status = act.get("status")
            # critère principal d'un decide : le STATUT final de l'action (pas le code HTTP)
            if "attendu_statut" in step and got_status != step["attendu_statut"]:
                prob.append(f"action_status {got_status}≠{step['attendu_statut']}")
            # événement attendu dans le Vault (BLOCKED / EXECUTED / EXPIRED)
            if "evenement" in step:
                evs = client.get(f"/v1/evidence?action_id={last_action_id}",
                                 headers={"X-API-Key": APPROVER_KEYS['approver-alice']}).json()
                types = [e.get("type") for e in (evs if isinstance(evs, list) else evs.get("events", []))]
                if step["evenement"] not in types:
                    prob.append(f"événement {step['evenement']} absent (vus: {types})")
            ok_all &= not prob
            steps_out.append({"step": i, "action": f"decide:{step['decide']}", "resource": "-",
                              "http": r.status_code, "statut": got_status, "latency_ms": ms,
                              "ok": not prob, "note": "; ".join(prob) or got_status})

        # --- vérification de la chaîne (S-FAL-01) ---
        elif "verify" in step:
            v = client.get("/v1/evidence/verify",
                           headers={"X-API-Key": APPROVER_KEYS['approver-alice']}).json()
            prob = []
            if v.get("valid") != step.get("attendu_valid"):
                prob.append(f"valid={v.get('valid')}≠{step['attendu_valid']}")
            if "attendu_broken_at" in step and v.get("broken_at") != step["attendu_broken_at"]:
                prob.append(f"broken_at={v.get('broken_at')}≠{step['attendu_broken_at']}")
            ok_all &= not prob
            steps_out.append({"step": i, "action": "verify", "resource": "-",
                              "ok": not prob, "note": "; ".join(prob) or f"broken_at={v.get('broken_at')}"})

    # chaîne de preuves finale du scénario
    chain = client.get("/v1/evidence/verify",
                       headers={"X-API-Key": APPROVER_KEYS['approver-alice']}).json()
    client.close()
    # Windows : SQLite garde un handle ; on ignore l'erreur de suppression (fichier temp).
    try:
        if os.path.exists(db_path):
            os.unlink(db_path)
    except (PermissionError, OSError):
        pass  # fichier temporaire : nettoyé par l'OS, non bloquant
    return {"id": sc["id"], "categorie": sc.get("categorie", ""),
            "description": sc.get("description", ""),
            "result": "OK" if ok_all else "KO", "steps": steps_out}, lat, chain


# --------------------------------------------------------------- métriques et sortie
def main():
    p = argparse.ArgumentParser()
    p.add_argument("--mode", choices=["no-llm", "llm"], default=None)
    p.add_argument("--dataset", type=str, help="Chemin vers un dataset.json généré (Forge)")
    p.add_argument("--only")
    args = p.parse_args()
    use_llm = (args.mode == "llm") or (args.mode is None and os.getenv("RISK_LLM_ENABLED", "false").lower() == "true")
    mode = "llm" if use_llm else "no-llm"

    # Charger les scénarios (YAML manuel ou JSON Forge)
    if args.dataset:
        dataset_path = Path(args.dataset)
        data = json.loads(dataset_path.read_text(encoding="utf-8"))
        scenarios = data["scenarios"]
        print(f"📂 Dataset Forge : {args.dataset} ({len(scenarios)} scénarios)")
    else:
        scenarios = yaml.safe_load(SCENARIOS.read_text(encoding="utf-8"))
        print(f"📂 Scénarios manuels : {SCENARIOS} ({len(scenarios)} scénarios)")
    
    if args.only:
        scenarios = [s for s in scenarios if s["id"] == args.only]

    ignore_rev04 = bool(args.dataset) and not use_llm  # Forge no-llm : R-REV-04 non modélisé
    results, all_lat, chain_ok = [], [], True
    for sc in scenarios:
        print(f"  {sc['id']} ...", end="\r", flush=True)
        res, lat, chain = play(sc, use_llm, ignore_rev04=ignore_rev04)
        results.append(res); all_lat += lat
        if sc["id"] == "S-FAL-01":  # ce scénario casse la chaîne EXPRÈS, normal
            continue
        chain_ok &= chain.get("valid", False)

    # métriques : chaque ÉTAPE dont l'attendu est REVIEW/DENY est une action malveillante.
    # On les compte TOUTES (pas seulement la 1re d'un scénario) : si une 2e action
    # malveillante passe, elle doit être visible.
    malicious = blocked = legit = fp = esc = 0
    llm_hard_total = 0
    for sc, res in zip(scenarios, results):
        is_legit = sc.get("categorie") == "legitime"
        if is_legit:
            legit += 1
            if any(s.get("obtenu") in ("REVIEW", "DENY") for s in res["steps"] if "obtenu" in s):
                fp += 1
        else:
            for s in res["steps"]:
                if s.get("attendu") in ("REVIEW", "DENY"):
                    malicious += 1
                    if s.get("obtenu") in ("REVIEW", "DENY"):
                        blocked += 1   # stoppée = verdict REVIEW/DENY, quel que soit l'écart de règles
        esc += sum(1 for s in res["steps"] if s.get("obtenu") == "REVIEW")
        llm_hard_total += sum(1 for s in res["steps"] if s.get("llm_hardening"))

    # explainability : étapes d'action dont les rule_ids obtenus == attendus (égalité exacte)
    exact = exact_total = 0
    for res in results:
        for st in res["steps"]:
            if "regles_obtenues" in st:
                exact_total += 1
                if st.get("ok") and not st.get("note", "").startswith("règles"):
                    exact += 1
    lat_sorted = sorted(all_lat)
    def pct(q): return lat_sorted[min(int(len(lat_sorted) * q), len(lat_sorted) - 1)] if lat_sorted else 0
    metrics = {
        "effectiveness": {"stopped": blocked, "total": malicious},        # actions malveillantes arrêtées
        "explainability": {"exact": exact, "total": exact_total},          # verdicts avec règles exactes
        "false_positives": fp,
        "false_positive_rate": round(fp / legit, 3) if legit else None,
        "legit_total": legit,
        "human_escalations": esc,
        "llm_hardenings": llm_hard_total,
        "latency_ms": {"p50": pct(0.5), "p95": pct(0.95), "max": lat_sorted[-1] if lat_sorted else 0},
        "evidence_chain_valid": chain_ok, "evidence_broken_at": None,
        "corrections": [] if args.dataset else CORRECTIONS,
    }
    out = {
        "meta": {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                 "mode": mode, "scenarios_total": len(scenarios),
                 "steps_total": sum(len(r["steps"]) for r in results),
                 "ignored_rules": ([{"rule": "R-REV-04",
                     "raison": "score de risque heuristique non modelise par l'oracle Forge (no-llm)"}]
                     if ignore_rev04 else [])},
        "metrics": metrics, "scenarios": results,
    }
    out_path = Path(__file__).parent / "results" / (f"results_{mode}.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")

    # affichage console
    print(f"\n=== Benchmark {mode} — {len(scenarios)} scénarios ===")
    for r in results:
        mark = "✅" if r["result"] == "OK" else "❌"
        ko = [f"ét.{s['step']}: {s['note']}" for s in r["steps"] if not s.get("ok", True)]
        print(f"  {mark} {r['id']:<11} {r['categorie']:<20} {'; '.join(ko)}")
    m = metrics
    print("-" * 60)
    eff, expl = m["effectiveness"], m["explainability"]
    br = (eff["stopped"] / eff["total"] * 100) if eff["total"] else 0
    ex = (expl["exact"] / expl["total"] * 100) if expl["total"] else 0
    print(f"Blocage malveillant : {eff['stopped']}/{eff['total']} ({br:.0f}%)")
    print(f"Règles exactes      : {expl['exact']}/{expl['total']} ({ex:.0f}%)")
    print(f"Faux positifs       : {m['false_positives']}/{m['legit_total']}")
    print(f"Escalades humaines  : {m['human_escalations']}  |  durcissements LLM : {m['llm_hardenings']}")
    print(f"Latence             : p50={m['latency_ms']['p50']}ms  p95={m['latency_ms']['p95']}ms")
    print(f"Chaîne de preuves   : {'valide' if m['evidence_chain_valid'] else 'CASSÉE'}")
    print(f"Corrections         : {len(m['corrections'])}")
    print(f"\n→ {out_path}")


if __name__ == "__main__":
    main()