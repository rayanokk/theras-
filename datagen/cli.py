"""CLI pour Forge (datagen) — commandes build, verify, stats, regen."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import yaml

from datagen.generator import generate
from datagen.oracle import Oracle


CACHE_DIR = Path(__file__).parent / "cache"
DOCUMENTS_DIR = CACHE_DIR / "documents"
DATASET_FILE = CACHE_DIR / "dataset.json"


def cmd_build(args):
    """Génère N scénarios et les écrit dans le cache (ou le chemin --out)."""
    print(f"🔨 Génération de {args.count} scénarios (seed={args.seed})...")

    # --no-llm : forcer le fallback sans Bedrock (masque le modèle le temps du build).
    if getattr(args, "no_llm", False):
        os.environ.pop("BEDROCK_MODEL_ID_AGENT", None)
        print("   (mode sans LLM : fallback déterministe)")

    # --out : fichier dataset de sortie ; les documents vont dans <dossier de --out>/documents/.
    dataset_file = Path(args.out) if getattr(args, "out", None) else DATASET_FILE
    documents_dir = dataset_file.parent / "documents"
    dataset_file.parent.mkdir(parents=True, exist_ok=True)
    documents_dir.mkdir(exist_ok=True)

    scenarios, documents, stats = generate(count=args.count, seed=args.seed)
    
    # Écrire les documents générés
    for resource_id, doc_data in documents.items():
        with open(documents_dir / f"{resource_id}", "w", encoding="utf-8") as f:
            f.write(doc_data["body"])
        print(f"  📄 {resource_id}")

    # Écrire le dataset
    dataset = {"scenarios": scenarios, "stats": stats}
    with open(dataset_file, "w", encoding="utf-8") as f:
        json.dump(dataset, f, indent=2, ensure_ascii=False)

    print(f"\n✅ Généré : {len(scenarios)} scénarios")
    print(f"   📊 Stats : {stats['llm']} LLM, {stats['fallback']} fallback")
    print(f"   📁 Dataset : {dataset_file}")


def cmd_verify(args):
    """Relit dataset.json et vérifie que l'oracle donne toujours les mêmes verdicts."""
    if not DATASET_FILE.exists():
        print(f"❌ {DATASET_FILE} introuvable. Lance `build` d'abord.")
        return
    
    print("🔍 Vérification de la cohérence oracle...")
    
    with open(DATASET_FILE, encoding="utf-8") as f:
        data = json.load(f)
    
    scenarios = data["scenarios"]
    
    # NOUVEAU : Oracle avec seed fixe pour le déterminisme
    import random
    random.seed(42)
    
    oracle = Oracle(use_risk=False)  # aligné sur le générateur : R-REV-04 non vérifié (probabiliste)
    
    divergences = []
    for sc in scenarios:
        agent = sc["agent"]
        session_tainted = agent_tainted = False
        
        for i, step in enumerate(sc["steps"]):
            action = step["action"]
            resource_id = step["resource_id"]
            recipient = step.get("parameters", {}).get("recipient") or step.get("parameters", {}).get("to")
            
            from datagen.oracle import domain_of
            domain = domain_of(recipient)
            
            verdict_attendu = step["attendu"]
            # R-REV-04 exclu de la comparaison (durcissement probabiliste non prédictible)
            regles_attendues = {r for r in step.get("regles", []) if r != "R-REV-04"}

            verdict_oracle, regles_oracle, _regles_no_llm = oracle.verdict(
                agent=agent, action=action, resource_id=resource_id,
                recipient_domain=domain,
                session_tainted=session_tainted, agent_tainted=agent_tainted
            )
            regles_oracle_set = {r for r in regles_oracle if r != "R-REV-04"}

            if verdict_oracle != verdict_attendu or regles_oracle_set != regles_attendues:
                divergences.append({
                    "scenario": sc["id"],
                    "step": i,
                    "action": action,
                    "attendu": (verdict_attendu, sorted(regles_attendues)),
                    "oracle": (verdict_oracle, sorted(regles_oracle_set))
                })
            
            # Taint après lecture doc non fiable
            from datagen.faits import fichier
            f = fichier(resource_id)
            if action == "read_file" and f and not f["trusted"]:
                session_tainted = agent_tainted = True
    
    if divergences:
        print(f"\n⚠️  {len(divergences)} divergence(s) détectée(s) :\n")
        for d in divergences:
            print(f"  {d['scenario']} step {d['step']} ({d['action']})")
            print(f"    Attendu : {d['attendu']}")
            print(f"    Oracle  : {d['oracle']}")
        print("\n❌ Le cache n'est plus cohérent avec l'oracle.")
    else:
        print(f"\n✅ {len(scenarios)} scénarios vérifiés : 100% cohérents avec l'oracle.")


def cmd_stats(args):
    """Affiche les stats du dataset."""
    if not DATASET_FILE.exists():
        print(f"❌ {DATASET_FILE} introuvable.")
        return
    
    with open(DATASET_FILE, encoding="utf-8") as f:
        data = json.load(f)
    
    stats = data.get("stats", {})
    scenarios = data["scenarios"]
    
    print(f"📊 Statistiques du dataset :")
    print(f"   Total scénarios : {len(scenarios)}")
    print(f"   Générés par LLM : {stats.get('llm', 0)}")
    print(f"   Fallback        : {stats.get('fallback', 0)}")
    print(f"\n   Par famille :")
    for famille, count in stats.get("par_famille", {}).items():
        print(f"     - {famille:25s} : {count}")


def cmd_regen(args):
    """Régénère le cache (alias de build)."""
    cmd_build(args)


def main():
    parser = argparse.ArgumentParser(description="Forge — générateur de données de test Theras")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # build
    p_build = subparsers.add_parser("build", help="Génère N scénarios")
    p_build.add_argument("--count", type=int, default=20, help="Nombre de scénarios (défaut: 20)")
    p_build.add_argument("--seed", type=int, default=0, help="Seed aléatoire (défaut: 0)")
    p_build.add_argument("--out", help="Fichier dataset de sortie (défaut: datagen/cache/dataset.json)")
    p_build.add_argument("--no-llm", action="store_true", help="Forcer le fallback sans Bedrock")
    
    # verify
    subparsers.add_parser("verify", help="Vérifie la cohérence oracle du cache")
    
    # stats
    subparsers.add_parser("stats", help="Affiche les stats du dataset")
    
    # regen
    p_regen = subparsers.add_parser("regen", help="Régénère le cache (alias de build)")
    p_regen.add_argument("--count", type=int, default=20)
    p_regen.add_argument("--seed", type=int, default=0)
    p_regen.add_argument("--out", help="Fichier dataset de sortie")
    p_regen.add_argument("--no-llm", action="store_true")
    
    args = parser.parse_args()
    
    if args.command == "build":
        cmd_build(args)
    elif args.command == "verify":
        cmd_verify(args)
    elif args.command == "stats":
        cmd_stats(args)
    elif args.command == "regen":
        cmd_regen(args)


if __name__ == "__main__":
    main()