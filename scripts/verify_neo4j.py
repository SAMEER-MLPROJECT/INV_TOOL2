"""Verify AttackGraph Lens persistence against a REAL Neo4j instance.

Usage (from the repository root, with NEO4J_URI, NEO4J_USERNAME and NEO4J_PASSWORD set or in .env):

    python scripts/verify_neo4j.py            # runs every check, then deletes its own test organisation
    python scripts/verify_neo4j.py --keep     # keeps the test data so you can inspect it in Neo4j Browser

Writes data/exports/neo4j_verification.json with the result of every check. Nothing here is simulated: every
check reads back what the database actually stored.
"""
from __future__ import annotations

import argparse
import json
import secrets
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from attackgraph.config import (  # noqa: E402
    AnalysisSettings,
    DeploymentConfig,
    load_env_file,
)
from attackgraph.graph.paths import PathQuery  # noqa: E402
from attackgraph.workspace import Workspace  # noqa: E402

RESULTS: list[dict] = []


def check(name: str, ok: bool, detail: object = "") -> bool:
    RESULTS.append({"check": name, "passed": bool(ok), "detail": detail})
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  ->  {detail}" if detail != "" else ""))
    return ok


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true", help="keep the test organisation's data in Neo4j")
    args = ap.parse_args()
    load_env_file()
    deploy = DeploymentConfig(graph_backend="neo4j")
    if not deploy.neo4j_uri:
        print("Set NEO4J_URI, NEO4J_USERNAME and NEO4J_PASSWORD (or put them in .env) first.")
        return 2
    org = "verify_" + secrets.token_hex(4)
    print(f"Neo4j: {deploy.neo4j_uri.split('@')[-1]}  database={deploy.neo4j_database}  test organisation={org}\n")

    ws = Workspace(deploy, AnalysisSettings(), org_id=org)
    t0 = time.perf_counter()
    ws.open(load_sample=True)
    st = ws.backend_status()
    if not check("connect and persist the sample dataset", st["persisted"] and st["neo4j"]["connected"],
                 {"message": st["neo4j"]["message"], "server": st["neo4j"].get("server"),
                  "seconds": round(time.perf_counter() - t0, 2)}):
        return finish(org, ws, args.keep)
    check("Cypher 25 allReduce available", bool(ws.neo4j.cypher25), {"cypher25": ws.neo4j.cypher25})
    c1 = ws.neo4j.counts(org)
    check("stored evidence matches the analysis graph",
          c1["events"] == len(ws.events) and c1["entities"] == len(ws.graph.entities) and c1["incidents"] == len(ws.incidents),
          {"neo4j": c1, "engine": {"events": len(ws.events), "entities": len(ws.graph.entities), "incidents": len(ws.incidents)}})

    sample = sorted(p for p in deploy.sample_dir.iterdir() if p.suffix.lower() in {".csv", ".json", ".jsonl"})
    ws.ingest([(p.name, p.read_bytes(), None) for p in sample])
    c2 = ws.neo4j.counts(org)
    check("re-ingesting the same files creates no duplicate events", c2["events"] == c1["events"],
          {"before": c1["events"], "after": c2["events"]})

    edr = deploy.sample_dir / "edr_events.jsonl"
    first = json.loads(edr.read_text().splitlines()[0])
    first["severity"] = "low" if str(first.get("severity")) != "low" else "high"
    ws.ingest([("conflicting_copy.jsonl", (json.dumps(first) + "\n").encode(), None)])
    c3 = ws.neo4j.counts(org)
    check("a conflicting copy is stored and flagged, not overwritten", c3["conflicting"] == c2["conflicting"] + 1,
          {"conflicting_before": c2["conflicting"], "conflicting_after": c3["conflicting"]})

    ws.set_status("user:sameer", "confirmed", by="verify-script")
    before = {"events": len(ws.events), "entities": len(ws.graph.entities), "relationships": len(ws.graph.rels),
              "incidents": [(i["id"], i["priority"], i["score"]) for i in ws.incidents], "statuses": dict(ws.statuses),
              "conflicting": len(ws.conflicting)}

    restarted = Workspace(deploy, AnalysisSettings(), org_id=org)
    t1 = time.perf_counter()
    restarted.open(load_sample=False)
    after = {"events": len(restarted.events), "entities": len(restarted.graph.entities),
             "relationships": len(restarted.graph.rels),
             "incidents": [(i["id"], i["priority"], i["score"]) for i in restarted.incidents],
             "statuses": dict(restarted.statuses), "conflicting": len(restarted.conflicting)}
    check("after a restart the workspace is rebuilt from Neo4j with identical results", before == after,
          {"restored_files": restarted.neo4j_state.get("restored_files"), "seconds": round(time.perf_counter() - t1, 2),
           "before": {k: v for k, v in before.items() if k != "incidents"},
           "after": {k: v for k, v in after.items() if k != "incidents"}})

    q = PathQuery(source="user:sameer", targets=["database:FINANCE-DB"], max_hops=5)
    res = restarted.paths(q)
    chk = res.get("neo4j_check") or {}
    check("Neo4j temporal path query agrees with the reference engine", bool(chk.get("ok")) and bool(chk.get("agree")), chk)

    prov = restarted.neo4j.entity_provenance(org, "database:FINANCE-DB", limit=5)
    check("provenance: entity -> events -> source file and row", bool(prov) and all(p["sha256"] and p["row"] is not None for p in prov),
          prov[:3])
    return finish(org, restarted, args.keep)


def finish(org: str, ws: Workspace, keep: bool) -> int:
    if ws.neo4j is not None and not keep:
        try:
            ws.neo4j.clear_org(org)
            print(f"\nremoved test organisation {org}")
        except Exception as exc:  # noqa: BLE001
            print(f"\ncould not remove test organisation {org}: {type(exc).__name__}")
    out = ROOT / "data" / "exports" / "neo4j_verification.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    passed = sum(r["passed"] for r in RESULTS)
    out.write_text(json.dumps({"run_at": datetime.now(timezone.utc).isoformat(), "organisation": org,
                               "passed": passed, "total": len(RESULTS), "checks": RESULTS}, indent=2, default=str))
    print(f"\n{passed}/{len(RESULTS)} checks passed. Report: {out}")
    return 0 if RESULTS and passed == len(RESULTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
