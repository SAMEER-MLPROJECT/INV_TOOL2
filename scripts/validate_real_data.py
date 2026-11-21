"""Run AttackGraph Lens on a real recorded attack and compare its findings with the dataset's published ground truth.

Dataset: OTRF Security-Datasets, compound/LSASS_campaign_03 (MIT licence). Host logs (Windows Security, Sysmon,
PowerShell, System), Zeek network logs and a packet capture of the same attack. Ground truth: the ATT&CK techniques
listed in the dataset's metadata file, written by the people who ran the attack.

    python scripts/validate_real_data.py            # writes docs/REAL_DATA_VALIDATION.md and data/exports/real_validation.json
"""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from attackgraph.config import AnalysisSettings, DeploymentConfig  # noqa: E402
from attackgraph.graph.paths import PathQuery  # noqa: E402
from attackgraph.workspace import Workspace  # noqa: E402

DATA = ROOT / "data" / "real" / "otrf_lsass_campaign_03"
NOT_OBSERVABLE = {"TA0042": "resource development happens on the attacker's own systems, before the attack; no host or "
                            "network log of the victim can show it"}


def ground_truth() -> list[dict]:
    meta = yaml.safe_load((DATA / "ground_truth_metadata.yaml").read_text())
    out = []
    for m in meta.get("attack_mappings") or []:
        sub = m.get("sub-technique")
        tid = m["technique"] + (f".{sub}" if sub else "")
        tactics = m.get("tactics") or []
        out.append({"technique": tid, "tactics": tactics, "observable": not any(t in NOT_OBSERVABLE for t in tactics)})
    return out


def main() -> int:
    deploy = DeploymentConfig(neo4j_uri=None, graph_backend="memory")
    ws = Workspace(deploy, AnalysisSettings())
    t0 = time.perf_counter()
    files = ws.load_real()
    secs = time.perf_counter() - t0
    g = ws.graph
    alerts = sorted((e for e in g.events.values() if e.category == "alert"), key=lambda e: e.timestamp)
    detected: dict[str, list] = {}
    for a in alerts:
        detected.setdefault(a.technique, []).append(a)

    gt = ground_truth()
    rows = []
    for t in gt:
        base = t["technique"].split(".")[0]
        hits = [a for tech, al in detected.items() if tech and tech.split(".")[0] == base for a in al]
        rows.append({**t, "detected": bool(hits), "first_seen": hits[0].timestamp.isoformat() if hits else None,
                     "rule": hits[0].facts.get("rule_id") if hits else None, "why": hits[0].facts.get("why") if hits else None,
                     "evidence": hits[0].facts.get("matched_event") if hits else None})
    observable = [r for r in rows if r["observable"]]
    caught = [r for r in observable if r["detected"]]
    gt_bases = {r["technique"].split(".")[0] for r in rows}
    extra = sorted({a.technique for a in alerts if a.technique.split(".")[0] not in gt_bases})

    incs = ws.incidents
    top = incs[0] if incs else None
    hyp = ws.hypotheses(top["id"]) if top else None
    path = ws.paths(PathQuery(source="user:pedro.gustavo", targets=["process:PRD01/lsass.exe"], max_hops=6))
    host_file = next(f for f in files if f["source_system"] == "windows_events")
    clock_note = next((n for n in host_file["format_notes"] if n.startswith("clock corrected")), None)
    exfil = [a for a in alerts if a.facts.get("rule_id") == "AGL-D12"]

    checks = {
        "every file accepted with no rejected records": all(f["rejected"] == 0 for f in files),
        "host clock error found and corrected (7 h)": bool(clock_note and "7:00:00" in clock_note),
        "network evidence joined to the host (192.168.1.42 -> PRD01)": g.ip_to_host.get("192.168.1.42") == "host:PRD01",
        f"all {len(observable)} observable ground-truth techniques detected": len(caught) == len(observable),
        "a single High or Critical incident": len(incs) == 1 and top["priority"] in {"High", "Critical"},
        "leading hypothesis is the external attacker with credential theft (H1)": bool(hyp and hyp["leading"] == "H1"),
        "benign administration is ruled out (negative score)": bool(hyp and next(h for h in hyp["hypotheses"] if h["id"] == "H6")["score"] < 0),
        "exfiltration over the C2 channel found in the packet capture (> 50 MB)": any("MB sent" in a.facts["why"] and
                                                                                     float(a.facts["why"].split(" MB")[0]) > 50 for a in exfil),
        "time-ordered path from the user to LSASS": path["total_valid_paths"] > 0,
    }
    report = {"run_at": datetime.now(timezone.utc).isoformat(), "seconds": round(secs, 2),
              "files": [{k: f[k] for k in ("file_name", "source_system", "records_read", "accepted", "rejected", "filtered",
                                           "detections", "format_notes")} for f in files],
              "events": len(g.events), "entities": len(g.entities), "relationships": len(g.rels),
              "ground_truth": rows, "observable_detected": f"{len(caught)}/{len(observable)}", "extra_techniques": extra,
              "incidents": [{k: i[k] for k in ("id", "priority", "score", "title")} for i in incs],
              "hypotheses": hyp, "path_count": path["total_valid_paths"],
              "path_example": path["paths"][0]["nodes"] if path["paths"] else None,
              "alerts": [{"time": a.timestamp.isoformat(), "rule": a.facts["rule_id"], "technique": a.technique,
                          "why": a.facts["why"], "evidence": a.facts["matched_event"]} for a in alerts],
              "checks": checks}
    out = ROOT / "data" / "exports" / "real_validation.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, default=str))
    write_markdown(report)
    for name, ok in checks.items():
        print(f"[{'PASS' if ok else 'FAIL'}] {name}")
    print(f"\n{sum(checks.values())}/{len(checks)} checks passed in {secs:.1f} s. Report: docs/REAL_DATA_VALIDATION.md")
    return 0 if all(checks.values()) else 1


def write_markdown(r: dict) -> None:
    L = ["# Real-data validation: OTRF LSASS_campaign_03", "",
         f"Generated by `scripts/validate_real_data.py` on {r['run_at'][:16]} UTC. Processing time: {r['seconds']} s.", "",
         "**Dataset.** A real attack recorded by the Open Threat Research Forge: a user runs a Metasploit payload, the operator "
         "explores the host, escalates through a service, injects into memory, dumps LSASS with `comsvcs.dll` and pulls the dump "
         "back over the command channel. Host logs (Security, Sysmon, PowerShell, System), Zeek logs and a packet capture of the "
         "same attack. MIT licence; provenance and hashes in `data/real/otrf_lsass_campaign_03/PROVENANCE.json`.", "",
         "**Ground truth.** The ATT&CK techniques listed in the dataset's own metadata file, written by the people who ran it.", "",
         "## Checks", ""]
    L += [f"- {'✅' if ok else '❌'} {name}" for name, ok in r["checks"].items()]
    L += ["", "## Ground truth vs detections", "",
          f"Observable techniques detected: **{r['observable_detected']}**.", "",
          "| Technique | Observable in victim logs | Detected | First seen (UTC) | Rule | Why |", "|---|---|---|---|---|---|"]
    for g in r["ground_truth"]:
        obs = "yes" if g["observable"] else "no (resource development)"
        L.append(f"| {g['technique']} | {obs} | {'yes' if g['detected'] else 'no'} | {(g['first_seen'] or '')[11:19]} | "
                 f"{g['rule'] or ''} | {(g['why'] or '').replace('|', '/')[:110]} |")
    L += ["", f"Also detected, not in the published mapping: {', '.join(r['extra_techniques']) or 'none'}. These are real "
          "activity in the recording (payload download, command channel, rundll32 service launch, PowerShell stagers), "
          "not counted as hits.", "", "## Files", "",
          "| File | Read as | Records | Used | Filtered (with reasons) | Rejected | Detections |", "|---|---|---|---|---|---|---|"]
    for f in r["files"]:
        L.append(f"| {f['file_name']} | {f['source_system']} | {f['records_read']} | {f['accepted']} | {f['filtered']} | "
                 f"{f['rejected']} | {f['detections']} |")
    notes = [n for f in r["files"] for n in f["format_notes"] if "clock" in n or "packet capture" in n]
    L += ["", *[f"- {n}" for n in notes], "", "## Incident and hypotheses", ""]
    for i in r["incidents"]:
        L.append(f"- **{i['id']}** {i['priority']} ({i['score']}): {i['title']}")
    h = r["hypotheses"]
    if h:
        L += ["", h["summary"], "", "| Rank | Hypothesis | Score | Supporting | Contradicting |", "|---|---|---|---|---|"]
        for x in h["hypotheses"]:
            L.append(f"| {x['rank']} | {x['title']} | {x['score']:+.1f} | {len(x['supporting'])} | {len(x['contradicting'])} |")
    L += ["", f"Time-ordered paths from `user:pedro.gustavo` to LSASS on PRD01: {r['path_count']}.",
          f"Example: {' → '.join(r['path_example'] or [])}", "", "## Detection timeline", "",
          "| Time (UTC) | Rule | Technique | Why |", "|---|---|---|---|"]
    for a in r["alerts"]:
        L.append(f"| {a['time'][11:19]} | {a['rule']} | {a['technique']} | {a['why'].replace('|', '/')[:120]} |")
    L += ["", "## Limits", "", "- One recorded attack on one host. This shows the pipeline works on real telemetry; it is not a "
          "precision/recall measurement, which would need many labelled incidents and benign periods.",
          "- One known false positive is visible above: a `systeminfo` run at 16:03 by Windows' own network diagnostics script.",
          "- Memory forensics (Volatility 3 output) is supported but this dataset contains no memory image."]
    (ROOT / "docs" / "REAL_DATA_VALIDATION.md").write_text("\n".join(L) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
