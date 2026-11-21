"""Rank competing explanations of an incident (Analysis of Competing Hypotheses, ACH).

For each incident we derive *indicators* from its evidence (alerts by ATT&CK technique, authentication failures, data
volume, hosts involved ...). Every hypothesis states which indicators support it, which contradict it, and which it
expects to see. The score rewards support, penalises contradiction more heavily (ACH: evidence that is inconsistent
with a hypothesis is more diagnostic than evidence that fits several), and penalises a hypothesis whose key evidence is
absent. Scores are relative support, not probabilities; every number links to the events behind it.
"""
from __future__ import annotations

from dataclasses import dataclass

from .graph.builder import TemporalGraph
from .models import EntityType, RelType

CONTRADICTION_WEIGHT = 1.5
MISSING_KEY_PENALTY = 3.0
METHOD = ("Analysis of Competing Hypotheses: support minus 1.5 x contradiction, minus 3 when a hypothesis's key evidence "
          "is absent. Relative support, not a probability.")


@dataclass(frozen=True)
class Indicator:
    id: str
    label: str
    techniques: tuple[str, ...] = ()


INDICATORS = [
    Indicator("user_exec", "Program launched by a user from a download or temp folder", ("T1204",)),
    Indicator("tool_download", "Executable downloaded over the network", ("T1105", "T1608")),
    Indicator("c2", "Command-and-control style traffic", ("T1071", "T1095", "T1573")),
    Indicator("discovery", "Discovery commands (whoami, systeminfo, tasklist ...)", ("T1082", "T1033", "T1057", "T1016", "T1087", "T1482")),
    Indicator("persistence", "New service or persistence mechanism", ("T1543", "T1053", "T1547")),
    Indicator("proxy_exec", "Signed binary proxy execution (rundll32 etc.)", ("T1218",)),
    Indicator("injection", "Code injection into another process", ("T1055",)),
    Indicator("credential_dump", "Credential dumping from LSASS or the SAM", ("T1003",)),
    Indicator("scripting", "Malicious script execution (PowerShell etc.)", ("T1059",)),
    Indicator("exfil", "Large outbound transfer / exfiltration", ("T1041", "T1048", "T1567")),
    Indicator("brute_force", "Repeated failed logons", ("T1110",)),
    Indicator("valid_accounts", "Use of a valid account in an unusual way", ("T1078",)),
    Indicator("lateral", "Movement to other hosts", ("T1021", "T1570", "T1550")),
    Indicator("data_collection", "Bulk access to data stores", ("T1213", "T1005", "T1530", "T1039")),
    Indicator("physical", "Physical event on an involved host (USB, console)", ()),
    Indicator("external", "Contact with an external address", ()),
]
IND = {i.id: i for i in INDICATORS}


@dataclass(frozen=True)
class Hypothesis:
    id: str
    title: str
    narrative: str
    supports: dict[str, float]
    contradicts: dict[str, float]
    key: tuple[str, ...]


HYPOTHESES = [
    Hypothesis("H1", "External attacker: malware foothold, then credential theft",
               "A user ran a malicious program; it called back to an attacker, who explored the host, escalated and "
               "dumped credentials from memory.",
               {"user_exec": 2, "tool_download": 1, "c2": 2, "discovery": 1, "persistence": 1, "proxy_exec": 1,
                "injection": 2, "credential_dump": 3, "scripting": 1, "exfil": 1},
               {}, ("credential_dump", "c2")),
    Hypothesis("H2", "Stolen credentials used to move laterally and take data",
               "Valid credentials (guessed or stolen) were used to log on to further hosts and reach data stores.",
               {"valid_accounts": 2, "brute_force": 1, "lateral": 3, "data_collection": 2, "exfil": 2, "credential_dump": 1},
               {}, ("lateral",)),
    Hypothesis("H3", "Insider misuse of legitimate access",
               "Someone with legitimate access collected and moved data without malware or exploitation.",
               {"data_collection": 3, "exfil": 2, "valid_accounts": 1},
               {"user_exec": 2, "c2": 2, "injection": 3, "tool_download": 2, "brute_force": 1, "credential_dump": 1},
               ("data_collection",)),
    Hypothesis("H4", "Password guessing against accounts",
               "An attacker tried passwords until one worked; no host compromise is implied.",
               {"brute_force": 3, "valid_accounts": 1},
               {"injection": 1}, ("brute_force",)),
    Hypothesis("H5", "Commodity malware without hands-on activity",
               "Automated malware infected the host and beaconed out, but no human operator explored or stole credentials.",
               {"user_exec": 2, "c2": 2, "tool_download": 1, "scripting": 1},
               {"discovery": 1, "credential_dump": 2, "persistence": 1, "lateral": 2}, ("c2",)),
    Hypothesis("H6", "Authorised administration or security testing (benign)",
               "The activity is an administrator or an authorised test using system tools.",
               {"discovery": 1},
               {"c2": 3, "injection": 3, "user_exec": 2, "tool_download": 2, "persistence": 2, "exfil": 2,
                "credential_dump": 1, "proxy_exec": 1}, ("discovery",)),
]


def _indicators(g: TemporalGraph, inc: dict) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {i.id: [] for i in INDICATORS}
    support = set(inc["supporting_events"]) | {a["uid"] for a in inc.get("alerts") or []}
    for a in inc.get("alerts") or []:
        tech = (a.get("technique") or "").split(".")[0]
        for ind in INDICATORS:
            if tech and tech in ind.techniques:
                found[ind.id].append(a["uid"])
    fails = [u for u in support if u in g.events and g.events[u].category == "authentication" and g.events[u].outcome != "success"]
    if len(fails) >= 5:
        found["brute_force"].extend(fails[:10])
    for u in support:
        ev = g.events.get(u)
        if ev is None:
            continue
        if ev.category == "db_access" and (ev.raw.get("rows_returned") not in (None, "") and
                                           str(ev.raw.get("rows_returned")).isdigit() and int(ev.raw["rows_returned"]) >= 1000):
            found["data_collection"].append(u)
        if ev.category == "physical" or ev.source_system == "edge_physical":
            found["physical"].append(u)
    hosts = set(inc["entities"].get("host", []))
    if len(hosts) >= 2:
        for r in g.rels.values():
            if r.type in (RelType.AUTHENTICATED_TO, RelType.CONNECTED_TO) and r.source in hosts | set(inc["entities"].get("user", [])) \
                    and r.target in hosts and r.source != r.target:
                found["lateral"].extend(o.event_uid for o in r.occurrences[:3] if o.event_uid in support)
    for eid in inc["entities"].get("ip", []):
        ent = g.entities.get(eid)
        if ent and ent.type == EntityType.IP and ent.category == "external":
            found["external"].extend(sorted(set(g.entity_events.get(eid, ())) & support)[:3])
    return {k: sorted(set(v))[:12] for k, v in found.items()}


def rank(g: TemporalGraph, inc: dict) -> dict:
    ind = _indicators(g, inc)
    present = {k for k, v in ind.items() if v}
    out = []
    for h in HYPOTHESES:
        sup = [{"indicator": k, "label": IND[k].label, "weight": w, "evidence": ind[k][:6]} for k, w in h.supports.items() if k in present]
        con = [{"indicator": k, "label": IND[k].label, "weight": w, "evidence": ind[k][:6]} for k, w in h.contradicts.items() if k in present]
        missing = [{"indicator": k, "label": IND[k].label} for k in h.supports if k not in present]
        key_missing = not any(k in present for k in h.key)
        score = sum(s["weight"] for s in sup) - CONTRADICTION_WEIGHT * sum(c["weight"] for c in con) - (MISSING_KEY_PENALTY if key_missing else 0)
        out.append({"id": h.id, "title": h.title, "narrative": h.narrative, "score": round(score, 1),
                    "supporting": sup, "contradicting": con, "missing": missing, "key_evidence_missing": key_missing})
    out.sort(key=lambda x: (-x["score"], len(x["contradicting"])))
    positive = sum(max(0.0, x["score"]) for x in out) or 1.0
    for i, x in enumerate(out):
        x["rank"] = i + 1
        x["relative_support_pct"] = round(100 * max(0.0, x["score"]) / positive)
        x["assessment"] = ("best supported" if i == 0 and x["score"] > 0 else
                           "inconsistent with the evidence" if x["contradicting"] and x["score"] < 0 else
                           "plausible" if x["score"] > 0 else "not supported")
    top = out[0]
    gap = top["score"] - (out[1]["score"] if len(out) > 1 else 0)
    next_checks = [m["label"] for m in top["missing"]][:4]
    if top["score"] <= 0:
        wanted = []
        for h in out[:3]:
            wanted += [m["label"] for m in h["missing"] if m["label"] not in wanted]
        return {"incident": inc["id"], "indicators": {k: {"label": IND[k].label, "evidence": v} for k, v in ind.items() if v},
                "hypotheses": out, "leading": None, "margin": 0.0,
                "summary": "No explanation is supported yet: the evidence is too thin to prefer one hypothesis.",
                "next_checks": wanted[:5], "method": METHOD}
    return {"incident": inc["id"], "indicators": {k: {"label": IND[k].label, "evidence": v} for k, v in ind.items() if v},
            "hypotheses": out, "leading": top["id"], "margin": round(gap, 1),
            "summary": (f"{top['title']} is best supported ({top['score']:+.1f}, {len(top['supporting'])} supporting "
                        f"indicators, {len(top['contradicting'])} contradicting), ahead of {out[1]['title'].lower()} by "
                        f"{gap:.1f}." if len(out) > 1 else top["title"]),
            "next_checks": next_checks,
            "method": METHOD}
