"""Pre-fill the fields Indian regulators ask for after a cyber incident, from the evidence graph.

Every field carries the event ids it was derived from. Fields the graph cannot know (the reporting officer,
actions already taken outside the tool) are marked "officer to complete" instead of being guessed. Nothing is
submitted anywhere: this is a draft for a human to review and sign.

Field lists follow the CERT-In incident reporting form, the RBI cyber security incident reporting (CSIR) form
annexed to RBI's IT framework directions for NBFCs, and DPDP Rules 2025 rule 7 (detailed report to the Data
Protection Board within 72 hours; in force from 13 May 2027).
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from .graph.builder import TemporalGraph
from .models import EntityType, RelType

CERTIN_DEADLINE = timedelta(hours=6)
DPDP_DEADLINE = timedelta(hours=72)
DPDP_IN_FORCE = datetime(2027, 5, 13, tzinfo=UTC)
OFFICER = "officer to complete"

# CERT-In Directions (28 April 2022), Annexure I categories, suggested from MITRE ATT&CK technique prefixes.
TECHNIQUE_TO_CERTIN = {
    "T1110": "Unauthorised access of IT systems/data",
    "T1078": "Unauthorised access of IT systems/data",
    "T1021": "Unauthorised access of IT systems/data",
    "T1003": "Compromise of critical systems/information",
    "T1543": "Compromise of critical systems/information",
    "T1059": "Malicious code attacks",
    "T1071": "Malicious code attacks",
    "T1105": "Malicious code attacks",
    "T1213": "Attacks on servers such as database, mail and DNS",
    "T1005": "Data breach",
    "T1530": "Data breach",
    "T1041": "Data leak",
    "T1048": "Data leak",
    "T1567": "Data leak",
    "T1595": "Targeted scanning/probing of critical networks/systems",
    "T1046": "Targeted scanning/probing of critical networks/systems",
}


def _field(value, evidence: list[str] | None = None, basis: str = "derived from the evidence graph") -> dict:
    return {"value": value, "evidence": sorted(set(evidence or []))[:50], "basis": basis}


def _bucket(n: int) -> str:
    return "1 to 10" if n <= 10 else ("10 to 100" if n <= 100 else "More than 100")


def clock(incident: dict, now: datetime | None = None) -> dict:
    now = now or datetime.now(UTC)
    alerts = sorted(incident.get("alerts") or [], key=lambda a: a["timestamp"])
    detected = datetime.fromisoformat(alerts[0]["timestamp"]) if alerts else datetime.fromisoformat(incident["start"])
    due = detected + CERTIN_DEADLINE
    remaining = (due - now).total_seconds()
    return {"detected_at": detected.isoformat(), "detected_by": alerts[0]["uid"] if alerts else None,
            "basis": "first alert in the incident" if alerts else "first correlated event (no alert)",
            "certin_due": due.isoformat(), "certin_remaining_seconds": round(remaining),
            "certin_status": "open" if remaining > 0 else "deadline passed",
            "dpdp_detailed_report_due": (detected + DPDP_DEADLINE).isoformat(),
            "dpdp_applies": detected >= DPDP_IN_FORCE,
            "note": "Deadlines run from when the incident was noticed. The first alert is used as a proxy; the reporting "
                    "officer must confirm the actual time of notice."}


def regulatory_draft(g: TemporalGraph, incident: dict, org_name: str, containment: dict | None,
                     statuses: dict[str, str], files: list[dict]) -> dict:
    ents = incident["entities"]
    support = list(incident["supporting_events"])
    alerts = incident.get("alerts") or []

    categories: dict[str, list[str]] = {}
    for a in alerts:
        tech = (a.get("technique") or "").split(".")[0]
        cat = TECHNIQUE_TO_CERTIN.get(tech)
        if cat:
            categories.setdefault(cat, []).append(a["uid"])
    first_ev = min((g.events[u] for u in support if u in g.events), key=lambda e: e.timestamp, default=None)

    systems = []
    for eid in ents.get("host", []) + ents.get("database", []) + ents.get("service", []):
        e = g.entities.get(eid)
        if e is None:
            continue
        uids = sorted(set(g.entity_events.get(eid, ())) & set(support))
        systems.append({"id": eid, "name": e.name, "type": e.type.value, "criticality": e.criticality,
                        "analyst_status": statuses.get(eid), "evidence": uids[:10]})
    systems.sort(key=lambda s: (-s["criticality"], s["name"]))
    hosts = [s for s in systems if s["type"] == "host"]

    locations: dict[str, list[str]] = {}
    for s in systems:
        inv_loc = g.entities[s["id"]].attributes.get("location")
        if inv_loc:
            locations.setdefault(f"{inv_loc} (asset inventory)", [])
        for _, tgt, d in g.g.out_edges(s["id"], data=True):
            rel = g.rels[d["rel_id"]]
            if rel.type == RelType.LOCATED_IN:
                locations.setdefault(g.entities[tgt].name, []).extend(o.event_uid for o in rel.occurrences)

    indicators, ioc_ev = [], []
    for eid in ents.get("ip", []) + ents.get("domain", []):
        e = g.entities.get(eid)
        if e and (e.type == EntityType.DOMAIN or e.category == "external"):
            indicators.append(e.name)
            ioc_ev += sorted(set(g.entity_events.get(eid, ())) & set(support))[:5]

    data_access, data_ev = [], []
    for u in support:
        ev = g.events.get(u)
        if ev and ev.category == "db_access":
            rows = ev.raw.get("rows_returned")
            data_access.append(f"{ev.action} on {ev.database} by {ev.user or 'unknown'} from {ev.src_host}"
                               + (f", {rows} rows" if rows not in (None, "") else ""))
            data_ev.append(u)

    confirmed = sorted(k for k, v in statuses.items() if v == "confirmed")
    plan = (containment or {}).get("plan") or []
    recommended = [f"{p['action']['label']} (path risk -{p['risk_reduction_pct']}%)" for p in plan]

    clk = clock(incident)
    types_value = sorted(categories) or ["Other: no alert technique maps to a CERT-In category; officer to classify"]
    common = {
        "organisation": _field(org_name, basis="the signed-in organisation"),
        "reporting_officer": _field(OFFICER, basis="name, designation, phone and e-mail of the officer filing the report"),
        "incident_types": _field(types_value, [u for v in categories.values() for u in v],
                                 "suggested from alert ATT&CK techniques; officer to confirm"),
        "occurred_at": _field(first_ev.timestamp.isoformat() if first_ev else incident["start"],
                              [first_ev.uid] if first_ev else [], "earliest correlated event"),
        "detected_at": _field(clk["detected_at"], [clk["detected_by"]] if clk["detected_by"] else [], clk["basis"]),
        "affected_systems": _field([f"{s['name']} ({s['type']}, criticality {s['criticality']})" for s in systems],
                                   [u for s in systems for u in s["evidence"]]),
        "affected_host_count": _field(_bucket(len(hosts)), [u for s in hosts for u in s["evidence"]],
                                      f"{len(hosts)} host(s) in the incident"),
        "affected_accounts": _field([g.entities[u].name for u in ents.get("user", []) if u in g.entities],
                                    [u for eid in ents.get("user", []) for u in sorted(set(g.entity_events.get(eid, ())) & set(support))[:3]]),
        "physical_location": _field(sorted(locations) or ["not recorded by any edge sensor; officer to complete"],
                                    [u for v in locations.values() for u in v],
                                    "asset inventory and edge sensor LOCATED_IN evidence" if locations else OFFICER),
        "symptoms": _field(sorted({a["rule"] for a in alerts}), [a["uid"] for a in alerts], "alert names"),
        "indicators_of_compromise": _field(sorted(set(indicators)) or ["none external in the evidence"], ioc_ev),
        "data_accessed": _field(data_access or ["no database access in the incident evidence"], data_ev,
                                "database audit events; whether personal data was involved is for the officer to assess"),
        "actions_taken": _field(([f"analyst confirmed compromise of {', '.join(confirmed)}"] if confirmed else [])
                                + ["officer to list actions already taken"], [],
                                "analyst verdicts recorded in AttackGraph Lens"),
        "recommended_containment": _field(recommended or ["no containment plan computed"], [],
                                          "simulated by AttackGraph Lens; advisory, not executed"),
    }
    forms = {
        "cert_in": {"title": "CERT-In incident report (within 6 hours of notice)", "deadline": clk["certin_due"],
                    "fields": ["organisation", "reporting_officer", "incident_types", "occurred_at", "detected_at",
                               "physical_location", "affected_systems", "affected_host_count", "symptoms",
                               "indicators_of_compromise", "actions_taken"]},
        "rbi_csir": {"title": "RBI cyber security incident reporting (CSIR) form, NBFC", "deadline": None,
                     "fields": ["organisation", "reporting_officer", "detected_at", "incident_types", "affected_systems",
                                "data_accessed", "actions_taken", "recommended_containment"]},
        "dpdp_72h": {"title": "DPDP Rules 2025, rule 7: detailed report to the Data Protection Board",
                     "deadline": clk["dpdp_detailed_report_due"],
                     "applies": clk["dpdp_applies"],
                     "fields": ["organisation", "reporting_officer", "occurred_at", "detected_at", "physical_location",
                                "data_accessed", "affected_accounts", "actions_taken", "recommended_containment"]},
    }
    used = sorted({u for f in common.values() for u in f["evidence"]})
    srcs = sorted({g.events[u].source_file for u in used if u in g.events})
    return {"incident": incident["id"], "title": incident["title"], "priority": incident["priority"], "clock": clk,
            "fields": common, "forms": forms,
            "evidence_files": [{"file_name": f["file_name"], "sha256": f["sha256"]} for f in files if f["file_name"] in srcs],
            "status": "DRAFT for human review. Nothing has been submitted to any regulator.",
            "sources": ["CERT-In Directions under section 70(B)(6) of the IT Act, 28 April 2022",
                        "RBI CSIR form, annex to the Master Direction on IT Framework for the NBFC sector",
                        "Digital Personal Data Protection Rules 2025, rule 7 (notified 13 November 2025)"]}
