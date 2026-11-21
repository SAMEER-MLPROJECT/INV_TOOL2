# AttackGraph Lens: finale build report (hackFront India Grand Finale, 21–22 November 2026)

Team EigenThinkers · T2.1 GraphOps · partner technology: Neo4j and Arduino UNO Q.
State as of 21 November, about 18:00 IST. Everything marked "tested" was run in the development environment; items that
need the team's own accounts or hardware are marked as such.

## A. Architecture

```
 EVIDENCE IN (upload, push API, signed edge devices)
   Windows event logs (Security, Sysmon, System, PowerShell) as JSON/JSONL
   Zeek logs (conn, dns, http, files, kerberos) · packet captures (PCAP/PCAPNG, analysed in-app)
   Volatility 3 memory-forensics output (pslist, cmdline, netscan, malfind)
   SIEM/IdP/EDR/firewall/DNS/DB-audit exports (CSV/JSON) · Arduino UNO Q edge events (HMAC + hash chain)
        │
        ▼
 1. FORMAT LAYER       Zeek TSV parser · PCAP flow/DNS/HTTP analyser (no payloads kept) · Volatility row flattener
 2. NORMALISERS        one adapter per source → common event model (raw record kept unchanged, parsed facts beside it)
                       noise is *filtered with a counted reason*, malformed rows are *rejected with a reason*
 3. ALIGNMENT          per-file clock correction (e.g. Windows TimeCreated vs Sysmon UtcTime) · IP→host learning so
                       network-only evidence joins the right machine · duplicate / conflict handling (both copies kept)
 4. DETECTION          14 ATT&CK-mapped rules (AGL-D01…D14); each alert cites the event it matched and why
 5. EVIDENCE GRAPH     NetworkX temporal graph (reference analysis) + Neo4j persistent store (per organisation)
 6. ANALYSIS           correlation → incidents · time-respecting attack paths · blast radius · containment what-if
                       · competing-hypothesis ranking (ACH) · regulator-ready draft · CERT-In clock
        │
        ▼
 PEOPLE OUT            SOC analyst (incidents, paths, hypotheses, report) · IT admin (infrastructure view)
                       CISO (regulator draft) · every number links back to file, row and raw record
```

Why hybrid: the temporal engine is tested and explains rejected routes; rewriting it in Cypher in 22 hours would risk
regressions. Neo4j holds the evidence permanently, is the source of truth after a restart, and answers path and
provenance queries that the UI shows next to the engine's results.

## B. Feature completion matrix

| Feature | Status | Evidence |
|---|---|---|
| Sign-in, sign-out, sessions, roles (analyst, IT admin, viewer) | Implemented and tested | `tests/test_auth.py`, `tests/test_e2e_auth.py` |
| Self-service organisation sign-up; organisations isolated from each other | Implemented and tested | same |
| Sign-in throttling per account and per client; CSRF header; security headers | Implemented and tested | same |
| Primary SOC analyst journey end to end in the browser | Implemented and tested | `test_e2e_auth.py::test_analyst_journey_end_to_end` |
| IT infrastructure admin journey (assets by tier and room, device events, containment, summary) | Implemented and tested | `test_e2e_auth.py::test_it_admin_journey_and_role_limits` |
| Regulator-ready draft: CERT-In, RBI CSIR, DPDP rule 7 fields with evidence links | Implemented and tested | `test_auth.py::test_regulatory_admin_clock_and_measured_timing` |
| CERT-In 6-hour clock; measured time from opening an incident to its first report | Implemented and tested | same |
| Conflicting records kept and flagged instead of discarded | Implemented and tested | `test_persistence.py::test_conflicting_copy_is_kept_and_flagged` |
| Neo4j write-through, no duplicates, outage reporting and recovery, restore after restart | Implemented and tested against an in-memory store with the same key rules | `tests/test_persistence.py` |
| Neo4j Cypher (parameterised, org-scoped, no wipe on sync, allReduce query shape) | Implemented and tested at driver level | `tests/test_neo4j_adapter.py` |
| **Neo4j against a real instance** | **Implemented, not yet run** (this environment cannot reach Neo4j) | run `python scripts/verify_neo4j.py`; report in `data/exports/neo4j_verification.json` |
| Signed, hash-chained edge envelopes; replay, clock, gap, chain and location-spoofing checks | Implemented and tested | `tests/test_edge.py` |
| UNO Q agent (USB, logins, self-test, heartbeat) | Implemented; tested against a live server with a simulated USB tree | see `edge/unoq/README.md` |
| **UNO Q agent on the physical board; LED matrix sketch** | **Implemented, not yet run on hardware** | test at the venue |
| Heterogeneous upload: Windows/Sysmon JSON, Zeek logs, PCAP/PCAPNG, Volatility 3 memory output | Implemented and tested | `tests/test_formats.py`, `tests/test_real_data.py`, browser test uploads a PCAP |
| Noise filtering with counted reasons; per-file clock correction; IP→host learning | Implemented and tested on real data | `tests/test_real_data.py` |
| 14 ATT&CK-mapped detection rules, each citing its evidence | Implemented and tested | `backend/attackgraph/detections.py` |
| Competing-hypothesis ranking (ACH) in the incident view and reports | Implemented and tested | `tests/test_real_data.py::test_incident_hypotheses_and_path` |
| **Works on real data**: OTRF LSASS_campaign_03 (real recorded attack) | **9/9 checks pass; 8/8 observable ground-truth techniques detected** | `scripts/validate_real_data.py`, `docs/REAL_DATA_VALIDATION.md` |
| Memory forensics on a real memory image | Format supported; **not demonstrated on real memory** (the dataset has none) | `tests/test_formats.py` uses format fixtures |
| Webcam person presence | Not implemented (stretch; event type reserved) | |
| Live public URL | Configured (`render.yaml`, Dockerfile), **not yet deployed** | needs the team's Render or Railway account |
| ArgosX baseline and final scans | **Pending** | `docs/ARGOSX_REMEDIATION_LOG.md` |
| Customer interviews (3 Customer Test) | **Pending**; script and template ready | `docs/CUSTOMER_DISCOVERY.md` |
| Multi-client MSSP console | Planned | organisation isolation is the foundation |

## C. Demonstration

**Real data in one click:** Settings & Data → **Load real attack data (OTRF)**, then Incidents → *Competing hypotheses*.
To show heterogeneous upload, upload `data/real/otrf_lsass_campaign_03/capture_headers_only.pcap` and the `.log` files
through the normal upload form, or the original 57 MB `.pcapng` from the OTRF repository.

Local: `./scripts/run_local.sh` (or the Dockerfile) with `AGL_DEMO_PASSWORD=<something>` and
`AGL_SHOW_DEMO_LOGINS=1` in `.env`. Hosted: Render blueprint `render.yaml`.

1. **SOC analyst**: sign in as `analyst`. Follow the guided tour: top incident (6-hour clock, measured timing) →
   Attack Paths (`user:sameer` → `database:FINANCE-DB`; the Neo4j cross-check line appears when Neo4j is connected) →
   Blast Radius → containment at 20:41 vs 21:10 → Regulator report → download HTML.
2. **IT admin**: sign in as `itadmin`. Infrastructure: FINANCE-DB and SRV-APP-02 suspected, all in Server room A;
   containment options; physical events. Note that Clear data and device registration are refused for this role.
3. **Neo4j persistence**: with `AGL_GRAPH_BACKEND=neo4j`, the top bar shows "Neo4j: persisted". Restart the service;
   Settings shows "Restored at start: N source files reloaded from Neo4j" and the same incidents. In Neo4j Browser:
   `MATCH (e:Event {org:'org_demo_nbfc'})-[:FROM_FILE]->(f) RETURN f.name, count(e)`.
4. **UNO Q**: plug an unknown USB stick into the hub. Within about a second it appears on the Infrastructure page
   ("same room as incident assets"), in Evidence (source `edge_physical`, `signature: verified`) and in the graph
   as `PLUGGED_INTO`. Re-send an old envelope with curl to show the 409 replay rejection.
5. **Report export**: Regulator report → HTML. The file lists every field, its evidence ids, the source files with
   SHA-256, and the measured time from opening the incident to the first report.
6. **Isolation**: sign in as `client-b`. The workspace is empty; nothing from the demo NBFC is visible.

## D. Validation evidence (21 November)

* `pytest`: **148 passed, 0 failed, 0 skipped**, including 11 browser tests in Chrome.
* Real data (OTRF LSASS_campaign_03, MIT licence): 41,954 host events + Zeek logs + 12,238-packet capture processed in
  under 2 s; 7-hour clock error corrected automatically; 8/8 observable ground-truth techniques detected; leading
  hypothesis "external attacker, malware foothold then credential theft"; 56.8 MB exfiltration found only in the capture.
  Full report: `docs/REAL_DATA_VALIDATION.md`.
* Baseline before the finale changes: 99 passed, 6 skipped (browser tests could not run then).
* `ruff` (CI rule set): clean. `tsc` strict build: clean. `pip-audit`: 0 known vulnerabilities. `npm audit`: 0.
  `bandit -ll`: no medium or high findings.
* Neo4j against a real instance: **pending** (`scripts/verify_neo4j.py`).
* UNO Q on hardware: **pending**. Agent ↔ server verified with a simulated USB tree.
* ArgosX: **pending**. Customer interviews: **pending**.

## E. Remaining limitations

* One real recorded attack plus the synthetic sample. This shows the pipeline works on real telemetry; it is not a
  precision/recall measurement, which needs many labelled incidents and benign periods.
* Users, sessions and device keys live in SQLite on the app host. On hosts without a persistent disk, sign-ups are lost
  on restart (demo accounts and `AGL_EDGE_DEVICES` devices are re-created with stable ids, so their Neo4j data is
  found again).
* One process per deployment: workspaces are held in memory per organisation and rebuilt from Neo4j at start.
* Device secrets are stored server-side in plain text (needed for HMAC verification).
* The regulatory draft suggests incident categories from ATT&CK techniques; an officer must confirm every field.
  Nothing is submitted to any regulator.
* Not enterprise-ready: no SSO, no audit export, no native SIEM connectors (file upload and push API only).
