from __future__ import annotations

import hashlib
import logging
import threading
import time
from collections import Counter
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .channels import analyse_incident, analyse_path
from .config import AnalysisSettings, DeploymentConfig
from .containment import plan_containment, what_if
from .correlate import correlate
from .deviation import D2_REFERENCE, SUSPICION_CAP, top_deviations
from .evidence import build_manifest
from .graph.blast import compute_blast_radius
from .graph.builder import TemporalGraph, build_graph
from .graph.paths import PathError, PathQuery, find_paths
from .hypotheses import rank as rank_hypotheses
from .ingest.loader import ALLOWED_EXTENSIONS, FileResult, IngestError, InventoryItem, ingest_bytes, sanitize_filename
from .live import LiveHub
from .models import NormalizedEvent
from .narrative import describe_event
from .regulatory import clock as reg_clock
from .regulatory import regulatory_draft
from .report import incident_report, to_html, to_json, to_markdown

log = logging.getLogger(__name__)
RECONNECT_BACKOFF_S = 30.0
LIVE_DERIVED_INTERVAL_S = 10.0
STATUSES = {"confirmed", "cleared"}


class Workspace:
    def __init__(self, deploy: DeploymentConfig | None = None, settings: AnalysisSettings | None = None,
                 org_id: str = "default") -> None:
        self.deploy = deploy or DeploymentConfig()
        self.settings = settings or AnalysisSettings()
        self.org_id = org_id
        self._lock = threading.RLock()
        self.files: list[FileResult] = []
        self.events: dict[str, NormalizedEvent] = {}
        self._digests: dict[str, str] = {}
        self.inventory: list[InventoryItem] = []
        self.cross_file: Counter = Counter()
        self.statuses: dict[str, str] = {}
        self.exports: list[dict] = []
        self.graph: TemporalGraph = build_graph([], [])
        self._incidents: list[dict] | None = None
        self.conflicting: list[tuple[NormalizedEvent, str]] = []
        self.neo4j = None
        self.live = LiveHub(self)
        self._unsaved: list[dict] = []
        self._unsaved_verdicts: list[tuple[str, str | None, str, str]] = []
        self._seq = 0
        self._restoring = False
        self._derived_dirty = False
        self._last_connect_try = 0.0
        self._last_derived_write = 0.0
        self.store_factory = None
        self.investigations: dict[str, dict] = {}
        self.neo4j_state: dict = {"configured": bool(self.deploy.neo4j_uri), "connected": False, "synced": False,
                                  "message": "not configured" if not self.deploy.neo4j_uri else "not yet connected"}

    @property
    def persistent(self) -> bool:
        return self.deploy.graph_backend == "neo4j" and bool(self.deploy.neo4j_uri)

    def reset(self) -> None:
        with self._lock:
            if self.persistent and not self._restoring:
                if self._connect():
                    self.neo4j.clear_org(self.org_id)
                elif self.files:
                    raise PersistenceUnavailable("Neo4j is unavailable, so stored evidence cannot be cleared; try again later")
                self._unsaved, self._unsaved_verdicts = [], []
                self._derived_dirty = True
            self.files, self.events, self._digests, self.inventory = [], {}, {}, []
            self.conflicting = []
            self.cross_file = Counter()
            self.statuses, self._incidents = {}, None
            self.graph = build_graph([], [])
            self.live.reset()
        self.live.publish("reset")

    def _add(self, res: FileResult) -> None:
        accepted: list[NormalizedEvent] = []
        conflicting: list[tuple[NormalizedEvent, str]] = [(ev, ev.source_file) for ev in res.conflicting]
        for ev in res.events:
            digest = hashlib.sha256(repr(sorted(ev.raw.items())).encode()).hexdigest()
            if ev.uid in self.events:
                key = "duplicate" if self._digests[ev.uid] == digest else "conflict"
                self.cross_file[key] += 1
                first = self.events[ev.uid].source_file
                res.add_issue(ev.source_row, key, f"event {ev.uid} already loaded from {first}; "
                                                  + ("ignored" if key == "duplicate" else "both copies kept, the first is used for analysis"))
                if key == "duplicate":
                    res.duplicates += 1
                else:
                    res.conflicts += 1
                    conflicting.append((ev, first))
                res.accepted -= 1
                continue
            self.events[ev.uid] = ev
            self._digests[ev.uid] = digest
            accepted.append(ev)
        self.conflicting.extend(conflicting)
        self.inventory.extend(res.inventory)
        self.files.append(res)
        if not self._restoring:
            self.queue_persist(res.summary(), accepted, conflicting, res.inventory)

    def queue_persist(self, summary: dict, events: list[NormalizedEvent], conflicting: list[tuple[NormalizedEvent, str]],
                      inventory: list) -> None:
        if not self.persistent:
            return
        self._seq += 1
        self._unsaved.append({"seq": self._seq, "summary": summary, "events": events, "conflicting": conflicting,
                              "inventory": [asdict(i) if not isinstance(i, dict) else i for i in inventory]})
        self._derived_dirty = True

    def ingest(self, items: list[tuple[str, bytes, str | None]]) -> list[dict]:
        out = []
        with self._lock:
            for name, data, hint in items:
                try:
                    res = ingest_bytes(data, name, max_bytes=self.deploy.max_upload_bytes,
                                       max_records=self.deploy.max_records_per_file, source_hint=hint or None,
                                       max_capture_bytes=self.deploy.max_capture_bytes)
                except IngestError as exc:
                    out.append({"file_name": sanitize_filename(name) if name else "?", "error": str(exc)})
                    continue
                self._add(res)
                out.append(res.summary())
            self.rebuild()
        return out

    def load_directory(self, directory: Path) -> list[dict]:
        items = [(p.name, p.read_bytes(), None) for p in sorted(directory.iterdir())
                 if p.is_file() and p.suffix.lower() in ALLOWED_EXTENSIONS]
        return self.ingest(items)

    def load_sample(self) -> list[dict]:
        with self._lock:
            self.reset()
            return self.load_directory(self.deploy.sample_dir)

    def rebuild(self, publish: bool = True) -> None:
        with self._lock:
            window = timedelta(minutes=self.settings.correlation_window_minutes)
            self.graph = build_graph(self.events.values(), self.inventory, window)
            self._incidents = None
            if not self._restoring:
                self.persist(force_derived=publish)
        if publish:
            self.live.publish("dataset")

    @property
    def incidents(self) -> list[dict]:
        with self._lock:
            if self._incidents is None:
                self._incidents = correlate(self.graph, self.settings, self.statuses)
            return self._incidents

    def incident(self, inc_id: str) -> dict | None:
        return next((i for i in self.incidents if i["id"] == inc_id), None)

    def _provider(self):
        if not (self.persistent and self.neo4j is not None and self.neo4j_state.get("synced")):
            return None, None
        store, org, st = self.neo4j, self.org_id, self.settings
        if store.supports_cypher25():
            gap = st.max_hop_gap_hours * 3600 if st.max_hop_gap_hours > 0 else None
            return (lambda s, t, h: store.temporal_candidate_paths(org, s, t, h, st.clock_skew_seconds, gap),
                    "Neo4j Cypher 25 allReduce: time-infeasible branches pruned during expansion")
        return (lambda s, t, h: store.candidate_paths(org, s, t, h), "Neo4j variable-length match (Cypher 25 not available)")

    def paths(self, q: PathQuery) -> dict:
        with self._lock:
            res = find_paths(self.graph, q, self.settings, None)
            res["neo4j_check"] = self._neo4j_cross_check(q, res)
            for p in res["paths"]:
                p["channels"] = analyse_path(self.graph, p)
            return res

    def _neo4j_cross_check(self, q: PathQuery, reference: dict) -> dict | None:
        provider, label = self._provider()
        if provider is None:
            return None
        t0 = time.perf_counter()
        try:
            res = find_paths(self.graph, q, self.settings, provider)
        except PathError:
            return None
        except Exception as exc:  # noqa: BLE001
            log.warning("neo4j path cross-check failed: %s", type(exc).__name__)
            self._mark_down(f"path query failed ({type(exc).__name__}); results come from the in-memory engine only")
            return {"query": label, "ok": False, "error": type(exc).__name__}
        ref = {tuple(p["nodes"]) for p in reference["paths"]}
        got = {tuple(p["nodes"]) for p in res["paths"]}
        return {"query": label, "ok": True, "ms": round((time.perf_counter() - t0) * 1000, 1),
                "paths_from_neo4j": res["total_valid_paths"], "paths_from_engine": reference["total_valid_paths"],
                "agree": got == ref and res["total_valid_paths"] == reference["total_valid_paths"],
                "only_in_engine": len(ref - got), "only_in_neo4j": len(got - ref)}

    def mark_opened(self, inc_id: str, user: str) -> dict:
        now = datetime.now(UTC).isoformat()
        rec = self.investigations.setdefault(inc_id, {"opened_at": now, "opened_by": user, "first_export_at": None,
                                                      "exports": 0})
        return rec

    def investigation_timing(self, inc_id: str) -> dict | None:
        rec = self.investigations.get(inc_id)
        if not rec:
            return None
        out = dict(rec)
        if rec["first_export_at"]:
            out["seconds_to_first_report"] = round((datetime.fromisoformat(rec["first_export_at"])
                                                    - datetime.fromisoformat(rec["opened_at"])).total_seconds())
        return out

    def incident_detail(self, inc_id: str) -> dict | None:
        inc = self.incident(inc_id)
        if inc is None:
            return None
        with self._lock:
            out = dict(inc)
            out["clock"] = reg_clock(inc)
            out["hypotheses"] = rank_hypotheses(self.graph, inc)
            out["investigation"] = self.investigation_timing(inc_id)
            out["channels"] = analyse_incident(self.graph, inc, timedelta(minutes=self.settings.correlation_window_minutes))
            if inc.get("hypothesis"):
                out["hypothesis"] = {**inc["hypothesis"], "channels": analyse_path(self.graph, inc["hypothesis"])}
            return out

    def incident_source(self, inc: dict) -> str | None:
        hyp = inc.get("hypothesis")
        if hyp:
            return hyp["source"]
        return (inc["identities"] or inc["affected_assets"] or [None])[0]

    def containment(self, inc_id: str, at: datetime | None = None, hops: int = 5) -> dict:
        inc = self.incident(inc_id)
        if inc is None:
            raise KeyError(inc_id)
        src = self.incident_source(inc)
        if src is None:
            raise ValueError("incident has no identity or asset to contain from")
        at = at or datetime.fromisoformat(inc["start"])
        with self._lock:
            res = plan_containment(self.graph, src, at, self.settings, hops)
        res["incident"] = inc_id
        return res

    def what_if(self, source: str, actions: list[str], at: datetime | None, hops: int = 5) -> dict:
        with self._lock:
            return what_if(self.graph, source, actions, at, self.settings, hops)

    def deviations(self, limit: int = 50) -> dict:
        with self._lock:
            return {"reference_d2": D2_REFERENCE, "suspicion_cap": SUSPICION_CAP, "models": self.graph.deviation_models,
                    "deviations": top_deviations(self.graph, limit)}

    def blast(self, entity: str, hops: int, temporal: bool, since: datetime | None, include_processes: bool) -> dict:
        with self._lock:
            return compute_blast_radius(self.graph, entity, self.settings, hops, temporal, since,
                                        include_processes=include_processes, statuses=self.statuses)

    def set_status(self, entity: str, status: str | None, by: str = "local") -> None:
        if entity not in self.graph.entities:
            raise KeyError(entity)
        if status is not None and status not in STATUSES:
            raise ValueError(f"status must be one of {sorted(STATUSES)} or null")
        with self._lock:
            if status is None:
                self.statuses.pop(entity, None)
            else:
                self.statuses[entity] = status
            self._incidents = None
            if self.persistent:
                self._unsaved_verdicts.append((entity, status, by, datetime.now(UTC).isoformat()))
                self._derived_dirty = True
                self.persist(force_derived=True)
        self.live.publish("analyst-status")

    def update_settings(self, new: AnalysisSettings) -> None:
        with self._lock:
            window_changed = new.correlation_window_minutes != self.settings.correlation_window_minutes
            self.settings = new
            if window_changed:
                self.rebuild(publish=False)
            self._incidents = None
        self.live.publish("settings")

    def file_summaries(self) -> list[dict]:
        return [f.summary() for f in self.files]

    def summary(self) -> dict:
        g = self.graph
        types = Counter(e.type.value for e in g.entities.values())
        rel_types = Counter(r.type.value for r in g.rels.values())
        sources = Counter(e.source_system for e in g.events.values())
        critical = sorted((e for e in g.entities.values() if e.criticality >= 4), key=lambda e: (-e.criticality, e.id))
        incs = self.incidents
        totals = Counter()
        for f in self.files:
            totals.update({"records_read": f.records_read, "accepted": f.accepted, "rejected": f.rejected,
                           "duplicates": f.duplicates, "conflicts": f.conflicts, "warnings": f.warnings})
        hist: Counter = Counter()
        sus_hist: Counter = Counter()
        for ev in g.events.values():
            key = ev.timestamp.replace(minute=0, second=0, microsecond=0).isoformat()
            hist[key] += 1
            if ev.category == "alert" or ev.severity >= self.settings.suspicion_threshold:
                sus_hist[key] += 1
        return {
            "events": len(g.events), "entities": len(g.entities), "relationships": len(g.rels),
            "occurrences": sum(len(r.occurrences) for r in g.rels.values()),
            "entity_types": dict(types), "relationship_types": dict(rel_types), "events_by_source": dict(sources),
            "source_systems": len(sources), "files": len(self.files), "ingestion": dict(totals),
            "time_range": {"start": g.min_time.isoformat() if g.min_time else None, "end": g.max_time.isoformat() if g.max_time else None},
            "critical_assets": [{"id": e.id, "name": e.name, "type": e.type.value, "category": e.category, "criticality": e.criticality}
                                for e in critical],
            "incidents": len(incs),
            "incidents_by_priority": dict(Counter(i["priority"] for i in incs)),
            "top_incident": ({k: incs[0][k] for k in ("id", "title", "priority", "score", "start", "end", "identities",
                                                      "affected_assets", "independent_sources")} | {"hypothesis_nodes": (incs[0]["hypothesis"] or {}).get("nodes")})
            if incs else None,
            "histogram": [{"hour": k, "events": hist[k], "suspicious": sus_hist.get(k, 0)} for k in sorted(hist)],
            "backend": self.backend_status(),
        }

    def entity_list(self, etype: str | None = None, q: str | None = None, limit: int = 500) -> list[dict]:
        out = []
        for e in self.graph.entities.values():
            if etype and e.type.value != etype:
                continue
            if q and q.lower() not in e.id.lower():
                continue
            out.append({"id": e.id, "type": e.type.value, "name": e.name, "category": e.category,
                        "criticality": e.criticality, "in_inventory": e.in_inventory,
                        "degree": self.graph.g.degree(e.id), "events": len(self.graph.entity_events.get(e.id, ())),
                        "status": self.statuses.get(e.id)})
        out.sort(key=lambda x: (-x["criticality"], x["id"]))
        return out[:limit]

    def hypotheses(self, inc_id: str) -> dict:
        inc = self.incident(inc_id)
        if inc is None:
            raise KeyError(inc_id)
        with self._lock:
            return rank_hypotheses(self.graph, inc)

    def load_real(self) -> list[dict]:
        root = self.deploy.sample_dir.parent / "real" / "otrf_lsass_campaign_03"
        files = sorted(p for p in root.iterdir() if p.suffix in {".jsonl", ".log", ".pcap"})
        self.reset()
        return self.ingest([(p.name, p.read_bytes(), None) for p in files])

    def regulatory(self, inc_id: str, org_name: str) -> dict:
        inc = self.incident(inc_id)
        if inc is None:
            raise KeyError(inc_id)
        try:
            plan = self.containment(inc_id)
        except (ValueError, KeyError):
            plan = None
        with self._lock:
            return regulatory_draft(self.graph, inc, org_name, plan, dict(self.statuses), self.file_summaries())

    def admin_overview(self, inc_id: str) -> dict:
        inc = self.incident(inc_id)
        if inc is None:
            raise KeyError(inc_id)
        src = self.incident_source(inc)
        blast = self.blast(src, 4, True, None, False) if src else {"nodes": [], "summary": {}}
        try:
            plan = self.containment(inc_id)
        except (ValueError, KeyError):
            plan = None
        g = self.graph
        with self._lock:
            infra = {"host", "database", "service", "device"}
            tiers = {n["id"]: n for n in blast["nodes"] if n["type"] in infra}
            for eid in inc["affected_assets"]:
                if eid in g.entities and eid not in tiers and g.entities[eid].type.value in infra:
                    e = g.entities[eid]
                    tiers[eid] = {"id": eid, "name": e.name, "type": e.type.value, "criticality": e.criticality, "hop": None,
                                  "classification": "IN_INCIDENT", "earliest_arrival": None}
            start = datetime.fromisoformat(inc["start"]) - timedelta(hours=1)
            end = datetime.fromisoformat(inc["end"]) + timedelta(hours=1)
            assets = []
            for eid, n in tiers.items():
                loc = next((g.entities[t].name for _, t, d in g.g.out_edges(eid, data=True)
                            if g.rels[d["rel_id"]].type.value == "LOCATED_IN"), None) or g.entities[eid].attributes.get("location")
                evs = [g.events[u] for u in g.entity_events.get(eid, ()) if u in g.events]
                sus = [e for e in evs if start <= e.timestamp <= end and e.severity >= self.settings.suspicion_threshold]
                assets.append({"id": eid, "name": n["name"], "type": n["type"], "criticality": n["criticality"],
                               "tier": n["classification"], "hop": n.get("hop"), "reached_at": n.get("earliest_arrival"),
                               "location": loc, "analyst_status": self.statuses.get(eid),
                               "suspicious_events": len(sus), "events_in_window": sum(1 for e in evs if start <= e.timestamp <= end)})
            order = {"CONFIRMED_COMPROMISE": 0, "SUSPECTED_LATERAL_MOVEMENT": 1, "IN_INCIDENT": 2, "OBSERVED_CONNECTION": 3,
                     "POTENTIAL_EXPOSURE": 4}
            assets.sort(key=lambda a: (order.get(a["tier"], 5), -a["criticality"], a["name"]))
            asset_ids = {a["id"] for a in assets}
            infra_events = []
            for ev in g.events.values():
                physical = ev.category == "physical" or ev.source_system == "edge_physical"
                on_asset = bool(set(g.event_elements.get(ev.uid, ())) & asset_ids)
                if not (physical or (on_asset and ev.category in {"service", "privilege", "process", "authentication"}
                                     and ev.severity >= self.settings.suspicion_threshold)):
                    continue
                if not physical and not (start <= ev.timestamp <= end):
                    continue
                infra_events.append({"uid": ev.uid, "timestamp": ev.timestamp.isoformat(), "source": ev.source_system,
                                     "kind": "physical" if physical else ev.category, "severity": round(ev.severity, 2),
                                     "description": describe_event(ev), "location": ev.location,
                                     "in_incident": ev.uid in set(inc["supporting_events"])})
            infra_events.sort(key=lambda e: e["timestamp"], reverse=True)
            crit = [a for a in assets if a["criticality"] >= 4 and a["tier"] in {"SUSPECTED_LATERAL_MOVEMENT", "CONFIRMED_COMPROMISE", "IN_INCIDENT"}]
            options = (plan or {}).get("candidates", [])[:6]
            physical_n = sum(1 for e in infra_events if e["kind"] == "physical")
            asset_rooms = {a["location"] for a in assets if a["location"]}
            for e in infra_events:
                e["same_room_as_incident_assets"] = bool(e["location"] and e["location"] in asset_rooms)
            colocated = [e for e in infra_events if e["same_room_as_incident_assets"]]
            summary = [
                f"{inc['priority']} incident {inc['id']}: {inc['title']}.",
                f"{len(assets)} infrastructure assets are within reach of {src}; "
                f"{sum(1 for a in assets if a['tier'] == 'SUSPECTED_LATERAL_MOVEMENT')} show suspected lateral movement.",
                ("Critical assets at risk: " + ", ".join(a["name"] for a in crit[:5]) + ".") if crit else "No critical asset shows suspected lateral movement.",
                (f"Recommended first action: {options[0]['label']} (cuts {options[0]['risk_reduction_pct']}% of path risk; simulated, not executed).")
                if options else "No containment option was computed.",
                (f"{physical_n} physical event(s) reported by edge sensors, {len(colocated)} of them in a room that holds "
                 f"assets from this incident ({', '.join(sorted(asset_rooms))}); treat them as evidence to check, not proof.")
                if physical_n else "No physical (edge sensor) events recorded.",
            ]
            return {"incident": inc["id"], "source": src, "summary": summary, "assets": assets,
                    "infrastructure_events": infra_events[:200], "containment_options": options,
                    "containment_effective_at": (plan or {}).get("effective_at"), "clock": reg_clock(inc),
                    "caveat": "Tiers separate evidence of movement from mere reachability. Containment figures are "
                              "simulations on the observed evidence and do not change any system."}

    def export_incident(self, inc_id: str, fmt: str, org_name: str = "Local workspace") -> tuple[str, bytes, str]:
        inc = self.incident_detail(inc_id)
        if inc is None:
            raise KeyError(inc_id)
        rec = self.investigations.get(inc_id)
        if rec is not None:
            rec["exports"] += 1
            rec["first_export_at"] = rec["first_export_at"] or datetime.now(UTC).isoformat()
            inc["investigation"] = self.investigation_timing(inc_id)
        rep = incident_report(self.graph, inc, self.file_summaries(), self.settings.model_dump())
        rep["regulatory_draft"] = self.regulatory(inc_id, org_name)
        if fmt == "json":
            body, mime = to_json(rep).encode(), "application/json"
        elif fmt == "md":
            body, mime = to_markdown(rep).encode(), "text/markdown; charset=utf-8"
        elif fmt == "html":
            body, mime = to_html(rep).encode(), "text/html; charset=utf-8"
        else:
            raise ValueError("format must be json, md or html")
        name = f"{inc_id}_report.{fmt}"
        digest = hashlib.sha256(body).hexdigest()
        rec = {"file_name": name, "sha256": digest, "size_bytes": len(body), "incident": inc_id,
               "exported_at": datetime.now(UTC).isoformat()}
        with self._lock:
            self.exports.append(rec)
            try:
                self.deploy.export_dir.mkdir(parents=True, exist_ok=True)
                (self.deploy.export_dir / name).write_bytes(body)
            except OSError:
                log.warning("could not write export copy to disk")
        return name, body, mime

    def manifest(self) -> dict:
        return build_manifest(self.file_summaries(), self.exports, len(self.graph.events))

    def backend_status(self) -> dict:
        pending = len(self._unsaved) + len(self._unsaved_verdicts)
        return {"mode": self.deploy.graph_backend, "local_engine": "NetworkX temporal graph (in-memory analysis)",
                "persistent": self.persistent,
                "persisted": (not self.persistent) or (self.neo4j_state.get("connected", False) and pending == 0),
                "pending_items": pending,
                "neo4j": {**self.neo4j_state, "uri_host": _host_only(self.deploy.neo4j_uri), "database": self.deploy.neo4j_database,
                          "cypher25": getattr(self.neo4j, "cypher25", None)}}

    def _mark_down(self, message: str) -> None:
        self.neo4j_state.update({"connected": False, "synced": False, "message": message})

    def _connect(self, factory=None, force: bool = False) -> bool:
        if self.neo4j is not None and self.neo4j_state.get("connected"):
            return True
        now = time.monotonic()
        if not force and now - self._last_connect_try < RECONNECT_BACKOFF_S and self._last_connect_try:
            return False
        self._last_connect_try = now
        from .store.neo4j_store import Neo4jGraphStore, Neo4jUnavailable
        d = self.deploy
        try:
            if self.neo4j is None:
                if self.store_factory is not None:
                    self.neo4j = self.store_factory()
                else:
                    self.neo4j = Neo4jGraphStore(d.neo4j_uri or "", d.neo4j_user or "", d.neo4j_password or "",
                                                 d.neo4j_database, driver_factory=factory)
            info = self.neo4j.verify()
            self.neo4j.ensure_schema()
            self.neo4j.supports_cypher25()
            self.neo4j_state.update({"configured": True, "connected": True, "server": info,
                                     "message": "connected"})
            return True
        except Neo4jUnavailable as exc:
            self._mark_down(str(exc))
        except Exception as exc:  # noqa: BLE001
            log.warning("neo4j connection failed: %s", type(exc).__name__)
            self.neo4j = None
            self._mark_down(f"connection failed ({type(exc).__name__}); data is NOT being persisted")
        return False

    def persist(self, force_derived: bool = True, factory=None, force_connect: bool = False) -> dict:
        if not self.persistent:
            return self.backend_status()
        with self._lock:
            if not self._connect(factory, force=force_connect):
                if self._unsaved or self._unsaved_verdicts:
                    self.neo4j_state["message"] = (f"Neo4j unavailable: {len(self._unsaved)} upload(s) and "
                                                   f"{len(self._unsaved_verdicts)} verdict(s) held in memory, NOT persisted")
                return self.backend_status()
            store = self.neo4j
            try:
                while self._unsaved:
                    item = self._unsaved[0]
                    store.write_file(self.org_id, item["seq"], item["summary"], item["events"], item["conflicting"], item["inventory"])
                    self._unsaved.pop(0)
                while self._unsaved_verdicts:
                    entity, status, by, at = self._unsaved_verdicts[0]
                    store.write_verdict(self.org_id, entity, status, by, at)
                    self._unsaved_verdicts.pop(0)
                due = force_derived or time.monotonic() - self._last_derived_write >= LIVE_DERIVED_INTERVAL_S
                if self._derived_dirty and due:
                    counts = store.write_derived(self.org_id, self.graph, self.incidents)
                    self._derived_dirty = False
                    self._last_derived_write = time.monotonic()
                    self.neo4j_state["synced_counts"] = counts
                fresh = not self._derived_dirty
                self.neo4j_state.update({"synced": fresh, "last_sync": datetime.now(UTC).isoformat(),
                                         "message": "all evidence persisted" + ("" if fresh else "; graph structure refresh pending")})
            except Exception as exc:  # noqa: BLE001
                log.warning("neo4j write failed: %s", type(exc).__name__)
                self.neo4j = None
                self._mark_down(f"write failed ({type(exc).__name__}); {len(self._unsaved)} upload(s) held in memory, NOT persisted")
            return self.backend_status()

    def neo4j_connect_and_sync(self, factory=None) -> dict:
        self._derived_dirty = True
        return self.persist(force_derived=True, factory=factory, force_connect=True)

    def open(self, load_sample: bool = False, factory=None) -> None:
        if self.persistent and self._connect(factory, force=True):
            try:
                data = self.neo4j.load_org(self.org_id)
            except Exception as exc:  # noqa: BLE001
                log.warning("neo4j restore failed: %s", type(exc).__name__)
                self.neo4j = None
                self._mark_down(f"restore failed ({type(exc).__name__}); starting empty and NOT persisting until it reconnects")
                data = None
            if data and data["files"]:
                self.restore(data)
                return
        if load_sample and not self.files and self.deploy.sample_dir.is_dir():
            self.load_sample()

    def restore(self, data: dict) -> None:
        from .ingest.loader import FileResult, InventoryItem
        with self._lock:
            self._restoring = True
            try:
                for f in data["files"]:
                    sm = f["summary"]
                    res = FileResult(file_name=sm["file_name"], sha256=sm["sha256"], size_bytes=sm.get("size_bytes", 0),
                                     adapter=sm.get("source_system"), adapter_label=sm.get("source_label"))
                    res.events = [ev for ev, conflict in f["events"] if not conflict]
                    res.conflicting = [ev for ev, conflict in f["events"] if conflict]
                    res.inventory = [InventoryItem(**{k: v for k, v in i.items() if k in InventoryItem.__dataclass_fields__})
                                     for i in f["inventory"]]
                    self._add(res)
                    for k in ("records_read", "accepted", "rejected", "duplicates", "conflicts", "warnings"):
                        setattr(res, k, sm.get(k, 0))
                    self._seq = max(self._seq, f["seq"] or 0)
                for entity, status in data["verdicts"]:
                    if status in STATUSES:
                        self.statuses[entity] = status
                    else:
                        self.statuses.pop(entity, None)
                self.rebuild(publish=False)
            finally:
                self._restoring = False
            self._derived_dirty = True
            self.persist(force_derived=True)
            self.neo4j_state["restored_files"] = len(data["files"])
        self.live.publish("dataset")


class PersistenceUnavailable(RuntimeError):
    pass


def _host_only(uri: str | None) -> str | None:
    if not uri:
        return None
    rest = uri.split("://", 1)[-1]
    return rest.split("@")[-1].split("/")[0]
