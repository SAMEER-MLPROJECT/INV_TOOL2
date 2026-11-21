from __future__ import annotations

import json
import logging
from collections.abc import Callable, Iterable
from datetime import datetime
from typing import Any

from ..graph.builder import TemporalGraph
from ..models import TRAVERSABLE, EntityType, NormalizedEvent, RelType

log = logging.getLogger(__name__)

LABELS = {t: t.value.capitalize() for t in EntityType}
BATCH = 500

SCHEMA = [
    "CREATE CONSTRAINT agl_entity_key IF NOT EXISTS FOR (e:Entity) REQUIRE e.key IS UNIQUE",
    "CREATE CONSTRAINT agl_event_key IF NOT EXISTS FOR (e:Event) REQUIRE e.key IS UNIQUE",
    "CREATE CONSTRAINT agl_file_key IF NOT EXISTS FOR (f:SourceFile) REQUIRE f.key IS UNIQUE",
    "CREATE CONSTRAINT agl_inv_key IF NOT EXISTS FOR (i:InventoryRecord) REQUIRE i.key IS UNIQUE",
    "CREATE CONSTRAINT agl_incident_key IF NOT EXISTS FOR (i:Incident) REQUIRE i.key IS UNIQUE",
    "CREATE INDEX agl_entity_org IF NOT EXISTS FOR (e:Entity) ON (e.org)",
    "CREATE INDEX agl_event_org_uid IF NOT EXISTS FOR (e:Event) ON (e.org, e.uid)",
    "CREATE INDEX agl_file_org IF NOT EXISTS FOR (f:SourceFile) ON (f.org, f.seq)",
    "CREATE INDEX agl_verdict_org IF NOT EXISTS FOR (v:Verdict) ON (v.org, v.entity)",
]


class Neo4jUnavailable(RuntimeError):
    pass


def _default_driver_factory(uri: str, user: str, password: str):  # pragma: no cover
    try:
        from neo4j import GraphDatabase
    except ImportError as exc:
        raise Neo4jUnavailable("the 'neo4j' Python driver is not installed") from exc
    return GraphDatabase.driver(uri, auth=(user, password), connection_timeout=10, max_transaction_retry_time=10)


def _epoch(ts: datetime) -> float:
    return ts.timestamp()


def _chunks(rows: list[dict], n: int = BATCH) -> Iterable[list[dict]]:
    for i in range(0, len(rows), n):
        yield rows[i:i + n]


class Neo4jGraphStore:
    """Persistent, organisation-scoped evidence graph.

    Evidence (source files, events with their raw records, inventory records, analyst verdicts) is written
    incrementally with MERGE on content keys and is never deleted by a sync. Derived structure (entities,
    relationships, incidents) is refreshed from the analysis engine after every change.
    """

    def __init__(self, uri: str, user: str, password: str, database: str = "neo4j",
                 driver_factory: Callable[[str, str, str], Any] | None = None) -> None:
        if not (uri and user and password):
            raise Neo4jUnavailable("NEO4J_URI, NEO4J_USERNAME and NEO4J_PASSWORD must all be set")
        self.uri = uri
        self.database = database
        self._driver = (driver_factory or _default_driver_factory)(uri, user, password)
        self.cypher25: bool | None = None

    def _run(self, query: str, **params: Any) -> list[dict]:
        with self._driver.session(database=self.database) as session:
            result = session.run(query, params)
            return [dict(r) for r in result]

    def close(self) -> None:
        self._driver.close()

    def verify(self) -> dict:
        self._driver.verify_connectivity()
        rows = self._run("CALL dbms.components() YIELD name, versions, edition RETURN name, versions, edition")
        return rows[0] if rows else {}

    def ensure_schema(self) -> list[str]:
        for s in SCHEMA:
            self._run(s)
        return SCHEMA

    # ---------------------------------------------------------------- evidence (append-only)

    def write_file(self, org: str, seq: int, summary: dict, events: list[NormalizedEvent],
                   conflicting: list[tuple[NormalizedEvent, str]], inventory: list[dict]) -> dict:
        fkey = f"{org}|{summary['sha256']}|{summary['file_name']}"
        self._run("MERGE (f:SourceFile {key: $key}) ON CREATE SET f.org = $org, f.seq = $seq, f.sha256 = $sha, "
                  "f.name = $name, f.adapter = $adapter, f.loaded_at = $loaded_at "
                  "SET f.summary = $summary",
                  key=fkey, org=org, seq=seq, sha=summary["sha256"], name=summary["file_name"],
                  adapter=summary.get("source_system"), loaded_at=summary.get("loaded_at"),
                  summary=json.dumps(summary, default=str))
        rows = [self._event_row(org, ev, conflict_with=None) for ev in events]
        rows += [self._event_row(org, ev, conflict_with=first) for ev, first in conflicting]
        written = 0
        for chunk in _chunks(rows):
            self._run(
                "UNWIND $rows AS row MATCH (f:SourceFile {key: $fkey}) "
                "MERGE (e:Event {key: row.key}) ON CREATE SET e += row.props "
                "MERGE (e)-[:FROM_FILE {row: row.props.source_row}]->(f)",
                rows=chunk, fkey=fkey)
            written += len(chunk)
        clinks = [{"key": r["key"], "uid": r["props"]["uid"]} for r in rows if r["conflict_with"]]
        for chunk in _chunks(clinks):
            self._run("UNWIND $rows AS row MATCH (c:Event {key: row.key}) "
                      "MATCH (first:Event {org: $org, uid: row.uid, conflict: false}) "
                      "MERGE (c)-[:CONFLICTS_WITH]->(first)", rows=chunk, org=org)
        inv = [{"key": f"{org}|{summary['sha256']}|{i['source_row']}", "props": {**i, "org": org, "tags": list(i.get("tags") or [])}}
               for i in inventory]
        for chunk in _chunks(inv):
            self._run("UNWIND $rows AS row MATCH (f:SourceFile {key: $fkey}) "
                      "MERGE (i:InventoryRecord {key: row.key}) ON CREATE SET i += row.props "
                      "MERGE (i)-[:FROM_FILE]->(f)", rows=chunk, fkey=fkey)
        return {"file": summary["file_name"], "events": written, "conflicts": len(conflicting), "inventory": len(inv)}

    @staticmethod
    def _event_row(org: str, ev: NormalizedEvent, conflict_with: str | None) -> dict:
        doc = ev.model_dump_json()
        digest = json.dumps(ev.raw, sort_keys=True, default=str)
        import hashlib
        h = hashlib.sha256(digest.encode()).hexdigest()
        props = {"org": org, "uid": ev.uid, "event_id": ev.event_id, "ts": _epoch(ev.timestamp), "time": ev.timestamp.isoformat(),
                 "source_system": ev.source_system, "source_file": ev.source_file, "source_row": ev.source_row,
                 "category": ev.category, "severity": ev.severity, "digest": h, "doc": doc, "conflict": conflict_with is not None}
        return {"key": f"{org}|{ev.uid}|{h}", "props": props, "conflict_with": conflict_with}

    def write_verdict(self, org: str, entity: str, status: str | None, by: str, at: str) -> None:
        self._run("CREATE (v:Verdict {org: $org, entity: $entity, status: $status, by: $by, at: $at}) "
                  "WITH v OPTIONAL MATCH (e:Entity {key: $ekey}) FOREACH (_ IN CASE WHEN e IS NULL THEN [] ELSE [1] END | "
                  "MERGE (e)-[:HAS_VERDICT]->(v))",
                  org=org, entity=entity, status=status or "none", by=by, at=at, ekey=f"{org}|{entity}")

    # ---------------------------------------------------------------- derived structure

    def write_derived(self, org: str, g: TemporalGraph, incidents: list[dict]) -> dict:
        by_type: dict[EntityType, list[dict]] = {}
        for e in g.entities.values():
            by_type.setdefault(e.type, []).append({
                "key": f"{org}|{e.id}", "props": {
                    "org": org, "id": e.id, "name": e.name, "type": e.type.value, "category": e.category,
                    "criticality": e.criticality, "in_inventory": e.in_inventory,
                    "first_seen": e.first_seen.isoformat() if e.first_seen else None,
                    "last_seen": e.last_seen.isoformat() if e.last_seen else None}})
        nodes = 0
        for etype, rows in by_type.items():
            for chunk in _chunks(rows):
                self._run(f"UNWIND $rows AS row MERGE (e:Entity {{key: row.key}}) SET e += row.props, e:{LABELS[etype]}", rows=chunk)
                nodes += len(chunk)
        by_rel: dict[RelType, list[dict]] = {}
        for r in g.rels.values():
            occ = sorted(r.occurrences, key=lambda o: o.timestamp)
            by_rel.setdefault(r.type, []).append({
                "src": f"{org}|{r.source}", "dst": f"{org}|{r.target}", "key": f"{org}|{r.id}",
                "props": {"org": org, "id": r.id, "ts": [_epoch(o.timestamp) for o in occ], "events": [o.event_uid for o in occ],
                          "sources": sorted(r.sources), "max_suspicion": r.max_suspicion, "basis": r.basis.value,
                          "count": len(occ), "first_seen": r.first_seen.isoformat(), "last_seen": r.last_seen.isoformat(),
                          "traversable": r.type in TRAVERSABLE}})
        rels = 0
        for rtype, rows in by_rel.items():
            for chunk in _chunks(rows):
                self._run(f"UNWIND $rows AS row MATCH (a:Entity {{key: row.src}}) MATCH (b:Entity {{key: row.dst}}) "
                          f"MERGE (a)-[r:{rtype.value} {{key: row.key}}]->(b) SET r += row.props", rows=chunk)
                rels += len(chunk)
        ev_links = [{"ekey": f"{org}|{eid}", "uids": sorted(uids)} for eid, uids in g.entity_events.items()]
        for chunk in _chunks(ev_links, 200):
            self._run("UNWIND $rows AS row MATCH (n:Entity {key: row.ekey}) UNWIND row.uids AS uid "
                      "MATCH (ev:Event {org: $org, uid: uid, conflict: false}) MERGE (ev)-[:EVIDENCE_FOR]->(n)",
                      rows=chunk, org=org)
        inc_rows = [{"key": f"{org}|{i['id']}", "props": {"org": org, "id": i["id"], "title": i["title"], "priority": i["priority"],
                                                         "score": i["score"], "start": i["start"], "end": i["end"]},
                     "events": list(i["supporting_events"]),
                     "entities": [f"{org}|{e}" for v in i["entities"].values() for e in v]} for i in incidents]
        self._run("MATCH (i:Incident {org: $org}) WHERE NOT i.key IN $keep DETACH DELETE i", org=org, keep=[r["key"] for r in inc_rows])
        for chunk in _chunks(inc_rows, 50):
            self._run("UNWIND $rows AS row MERGE (i:Incident {key: row.key}) SET i += row.props WITH i, row "
                      "CALL (i, row) { UNWIND row.events AS uid MATCH (ev:Event {org: row.props.org, uid: uid, conflict: false}) "
                      "MERGE (i)-[:SUPPORTED_BY]->(ev) } "
                      "CALL (i, row) { UNWIND row.entities AS ek MATCH (n:Entity {key: ek}) MERGE (i)-[:AFFECTS]->(n) }",
                      rows=chunk)
        return {"nodes": nodes, "relationships": rels, "incidents": len(inc_rows)}

    # ---------------------------------------------------------------- restore after restart

    def load_org(self, org: str) -> dict:
        files = self._run("MATCH (f:SourceFile {org: $org}) RETURN f.key AS key, f.seq AS seq, f.summary AS summary "
                          "ORDER BY f.seq", org=org)
        out = []
        for f in files:
            evs = self._run("MATCH (e:Event)-[:FROM_FILE]->(f:SourceFile {key: $key}) "
                            "RETURN e.doc AS doc, e.conflict AS conflict, e.source_row AS row ORDER BY row", key=f["key"])
            inv = self._run("MATCH (i:InventoryRecord)-[:FROM_FILE]->(f:SourceFile {key: $key}) "
                            "RETURN i {.*} AS item ORDER BY item.source_row", key=f["key"])
            out.append({"seq": f["seq"], "summary": json.loads(f["summary"]),
                        "events": [(NormalizedEvent.model_validate_json(e["doc"]), bool(e["conflict"])) for e in evs],
                        "inventory": [i["item"] for i in inv]})
        verdicts = self._run("MATCH (v:Verdict {org: $org}) RETURN v.entity AS entity, v.status AS status ORDER BY v.at", org=org)
        return {"files": out, "verdicts": [(v["entity"], v["status"]) for v in verdicts]}

    def clear_org(self, org: str) -> None:
        for label in ("Event", "InventoryRecord", "SourceFile", "Entity", "Incident", "Verdict"):
            self._run(f"MATCH (n:{label} {{org: $org}}) CALL (n) {{ DETACH DELETE n }} IN TRANSACTIONS OF 1000 ROWS", org=org)

    def counts(self, org: str) -> dict:
        rows = self._run("CALL () { MATCH (e:Event {org: $org}) RETURN count(e) AS events } "
                         "CALL () { MATCH (e:Event {org: $org, conflict: true}) RETURN count(e) AS conflicting } "
                         "CALL () { MATCH (f:SourceFile {org: $org}) RETURN count(f) AS files } "
                         "CALL () { MATCH (n:Entity {org: $org}) RETURN count(n) AS entities } "
                         "CALL () { MATCH (:Entity {org: $org})-[r]->(:Entity {org: $org}) RETURN count(r) AS relationships } "
                         "CALL () { MATCH (i:Incident {org: $org}) RETURN count(i) AS incidents } "
                         "RETURN events, conflicting, files, entities, relationships, incidents", org=org)
        return rows[0] if rows else {}

    # ---------------------------------------------------------------- graph queries

    @staticmethod
    def _hops(max_hops: int) -> int:
        if not isinstance(max_hops, int) or isinstance(max_hops, bool) or not 1 <= max_hops <= 8:
            raise ValueError("max_hops must be an integer between 1 and 8")
        return max_hops

    def temporal_candidate_paths(self, org: str, source: str, target: str, max_hops: int, skew_s: float,
                                 max_gap_s: float | None, limit: int = 200) -> list[list[str]]:
        """Cypher 25: allReduce carries the set of feasible arrival times along the path and prunes a branch
        as soon as no occurrence of the next relationship can follow the previous step in time."""
        hops = self._hops(max_hops)
        gap = float(max_gap_s) if max_gap_s else 1e12
        rows = self._run(
            "CYPHER 25 "
            "MATCH p = (s:Entity {key: $s})(()-[r WHERE r.traversable AND r.org = $org]->()){1," + str(hops) + "}(t:Entity {key: $t}) "
            "WHERE allReduce(acc = null, x IN r | CASE WHEN acc IS NULL THEN x.ts "
            "ELSE [ts IN x.ts WHERE any(a IN acc WHERE ts >= a - $skew AND ts <= a + $gap)] END, acc IS NULL OR size(acc) > 0) "
            "AND all(i IN range(0, size(nodes(p)) - 2) WHERE NOT nodes(p)[i] IN nodes(p)[i + 1..]) "
            "RETURN [x IN relationships(p) | x.id] AS rels LIMIT $limit",
            s=f"{org}|{source}", t=f"{org}|{target}", org=org, skew=float(skew_s), gap=gap, limit=int(limit))
        return [r["rels"] for r in rows]

    def candidate_paths(self, org: str, source: str, target: str, max_hops: int, limit: int = 200) -> list[list[str]]:
        hops = self._hops(max_hops)
        rows = self._run(
            f"MATCH p = (s:Entity {{key: $s}})-[*1..{hops}]->(t:Entity {{key: $t}}) "
            "WHERE all(r IN relationships(p) WHERE r.traversable AND r.org = $org) "
            "AND all(i IN range(0, size(nodes(p)) - 2) WHERE NOT nodes(p)[i] IN nodes(p)[i + 1..]) "
            "RETURN [r IN relationships(p) | r.id] AS rels LIMIT $limit",
            s=f"{org}|{source}", t=f"{org}|{target}", org=org, limit=int(limit))
        return [r["rels"] for r in rows]

    def supports_cypher25(self) -> bool:
        if self.cypher25 is None:
            try:
                self._run("CYPHER 25 RETURN allReduce(acc = 0, x IN [1, 2] | acc + x, acc < 10) AS ok")
                self.cypher25 = True
            except Exception as exc:  # noqa: BLE001
                log.info("Cypher 25 allReduce not available: %s", type(exc).__name__)
                self.cypher25 = False
        return self.cypher25

    def neighbourhood_counts(self, org: str, source: str, max_hops: int) -> dict[str, int]:
        hops = self._hops(max_hops)
        rows = self._run(
            f"MATCH (s:Entity {{key: $s}})-[rs*1..{hops}]->(n:Entity) "
            "WHERE all(r IN rs WHERE r.traversable AND r.org = $org) AND n.key <> $s "
            "RETURN n.type AS type, count(DISTINCT n) AS n",
            s=f"{org}|{source}", org=org)
        return {r["type"]: r["n"] for r in rows}

    def entity_provenance(self, org: str, entity: str, limit: int = 50) -> list[dict]:
        return self._run(
            "MATCH (ev:Event)-[:EVIDENCE_FOR]->(n:Entity {key: $k}) MATCH (ev)-[ff:FROM_FILE]->(f:SourceFile) "
            "RETURN ev.uid AS uid, ev.time AS time, ev.source_system AS source, f.name AS file, f.sha256 AS sha256, "
            "ff.row AS row ORDER BY ev.ts LIMIT $limit", k=f"{org}|{entity}", limit=int(limit))
