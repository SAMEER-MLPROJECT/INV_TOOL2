"""Workspace persistence logic against an in-memory store that applies the same key rules as the Neo4j store
(MERGE on content keys, evidence never deleted by a sync, organisation scoping). The Cypher itself is checked in
test_neo4j_adapter.py and against a real instance by scripts/verify_neo4j.py."""
import json

import pytest

from attackgraph.config import AnalysisSettings
from attackgraph.graph.paths import PathQuery
from attackgraph.workspace import PersistenceUnavailable, Workspace

from .conftest import KAT_FIELDS, KAT_ROWS, to_csv


class FakeStore:
    def __init__(self, db):
        self.db = db
        self.cypher25 = True

    def _check(self):
        if self.db["down"]:
            raise ConnectionError("neo4j down")

    def verify(self):
        self._check()
        return {"name": "fake", "versions": ["5"], "edition": "test"}

    def ensure_schema(self):
        self._check()

    def supports_cypher25(self):
        return self.cypher25

    def write_file(self, org, seq, summary, events, conflicting, inventory):
        self._check()
        fkey = f"{org}|{summary['sha256']}|{summary['file_name']}"
        self.db["files"].setdefault(fkey, {"org": org, "seq": seq, "summary": json.dumps(summary, default=str)})
        for ev in events:
            self.db["events"].setdefault(f"{org}|{ev.uid}|{json.dumps(ev.raw, sort_keys=True)}",
                                         {"fkey": fkey, "doc": ev.model_dump_json(), "conflict": False})
        for ev, _ in conflicting:
            self.db["events"].setdefault(f"{org}|{ev.uid}|{json.dumps(ev.raw, sort_keys=True)}",
                                         {"fkey": fkey, "doc": ev.model_dump_json(), "conflict": True})
        for i in inventory:
            self.db["inventory"].setdefault(f"{org}|{summary['sha256']}|{i['source_row']}", {"fkey": fkey, **i})
        self.db["writes"] += 1

    def write_verdict(self, org, entity, status, by, at):
        self._check()
        self.db["verdicts"].append((org, entity, status or "none", by, at))

    def write_derived(self, org, g, incidents):
        self._check()
        self.db["derived"][org] = (len(g.entities), len(g.rels), len(incidents))
        return {"nodes": len(g.entities), "relationships": len(g.rels), "incidents": len(incidents)}

    def load_org(self, org):
        self._check()
        from attackgraph.models import NormalizedEvent
        files = sorted(((k, v) for k, v in self.db["files"].items() if v["org"] == org), key=lambda kv: kv[1]["seq"])
        out = []
        for fkey, f in files:
            evs = [(NormalizedEvent.model_validate_json(e["doc"]), e["conflict"]) for e in self.db["events"].values() if e["fkey"] == fkey]
            inv = [{k: v for k, v in i.items() if k != "fkey"} for i in self.db["inventory"].values() if i["fkey"] == fkey]
            out.append({"seq": f["seq"], "summary": json.loads(f["summary"]), "events": evs, "inventory": inv})
        return {"files": out, "verdicts": [(e, s) for o, e, s, _, _ in self.db["verdicts"] if o == org]}

    def clear_org(self, org):
        self._check()
        for table in ("files", "events", "inventory"):
            self.db[table] = {k: v for k, v in self.db[table].items() if not k.startswith(org + "|")}
        self.db["verdicts"] = [v for v in self.db["verdicts"] if v[0] != org]

    def temporal_candidate_paths(self, org, s, t, h, skew, gap):
        self._check()
        return self.db.setdefault("path_answers", [])

    def candidate_paths(self, org, s, t, h):
        return []


@pytest.fixture
def db():
    return {"down": False, "files": {}, "events": {}, "inventory": {}, "verdicts": [], "derived": {}, "writes": 0}


@pytest.fixture
def pdeploy(deploy):
    return deploy.model_copy(update={"graph_backend": "neo4j", "neo4j_uri": "neo4j+s://x.example", "neo4j_user": "u",
                                     "neo4j_password": "p"})


def make_ws(pdeploy, db, org="org_a"):
    ws = Workspace(pdeploy, AnalysisSettings(), org_id=org)
    ws.store_factory = lambda: FakeStore(db)
    return ws


def test_ingest_is_written_through_and_survives_restart(pdeploy, db, kat_files):
    ws = make_ws(pdeploy, db)
    ws.open()
    ws.ingest(kat_files)
    st = ws.backend_status()
    assert st["persisted"] and st["pending_items"] == 0 and st["neo4j"]["synced"]
    ws.set_status("user:user-01", "confirmed", by="analyst")
    before = (len(ws.events), len(ws.graph.entities), len(ws.graph.rels), [i["id"] for i in ws.incidents])

    ws2 = make_ws(pdeploy, db)
    ws2.open(load_sample=True)
    after = (len(ws2.events), len(ws2.graph.entities), len(ws2.graph.rels), [i["id"] for i in ws2.incidents])
    assert after == before
    assert ws2.statuses == {"user:user-01": "confirmed"}
    assert ws2.neo4j_state["restored_files"] == 2
    assert [f.file_name for f in ws2.files] == [f.file_name for f in ws.files]


def test_repeated_ingest_creates_no_duplicate_evidence(pdeploy, db, kat_files):
    ws = make_ws(pdeploy, db)
    ws.open()
    ws.ingest(kat_files)
    n = len(db["events"])
    res = ws.ingest(kat_files)
    assert len(db["events"]) == n
    assert res[0]["duplicates"] == len(KAT_ROWS) - 0 and len(ws.events) == len(KAT_ROWS)


def test_conflicting_copy_is_kept_and_flagged(pdeploy, db, kat_files):
    ws = make_ws(pdeploy, db)
    ws.open()
    ws.ingest(kat_files)
    changed = [dict(r) for r in KAT_ROWS[:1]]
    changed[0]["severity"] = "0.1"
    res = ws.ingest([("later.csv", to_csv(changed, KAT_FIELDS), None)])
    assert res[0]["conflicts"] == 1
    assert len(ws.conflicting) == 1 and ws.conflicting[0][1] == "kat_events.csv"
    assert ws.events["idp:E1"].severity == 0.8
    stored = [e for e in db["events"].values() if e["conflict"]]
    assert len(stored) == 1 and json.loads(stored[0]["doc"])["severity"] == 0.1
    ws2 = make_ws(pdeploy, db)
    ws2.open()
    assert len(ws2.conflicting) == 1 and ws2.events["idp:E1"].severity == 0.8


def test_outage_is_reported_and_recovered_without_loss(pdeploy, db, kat_files):
    ws = make_ws(pdeploy, db)
    ws.open()
    db["down"] = True
    ws.ingest(kat_files)
    st = ws.backend_status()
    assert not st["persisted"] and st["pending_items"] == 2 and not st["neo4j"]["connected"]
    assert "NOT persisted" in st["neo4j"]["message"]
    assert len(ws.events) == len(KAT_ROWS)
    with pytest.raises(PersistenceUnavailable):
        ws.reset()
    db["down"] = False
    st = ws.neo4j_connect_and_sync()
    assert st["persisted"] and st["pending_items"] == 0 and len(db["events"]) == len(KAT_ROWS)


def test_organisations_do_not_share_stored_evidence(pdeploy, db, kat_files):
    a = make_ws(pdeploy, db, "org_a")
    a.open()
    a.ingest(kat_files)
    b = make_ws(pdeploy, db, "org_b")
    b.open()
    assert len(b.events) == 0
    b.reset()
    a2 = make_ws(pdeploy, db, "org_a")
    a2.open()
    assert len(a2.events) == len(KAT_ROWS)


def test_clear_deletes_only_on_explicit_reset(pdeploy, db, kat_files):
    ws = make_ws(pdeploy, db)
    ws.open()
    ws.ingest(kat_files)
    ws.rebuild()
    assert len(db["events"]) == len(KAT_ROWS)
    ws.reset()
    assert len(db["events"]) == 0


def test_neo4j_path_candidates_are_revalidated_and_failure_falls_back(pdeploy, db, kat_files):
    ws = make_ws(pdeploy, db)
    ws.open()
    ws.ingest(kat_files)
    q = PathQuery(source="user:user-01", targets=["database:DB-01"], max_hops=5)
    ref = ws.paths(q)
    chk = ref["neo4j_check"]
    assert chk["ok"] and chk["query"].startswith("Neo4j Cypher 25 allReduce")
    assert ref["paths"] and chk["paths_from_neo4j"] == 0 and chk["agree"] is False
    db["path_answers"] = [[st["relationship_id"] for st in p["steps"]] for p in ref["paths"]]
    assert ws.paths(q)["neo4j_check"]["agree"] is True
    db["down"] = True
    res2 = ws.paths(q)
    assert res2["paths"] == ref["paths"] and res2["neo4j_check"]["ok"] is False
    assert not ws.backend_status()["neo4j"]["connected"]


def test_memory_mode_never_claims_persistence(deploy, kat_files):
    ws = Workspace(deploy, AnalysisSettings())
    ws.ingest(kat_files)
    st = ws.backend_status()
    assert st["persistent"] is False and st["neo4j"]["connected"] is False
