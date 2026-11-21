import pytest

from attackgraph.store.neo4j_store import Neo4jGraphStore, Neo4jUnavailable


class FakeSession:
    def __init__(self, log, responder):
        self.log, self.responder = log, responder

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, params):
        self.log.append((query, params))
        return self.responder(query, params)


class FakeDriver:
    def __init__(self, responder=lambda q, p: []):
        self.log = []
        self.responder = responder
        self.closed = False

    def session(self, database):
        assert database == "neo4j"
        return FakeSession(self.log, self.responder)

    def verify_connectivity(self):
        return None

    def close(self):
        self.closed = True


def make(responder=lambda q, p: []):
    drv = FakeDriver(responder)
    store = Neo4jGraphStore("neo4j+s://example.databases.neo4j.io", "neo4j", "pw", driver_factory=lambda *a: drv)
    return store, drv


def test_requires_credentials():
    with pytest.raises(Neo4jUnavailable):
        Neo4jGraphStore("", "", "")


def test_evidence_write_is_merge_only_and_parameterised(kat_ws):
    store, drv = make()
    res = kat_ws.files[0]
    out = store.write_file("org_a", 1, res.summary(), res.events, [], [])
    assert out["events"] == len(res.events)
    queries = [q for q, _ in drv.log]
    assert not any("DELETE" in q for q in queries)
    ev_q = next((q, p) for q, p in drv.log if "MERGE (e:Event {key: row.key})" in q)
    assert "ON CREATE SET e += row.props" in ev_q[0]
    keys = [r["key"] for r in ev_q[1]["rows"]]
    assert all(k.startswith("org_a|") for k in keys) and len(set(keys)) == len(keys)
    for q in queries:
        assert "user-01" not in q and "DB-01" not in q and "evil.exe" not in q


def test_derived_write_is_org_scoped_and_never_wipes_evidence(kat_ws):
    store, drv = make()
    store.write_derived("org_a", kat_ws.graph, kat_ws.incidents)
    deletes = [q for q, _ in drv.log if "DELETE" in q]
    assert deletes == ["MATCH (i:Incident {org: $org}) WHERE NOT i.key IN $keep DETACH DELETE i"]
    rel_rows = [r for q, p in drv.log if "MERGE (a)-[r:" in q for r in p["rows"]]
    accessed = next(r for r in rel_rows if r["props"]["id"] == "host:SRV-01|ACCESSED|database:DB-01")
    assert accessed["key"] == "org_a|host:SRV-01|ACCESSED|database:DB-01"
    assert accessed["props"]["events"] == ["dbaudit:E4"] and accessed["props"]["traversable"] is True
    assert accessed["props"]["ts"] == sorted(accessed["props"]["ts"])


def test_temporal_query_uses_allreduce_and_parameters():
    store, drv = make(lambda q, p: [{"rels": ["a|X|b"]}])
    evil = "x'}) MATCH (n) DETACH DELETE n //"
    assert store.temporal_candidate_paths("org_a", evil, "database:DB-01", 3, 120, 6 * 3600) == [["a|X|b"]]
    q, p = drv.log[-1]
    assert q.startswith("CYPHER 25 ") and "allReduce(" in q and "{1,3}" in q
    assert evil not in q and p["s"] == "org_a|" + evil and p["skew"] == 120.0 and p["gap"] == 21600.0


def test_clear_is_org_scoped():
    store, drv = make()
    store.clear_org("org_b")
    for q, p in drv.log:
        assert "{org: $org}" in q and p["org"] == "org_b"


@pytest.mark.parametrize("bad", [0, 9, "3; DROP", 2.5, True])
def test_hop_bound_validated(bad):
    store, _ = make()
    with pytest.raises(ValueError):
        store.candidate_paths("org", "a", "b", bad)
    with pytest.raises(ValueError):
        store.temporal_candidate_paths("org", "a", "b", bad, 0, None)
