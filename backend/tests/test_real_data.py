"""End-to-end on a REAL recorded attack (OTRF Security-Datasets LSASS_campaign_03, MIT licence): Windows host logs,
Zeek logs and a packet capture of the same intrusion, checked against the dataset's published ATT&CK mapping."""
import pytest
import yaml

from attackgraph.config import AnalysisSettings
from attackgraph.graph.paths import PathQuery
from attackgraph.workspace import Workspace

from .conftest import ROOT

DATA = ROOT / "data" / "real" / "otrf_lsass_campaign_03"


@pytest.fixture(scope="module")
def real(tmp_path_factory):
    from attackgraph.config import DeploymentConfig
    ws = Workspace(DeploymentConfig(neo4j_uri=None, graph_backend="memory", export_dir=tmp_path_factory.mktemp("x")),
                   AnalysisSettings())
    files = ws.load_real()
    return ws, files


def test_heterogeneous_files_all_recognised(real):
    _, files = real
    kinds = {f["file_name"]: f["source_system"] for f in files}
    assert kinds == {"capture_headers_only.pcap": "pcap", "conn.log": "zeek_conn", "dns.log": "zeek_dns",
                     "files.log": "zeek_files", "host_events_used.jsonl": "windows_events", "http.log": "zeek_http",
                     "kerberos.log": "zeek_kerberos"}
    assert all(f["rejected"] == 0 for f in files)


def test_clock_skew_between_sources_is_corrected(real):
    ws, files = real
    host = next(f for f in files if f["source_system"] == "windows_events")
    assert any("clock corrected by 7:00:00" in n for n in host["format_notes"])
    assert host["first_event"].startswith("2023-08-18T15:5")


def test_network_evidence_joins_the_host(real):
    ws, _ = real
    assert ws.graph.ip_to_host["192.168.1.42"] == "host:PRD01"


def test_every_observable_ground_truth_technique_is_detected(real):
    ws, _ = real
    meta = yaml.safe_load((DATA / "ground_truth_metadata.yaml").read_text())
    expected = {m["technique"] for m in meta["attack_mappings"] if "TA0042" not in (m.get("tactics") or [])}
    detected = {e.technique.split(".")[0] for e in ws.graph.events.values() if e.category == "alert"}
    assert expected <= detected, expected - detected


def test_incident_hypotheses_and_path(real):
    ws, _ = real
    assert len(ws.incidents) == 1 and ws.incidents[0]["priority"] in {"High", "Critical"}
    h = ws.hypotheses(ws.incidents[0]["id"])
    scores = {x["id"]: x["score"] for x in h["hypotheses"]}
    assert h["leading"] == "H1" and scores["H6"] < 0 and scores["H5"] < scores["H1"]
    top = h["hypotheses"][0]
    assert not top["contradicting"] and all(s["evidence"] for s in top["supporting"])
    res = ws.paths(PathQuery(source="user:pedro.gustavo", targets=["process:PRD01/lsass.exe"], max_hops=6))
    assert res["total_valid_paths"] >= 1


def test_exfiltration_seen_only_in_the_packet_capture(real):
    ws, _ = real
    exfil = [e for e in ws.graph.events.values() if e.category == "alert" and e.facts.get("rule_id") == "AGL-D12"]
    assert exfil and all(ws.graph.events[e.related_event_ids[0]].source_system == "pcap" for e in exfil)
    assert float(exfil[0].facts["why"].split(" MB")[0]) > 50


def test_detections_cite_their_evidence(real):
    ws, _ = real
    for a in (e for e in ws.graph.events.values() if e.category == "alert"):
        assert a.related_event_ids[0] in ws.graph.events and a.facts["why"]
