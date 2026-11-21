import json
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from attackgraph.api.app import create_app
from attackgraph.auth import AuthStore
from attackgraph.edge import sign

H = {"X-Requested-With": "agl"}
PW = "demo-password-123"


@pytest.fixture
def setup(deploy, tmp_path):
    d = deploy.model_copy(update={"auth_db": tmp_path / "auth.sqlite3", "demo_password": PW})
    store = AuthStore(d.auth_db)
    app = create_app(store=store, deploy=d)
    analyst = TestClient(app, raise_server_exceptions=False)
    assert analyst.post("/api/auth/login", json={"username": "analyst", "password": PW}, headers=H).status_code == 200
    dev = analyst.post("/api/org/devices", json={"name": "UNOQ-RACK-01", "location": "Server room A"}, headers=H).json()
    assert dev["secret"] and len(dev["secret"]) == 64
    return app, analyst, dev


class Device:
    def __init__(self, dev):
        self.dev, self.seq, self.prev = dev, 0, ""

    def envelope(self, events, seq=None, prev=None, sent_at=None):
        import hashlib
        self.seq = seq if seq is not None else self.seq + 1
        env = {"device_id": self.dev["id"], "seq": self.seq, "prev_hash": self.prev if prev is None else prev,
               "sent_at": sent_at or datetime.now(UTC).isoformat(), "events": events}
        body = json.dumps(env).encode()
        self.prev = hashlib.sha256(body).hexdigest()
        return body

    def post(self, client, body, secret=None):
        return client.post("/api/edge/events", content=body, headers={
            "X-AGL-Device": self.dev["id"], "X-AGL-Signature": sign(secret or self.dev["secret"], body),
            "Content-Type": "application/json"})


def usb(ts, vid="0781", pid="5567", serial="AB12", product="Cruzer Blade", severity="medium"):
    return {"event_type": "usb_connect", "timestamp": ts, "vendor_id": vid, "product_id": pid, "serial": serial,
            "product": product, "severity": severity}


def test_signed_events_enter_the_graph_and_timeline(setup):
    app, analyst, dev = setup
    d = Device(dev)
    now = datetime.now(UTC)
    r = d.post(TestClient(app), d.envelope([
        usb(now.isoformat()),
        {"event_type": "console_login", "timestamp": (now + timedelta(minutes=1)).isoformat(), "user": "svc_backup", "severity": "low"},
        {"event_type": "login_failed", "timestamp": (now + timedelta(minutes=2)).isoformat(), "user": "root", "src_ip": "10.10.9.9"},
    ]))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["accepted"] == 3 and body["flags"] == [] and body["led_level"] in (0, 1, 2, 3)
    ents = {e["id"]: e for e in analyst.get("/api/entities?limit=5000").json()}
    assert "device:usb:0781:5567:AB12" in ents and "location:Server room A" in ents and "user:svc_backup" in ents
    rel = analyst.get("/api/relationships/device:usb:0781:5567:AB12|PLUGGED_INTO|host:UNOQ-RACK-01").json()
    assert rel["occurrences"][0]["rule"] == "R-PHY-01"
    evs = analyst.get("/api/events?source=edge_physical").json()
    assert evs["total"] == 3
    ev = analyst.get(f"/api/events/{evs['events'][0]['uid']}").json()
    assert ev["raw"]["signature"] == "verified" and ev["raw"]["location"] == "Server room A"


def test_bad_signature_replay_and_clock_are_rejected(setup):
    app, _, dev = setup
    c = TestClient(app, raise_server_exceptions=False)
    d = Device(dev)
    now = datetime.now(UTC).isoformat()
    body = d.envelope([usb(now)])
    assert d.post(c, body, secret="0" * 64).status_code == 401
    assert d.post(c, body).status_code == 200
    assert d.post(c, body).status_code == 409
    stale = d.envelope([], sent_at=(datetime.now(UTC) - timedelta(hours=2)).isoformat())
    assert d.post(c, stale).status_code == 400
    forged = json.dumps({"device_id": "dev_nope", "seq": 1, "sent_at": now, "events": []}).encode()
    assert c.post("/api/edge/events", content=forged, headers={"X-AGL-Device": "dev_nope", "X-AGL-Signature": "x"}).status_code == 401


def test_gaps_and_broken_chain_are_flagged_as_evidence(setup):
    app, analyst, dev = setup
    c = TestClient(app, raise_server_exceptions=False)
    d = Device(dev)
    assert d.post(c, d.envelope([])).json()["flags"] == []
    r = d.post(c, d.envelope([], seq=5)).json()
    assert any("sequence gap: 3" in f for f in r["flags"])
    r = d.post(c, d.envelope([], prev="f" * 64)).json()
    assert any("hash chain broken" in f for f in r["flags"])
    alerts = [e for e in analyst.get("/api/events?source=edge_physical&limit=50").json()["events"]
              if "integrity" in e["uid"]]
    assert len(alerts) == 2


def test_device_cannot_claim_another_location_or_org(setup):
    app, analyst, dev = setup
    d = Device(dev)
    ev = usb(datetime.now(UTC).isoformat())
    ev["location"] = "CEO office"
    assert d.post(TestClient(app), d.envelope([ev])).status_code == 200
    assert "location:CEO office" not in {e["id"] for e in analyst.get("/api/entities?limit=5000").json()}
    other = TestClient(app, raise_server_exceptions=False)
    other.post("/api/auth/login", json={"username": "client-b", "password": PW}, headers=H)
    assert other.get("/api/events?source=edge_physical").json()["total"] == 0
    assert other.get("/api/org/devices").json() == []


def test_only_manage_role_registers_devices(setup):
    app, _, _ = setup
    v = TestClient(app, raise_server_exceptions=False)
    v.post("/api/auth/login", json={"username": "itadmin", "password": PW}, headers=H)
    assert v.post("/api/org/devices", json={"name": "UNOQ-2", "location": "Branch rack"}, headers=H).status_code == 403
    assert [x["name"] for x in v.get("/api/org/devices").json()] == ["UNOQ-RACK-01"]
