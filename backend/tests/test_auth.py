import pytest
from fastapi.testclient import TestClient

from attackgraph.api.app import create_app
from attackgraph.auth import AuthStore

H = {"X-Requested-With": "agl"}
PW = "demo-password-123"


@pytest.fixture
def auth_deploy(deploy, tmp_path):
    return deploy.model_copy(update={"auth_db": tmp_path / "auth.sqlite3", "demo_password": PW, "show_demo_logins": True})


@pytest.fixture
def app(auth_deploy):
    return create_app(store=AuthStore(auth_deploy.auth_db), deploy=auth_deploy)


def login(app, username, password=PW):
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/api/auth/login", json={"username": username, "password": password}, headers=H)
    assert r.status_code == 200, r.text
    return c


def test_everything_requires_sign_in(app):
    c = TestClient(app, raise_server_exceptions=False)
    for path in ("/api/summary", "/api/incidents", "/api/graph", "/api/events", "/api/evidence/manifest", "/api/auth/me"):
        assert c.get(path).status_code == 401, path
    assert c.post("/api/datasets/clear", headers=H).status_code == 401
    assert c.get("/api/health").status_code == 200
    cfg = c.get("/api/auth/config").json()
    assert cfg["auth_required"] and cfg["signup"] and len(cfg["demo_accounts"]) == 4


def test_login_cookie_flags_and_wrong_password(app):
    c = TestClient(app, raise_server_exceptions=False)
    bad = c.post("/api/auth/login", json={"username": "analyst", "password": "wrong-password"}, headers=H)
    assert bad.status_code == 401 and "wrong username or password" in bad.text
    ok = c.post("/api/auth/login", json={"username": "analyst", "password": PW}, headers=H)
    assert ok.status_code == 200
    cookie = ok.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie and "agl_session=" in cookie
    me = c.get("/api/auth/me").json()
    assert me["role"] == "analyst" and me["org"]["name"].startswith("Demo NBFC") and me["permissions"]["manage"]


def test_login_rate_limit_counts_failures_per_account(app):
    c = TestClient(app, raise_server_exceptions=False)
    for _ in range(5):
        assert c.post("/api/auth/login", json={"username": "viewer", "password": PW}, headers=H).status_code == 200
    codes = [c.post("/api/auth/login", json={"username": "analyst", "password": "nope-nope-nope"}, headers=H).status_code
             for _ in range(10)]
    assert codes[:8] == [401] * 8 and codes[-1] == 429
    assert c.post("/api/auth/login", json={"username": "analyst", "password": PW}, headers=H).status_code == 429
    assert c.post("/api/auth/login", json={"username": "itadmin", "password": PW}, headers=H).status_code == 200


def test_demo_orgs_have_stable_ids_and_env_devices(auth_deploy, tmp_path):
    from attackgraph.auth import DEMO_ORG_A
    secret = "ab" * 32
    d = auth_deploy.model_copy(update={"edge_devices": '[{"id": "dev_unoq01", "name": "UNOQ-RACK-01", "location": "Server room A", "secret": "' + secret + '"}]'})
    store = AuthStore(d.auth_db)
    create_app(store=store, deploy=d)
    assert {o["id"] for o in store.orgs()} >= {DEMO_ORG_A}
    dev = store.device("dev_unoq01")
    assert dev["org_id"] == DEMO_ORG_A and dev["secret"] == secret
    create_app(store=store, deploy=d)
    assert len(store.devices(DEMO_ORG_A)) == 1


def test_csrf_header_required_for_state_changes(app):
    c = login(app, "analyst")
    assert c.post("/api/datasets/clear").status_code == 403
    assert c.post("/api/datasets/clear", headers=H).status_code == 200


def test_roles(app):
    viewer = login(app, "viewer")
    assert viewer.get("/api/summary").status_code == 200
    assert viewer.post("/api/datasets/sample", headers=H).status_code == 403
    assert login(app, "itadmin").post("/api/datasets/sample", headers=H).status_code == 403
    assert viewer.post("/api/datasets/clear", headers=H).status_code == 403
    assert viewer.post("/api/entities/user:sameer/status", json={"status": "confirmed"}, headers=H).status_code == 403
    itadmin = login(app, "itadmin")
    assert itadmin.post("/api/stream/flush", headers=H).status_code == 200
    assert itadmin.post("/api/datasets/clear", headers=H).status_code == 403
    assert itadmin.put("/api/settings", json={}, headers=H).status_code == 403
    analyst = login(app, "analyst")
    assert analyst.post("/api/entities/user:sameer/status", json={"status": "confirmed"}, headers=H).status_code == 200


def test_organisations_are_isolated(app):
    a = login(app, "analyst")
    b = login(app, "client-b")
    assert a.get("/api/summary").json()["events"] > 1000
    sb = b.get("/api/summary").json()
    assert sb["events"] == 0 and sb["incidents"] == 0
    assert b.get("/api/entities/user:sameer").status_code == 404
    assert b.get("/api/blast-radius/user:sameer").status_code == 404
    b.post("/api/datasets/sample", headers=H)
    b.post("/api/datasets/clear", headers=H)
    assert a.get("/api/summary").json()["events"] > 1000


def test_signup_creates_isolated_org_and_logout(app):
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/api/auth/signup", json={"organisation": "Acme Finance", "username": "acme.soc",
                                          "password": "a-long-password", "load_sample": False}, headers=H)
    assert r.status_code == 200 and r.json()["org"]["name"] == "Acme Finance"
    assert c.get("/api/summary").json()["events"] == 0
    assert c.post("/api/auth/signup", json={"organisation": "X Y", "username": "acme.soc", "password": "a-long-password"},
                  headers=H).status_code == 409
    assert c.post("/api/auth/signup", json={"organisation": "Short pw", "username": "shorty", "password": "short"},
                  headers=H).status_code == 422
    c.post("/api/auth/logout", headers=H)
    assert c.get("/api/summary").status_code == 401


def test_add_user_requires_manage_role(app):
    analyst = login(app, "analyst")
    r = analyst.post("/api/org/users", json={"username": "new.analyst", "password": "another-long-pw", "role": "viewer"}, headers=H)
    assert r.status_code == 200
    assert any(u["username"] == "new.analyst" for u in analyst.get("/api/org/users").json())
    viewer = login(app, "viewer")
    assert viewer.post("/api/org/users", json={"username": "x.y.z", "password": "another-long-pw", "role": "analyst"},
                       headers=H).status_code == 403
    login(app, "new.analyst", "another-long-pw")


def test_regulatory_admin_clock_and_measured_timing(app):
    a = login(app, "analyst")
    inc = a.get("/api/incidents").json()[0]["id"]
    detail = a.get(f"/api/incidents/{inc}").json()
    assert detail["clock"]["certin_due"] and detail["investigation"]["opened_by"] == "analyst"
    reg = a.get(f"/api/incidents/{inc}/regulatory").json()
    assert reg["fields"]["organisation"]["value"].startswith("Demo NBFC")
    assert reg["fields"]["reporting_officer"]["value"] == "officer to complete"
    assert reg["fields"]["affected_systems"]["evidence"] and set(reg["forms"]) == {"cert_in", "rbi_csir", "dpdp_72h"}
    assert any("Server room A" in v for v in reg["fields"]["physical_location"]["value"])
    adm = login(app, "itadmin").get(f"/api/incidents/{inc}/admin").json()
    assert adm["assets"] and adm["containment_options"] and len(adm["summary"]) == 5
    assert adm["assets"][0]["tier"] in {"SUSPECTED_LATERAL_MOVEMENT", "IN_INCIDENT"}
    rep = a.get(f"/api/incidents/{inc}/report?format=html")
    assert rep.status_code == 200 and "Regulator-ready draft" in rep.text and "CERT-In" in rep.text
    again = a.get(f"/api/incidents/{inc}").json()["investigation"]
    assert again["exports"] == 1 and again["seconds_to_first_report"] >= 0
    assert login(app, "viewer").get(f"/api/incidents/{inc}/regulatory").status_code == 200
    assert a.get("/api/incidents/INC-9999/regulatory").status_code == 404


def test_hardening_headers_and_hidden_docs(app):
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/api/health")
    for h in ("content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy",
              "permissions-policy", "cross-origin-opener-policy", "cross-origin-resource-policy"):
        assert h in r.headers, h
    assert r.headers["cache-control"] == "no-store"
    assert c.get("/api/docs").status_code in (401, 404) and c.get("/api/openapi.json").status_code in (401, 404)
    assert c.get("/.well-known/security.txt").text.startswith("Contact:")
