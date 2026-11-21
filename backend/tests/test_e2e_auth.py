"""Browser tests of the signed-in product: the SOC analyst journey, the IT admin journey, roles and isolation."""
from __future__ import annotations

import os
import socket
import threading
import time

import pytest

from .conftest import ROOT

pytestmark = pytest.mark.e2e
DIST = ROOT / "frontend" / "dist"
playwright = pytest.importorskip("playwright.sync_api")
PW = "evaluator-pass-2026"


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    if not (DIST / "index.html").is_file():
        pytest.skip("frontend not built")
    import uvicorn

    from attackgraph.api.app import create_app
    from attackgraph.auth import AuthStore
    from attackgraph.config import DeploymentConfig

    tmp = tmp_path_factory.mktemp("auth")
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    d = DeploymentConfig(frontend_dist=DIST, graph_backend="memory", neo4j_uri=None, export_dir=tmp / "exports",
                         auth_db=tmp / "auth.sqlite3", demo_password=PW, show_demo_logins=True)
    srv = uvicorn.Server(uvicorn.Config(create_app(store=AuthStore(d.auth_db), deploy=d), host="127.0.0.1", port=port, log_level="warning"))
    t = threading.Thread(target=srv.run, daemon=True)
    t.start()
    for _ in range(100):
        if srv.started:
            break
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    srv.should_exit = True
    t.join(timeout=5)


@pytest.fixture(scope="module")
def browser():
    with playwright.sync_playwright() as p:
        try:
            b = p.chromium.launch(executable_path=os.environ.get("AGL_CHROME") or None)
        except Exception as exc:  # pragma: no cover
            pytest.skip(f"no Chromium available: {exc}")
        yield b
        b.close()


def sign_in(browser, server, username):
    ctx = browser.new_context(viewport={"width": 1500, "height": 950})
    pg = ctx.new_page()
    errors: list[str] = []
    pg.on("pageerror", lambda e: errors.append(str(e)))
    pg.goto(server)
    pg.get_by_label("Username").fill(username)
    pg.get_by_label("Password").fill(PW)
    pg.get_by_role("button", name="Sign in").last.click()
    pg.get_by_text("Start here").wait_for(timeout=10_000)
    return ctx, pg, errors


def test_login_page_and_wrong_password(server, browser):
    ctx = browser.new_context()
    pg = ctx.new_page()
    pg.goto(server)
    pg.get_by_text("Evaluator accounts (synthetic data only)").wait_for()
    pg.get_by_label("Username").fill("analyst")
    pg.get_by_label("Password").fill("not-the-password")
    pg.get_by_role("button", name="Sign in").last.click()
    pg.get_by_text("wrong username or password").wait_for()
    ctx.close()


def test_analyst_journey_end_to_end(server, browser):
    ctx, pg, errors = sign_in(browser, server, "analyst")
    pg.get_by_text("SOC analyst journey").wait_for()
    pg.goto(server + "/#/incidents")
    pg.get_by_text("CERT-In 6-hour clock").first.wait_for()
    pg.get_by_role("button", name="Regulator-ready draft").first.click()
    pg.get_by_text("DRAFT for human review").wait_for()
    pg.get_by_text("officer to complete").first.wait_for()
    pg.get_by_role("tab", name="DPDP Rules 2025").click()
    pg.get_by_text("detailed report to the Data Protection Board").wait_for()
    with pg.expect_download() as dl:
        pg.get_by_role("link", name="HTML").click()
    assert dl.value.suggested_filename.endswith("_report.html")
    pg.goto(server + "/#/paths?source=user:sameer")
    assert not errors, errors
    ctx.close()


def test_it_admin_journey_and_role_limits(server, browser):
    ctx, pg, errors = sign_in(browser, server, "itadmin")
    pg.get_by_text("IT infrastructure admin journey").wait_for()
    pg.goto(server + "/#/infrastructure")
    pg.get_by_text("Incident summary for infrastructure").wait_for()
    pg.get_by_text("Affected infrastructure").wait_for()
    pg.get_by_text("Containment options (simulated)").wait_for()
    pg.get_by_text("FINANCE-DB").first.wait_for()
    pg.get_by_text("Server room A").first.wait_for()
    pg.goto(server + "/#/settings")
    assert pg.get_by_role("button", name="Clear all data").is_disabled()
    assert not errors, errors
    ctx.close()


def test_second_organisation_sees_nothing_and_logout(server, browser):
    ctx, pg, errors = sign_in(browser, server, "client-b")
    pg.get_by_text("This workspace is empty").wait_for()
    pg.get_by_role("button", name="Sign out").click()
    pg.get_by_text("Evaluator accounts (synthetic data only)").wait_for()
    pg.goto(server + "/#/incidents")
    pg.get_by_text("Evaluator accounts (synthetic data only)").wait_for()
    assert not errors, errors
    ctx.close()


def test_real_attack_data_hypotheses_and_pcap_upload(server, browser):
    ctx, pg, errors = sign_in(browser, server, "analyst")
    pg.goto(server + "/#/settings")
    pg.get_by_role("button", name="Load real attack data (OTRF)").click()
    pg.get_by_text("Real attack dataset loaded").wait_for(timeout=20_000)
    pg.get_by_text("clock corrected by 7:00:00").first.wait_for()
    pg.goto(server + "/#/incidents")
    pg.get_by_role("heading", name="Competing hypotheses").wait_for(timeout=15_000)
    pg.get_by_text("External attacker: malware foothold, then credential theft is best supported").wait_for()
    pg.get_by_text("Authorised administration or security testing (benign)").wait_for()
    pg.goto(server + "/#/settings")
    pg.get_by_label("Dataset files").set_input_files(str(ROOT / "data" / "real" / "otrf_lsass_campaign_03" / "capture_headers_only.pcap"))
    pg.get_by_role("button", name="Upload").first.click()
    pg.get_by_text("packet capture: 12238 packets").first.wait_for(timeout=20_000)
    assert not errors, errors
    ctx.close()
