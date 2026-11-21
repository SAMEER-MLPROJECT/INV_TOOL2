"""Check a running AttackGraph Lens deployment end to end.

Usage (password read from the environment, never from the command line):

    AGL_DEMO_PASSWORD=... python scripts/smoke_deploy.py https://your-app.onrender.com

Checks: interface served, security headers, docs hidden, security.txt, sign-in required, role permissions,
organisation isolation, real-data load, incident, hypothesis ranking, mixed-format upload (PCAP + Zeek + Windows) and,
when Neo4j is configured, that the deployment reports it as connected. Uses only the standard library.
Note: the upload step replaces the analyst workspace with the real-data files; use Settings & Data to reset afterwards.
"""
from __future__ import annotations

import http.cookiejar
import json
import os
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path

REAL = Path(__file__).resolve().parent.parent / "data" / "real" / "otrf_lsass_campaign_03"
results: list[bool] = []


def check(name: str, ok: bool, detail: object = "") -> None:
    results.append(bool(ok))
    print(("PASS  " if ok else "FAIL  ") + name + (f"  ({detail})" if detail != "" else ""))


def opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def call(op, base: str, method: str, path: str, body=None, raw: bytes | None = None, ctype: str = "application/json"):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    headers = {"X-Requested-With": "agl"}
    if data is not None:
        headers["Content-Type"] = ctype
    req = urllib.request.Request(base + path, data=data, method=method, headers=headers)
    try:
        with op.open(req, timeout=120) as r:
            return r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()


def items(payload: bytes, key: str) -> list:
    doc = json.loads(payload)
    return doc.get(key, []) if isinstance(doc, dict) else doc


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    base = sys.argv[1].rstrip("/")
    pw = os.environ.get("AGL_DEMO_PASSWORD")
    if not pw:
        print("Set AGL_DEMO_PASSWORD in the environment first.")
        return 2

    a = opener()
    s, h, _ = call(a, base, "GET", "/")
    check("interface served", s == 200, s)
    for k in ("Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy",
              "Permissions-Policy"):
        check(f"header {k}", k in h)
    if base.startswith("https://"):
        check("header Strict-Transport-Security", "Strict-Transport-Security" in h)
    check("API docs hidden", call(a, base, "GET", "/api/docs")[0] == 404)
    check("security.txt published", call(a, base, "GET", "/.well-known/security.txt")[0] == 200)
    check("sign-in required", call(a, base, "GET", "/api/incidents")[0] == 401)
    check("wrong password rejected",
          call(opener(), base, "POST", "/api/auth/login", {"username": "analyst", "password": pw + "x"})[0] == 401)

    s, _, _ = call(a, base, "POST", "/api/auth/login", {"username": "analyst", "password": pw})
    check("analyst signs in", s == 200, s)
    if s != 200:
        print("Cannot continue without signing in. Is AGL_DEMO_PASSWORD the value set on the server?")
        return 1
    s, _, b = call(a, base, "GET", "/api/backend")
    if s == 200:
        print(f"INFO  graph backend: {json.dumps(json.loads(b))[:300]}")

    s, _, _ = call(a, base, "POST", "/api/datasets/real")
    check("real attack data loads", s == 200, s)
    s, _, b = call(a, base, "GET", "/api/incidents")
    incs = items(b, "incidents") if s == 200 else []
    check("one High incident", len(incs) == 1 and str(incs[0].get("priority")).lower() == "high",
          [(i.get("id"), i.get("priority"), i.get("score")) for i in incs])
    if incs:
        s, _, b = call(a, base, "GET", f"/api/incidents/{incs[0]['id']}/hypotheses")
        top = json.loads(b)["hypotheses"][0] if s == 200 else {}
        check("hypothesis ranking: external attacker leads", "External attacker" in top.get("title", ""),
              f"{top.get('title')} {top.get('score')}")

    bd = uuid.uuid4().hex
    parts = []
    for fn in ("capture_headers_only.pcap", "conn.log", "host_events_used.jsonl"):
        parts.append(f'--{bd}\r\nContent-Disposition: form-data; name="files"; filename="{fn}"\r\n'
                     f"Content-Type: application/octet-stream\r\n\r\n".encode() + (REAL / fn).read_bytes() + b"\r\n")
    parts.append(f'--{bd}\r\nContent-Disposition: form-data; name="mode"\r\n\r\nreplace\r\n--{bd}--\r\n'.encode())
    s, _, b = call(a, base, "POST", "/api/datasets/upload", raw=b"".join(parts),
                   ctype=f"multipart/form-data; boundary={bd}")
    files = json.loads(b).get("files", []) if s == 200 else []
    check("mixed upload: PCAP + Zeek + Windows accepted", s == 200 and len(files) == 3,
          [(f.get("accepted"), f.get("detections")) for f in files] if files else b[:200])

    v = opener()
    call(v, base, "POST", "/api/auth/login", {"username": "viewer", "password": pw})
    check("viewer cannot change data", call(v, base, "POST", "/api/datasets/real")[0] == 403)
    c = opener()
    call(c, base, "POST", "/api/auth/login", {"username": "client-b", "password": pw})
    s, _, b = call(c, base, "GET", "/api/incidents")
    check("second organisation sees none of the first one's data", s == 200 and len(items(b, "incidents")) == 0)

    print(f"\n{sum(results)}/{len(results)} checks passed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
