# ArgosX remediation log

Status: **PENDING**. No ArgosX scan has been run yet. Nothing below is a scan result.

| | Due | Report file | Run at | Findings (critical / high / medium / low) |
|---|---|---|---|---|
| Baseline scan | 21 Nov, 23:59 | `security/argosx_baseline.pdf` | | |
| Final scan | 22 Nov, 11:00 | `security/argosx_final.pdf` | | |

## Findings

One row per finding from the baseline report. Fill "Fix" and "Verification" from what was actually done.

| # | Finding (as ArgosX words it) | Severity | Component | Fix implemented | Verification | Remaining risk and why it is acceptable |
|---|---|---|---|---|---|---|
| 1 | | | | | | |

## Controls already in place before the baseline scan

These were built during the finale. They are listed so that a finding can be checked against them, not as a claim
that the scanner will agree.

| Control | Where |
|---|---|
| Every API route except health, sign-in config, sign-in and sign-up requires a session | `api/app.py` `_ws_for` |
| Roles: viewer read-only; IT admin cannot clear data, change settings or register devices | `auth.py`, `tests/test_auth.py` |
| Organisation isolation: one workspace and one Neo4j key space per organisation | `orgs.py`, `tests/test_auth.py`, `tests/test_persistence.py` |
| Passwords hashed with scrypt (n=2^14, r=8, p=1, 16-byte salt); 10-character minimum | `auth.py` |
| Session tokens: 256-bit random, stored only as SHA-256, HttpOnly, SameSite=Strict, Secure over https, 8 h expiry | `auth.py`, `api/app.py` |
| CSRF: state-changing requests need `X-Requested-With: agl` (forces a CORS pre-flight cross-site) | `api/app.py` middleware |
| Sign-in throttling: 8 failed attempts per account and 60 per client in 5 minutes | `auth.py` |
| Headers: CSP, X-Frame-Options DENY, nosniff, Referrer-Policy, Permissions-Policy, COOP, HSTS over https, no-store on API | `api/app.py` |
| Uploads: extension allow-list, size and record limits, parsed as data and never executed | `ingest/loader.py` |
| Edge devices: HMAC-SHA256 per device, replay rejection, ±10 min clock check, hash chain, server-side location | `edge.py`, `tests/test_edge.py` |
| Cypher: values always passed as parameters; hop bounds validated | `store/neo4j_store.py`, `tests/test_neo4j_adapter.py` |
| Errors: unhandled exceptions return a reference id, no stack trace | `api/app.py` |
| Dependencies: `pip-audit` and `npm audit` reported 0 known vulnerabilities on 21 Nov | run before the baseline scan |

## Known, accepted risks to explain if raised

* **Evaluator password shown on the sign-in page** when `AGL_SHOW_DEMO_LOGINS=1`. Intentional for judging; those
  accounts only reach synthetic data. Turn it off after judging.
* **Device secrets stored in plain text in the auth database.** The server needs the secret to verify the HMAC; the
  production fix is a KMS or hardware-backed key on the device.
* **`/api/docs` is public.** It documents routes; every data route still requires sign-in.
