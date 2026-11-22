# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately to the maintainers (use GitHub's *Report a vulnerability* /
private security advisory on this repository) rather than opening a public issue. Include steps to reproduce and the
affected version. We aim to acknowledge reports within 7 days.

## Intended deployment

The hosted API requires a session and checks the user's role and organisation for workspace operations. Use HTTPS
and set `AGL_COOKIE_SECURE=1`. For an invite-only deployment, set `AGL_ALLOW_SIGNUP=0` and create individual
accounts for reviewers.

The Blueprint sets `AGL_SHOW_DEMO_LOGINS=1` for public demonstrations. In that mode the sign-in page and
`/api/auth/config` publish the shared evaluator password. Set it to `0` before deploying a private workspace.
Rotate the evaluator password if it was previously displayed.

## Evidence and credentials

Uploaded files and exported reports can contain usernames, hosts, IP addresses and original event records.
The optional Neo4j backend retains evidence by organisation. SQLite stores accounts, sessions and device state.
Protect both stores and keep real uploads, exports, database files and credentials out of Git.

## Built-in controls

- Session cookies use HttpOnly and SameSite=Strict. The login and signup endpoints throttle repeated attempts.
- Browser requests that change API state require the `X-Requested-With: agl` header. The edge ingest endpoint
  authenticates signed device envelopes.
- The upload endpoint bounds file count and file size. Packet captures have a separate per-file limit.
- Graph queries have hop and expansion limits. The Neo4j adapter binds query parameters.
- The HTTP middleware sets a content security policy, frame and MIME-type protections, and HSTS on HTTPS.
  API responses passing through the middleware carry `Cache-Control: no-store`.
