from __future__ import annotations

import hashlib
import hmac
import logging
import re
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

log = logging.getLogger(__name__)

ROLES = ("analyst", "itadmin", "viewer")
CAN_INGEST = {"analyst", "itadmin"}
CAN_INVESTIGATE = {"analyst", "itadmin"}
CAN_MANAGE = {"analyst"}

USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,39}$")
ORG_NAME_RE = re.compile(r"^[\w .,&()'-]{2,60}$")
MIN_PASSWORD = 10
SESSION_HOURS = 8
SCRYPT = dict(n=2 ** 14, r=8, p=1, dklen=32)

SCHEMA = """
CREATE TABLE IF NOT EXISTS orgs (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL, sample INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, org_id TEXT NOT NULL REFERENCES orgs(id),
  role TEXT NOT NULL, pw_salt BLOB NOT NULL, pw_hash BLOB NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), expires_at REAL NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS devices (
  id TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES orgs(id), name TEXT NOT NULL, location TEXT NOT NULL,
  secret TEXT NOT NULL, last_seq INTEGER NOT NULL DEFAULT 0, last_hash TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
"""


class AuthError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass(frozen=True)
class User:
    id: str
    username: str
    org_id: str
    org_name: str
    role: str

    def public(self) -> dict:
        return {"username": self.username, "role": self.role, "org": {"id": self.org_id, "name": self.org_name},
                "permissions": {"ingest": self.role in CAN_INGEST, "investigate": self.role in CAN_INVESTIGATE,
                                "manage": self.role in CAN_MANAGE}}


def _now() -> str:
    return datetime.now(UTC).isoformat()


def hash_password(password: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    salt = salt or secrets.token_bytes(16)
    return salt, hashlib.scrypt(password.encode(), salt=salt, **SCRYPT)


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class RateLimiter:
    def __init__(self, limit: int, window_s: float) -> None:
        self.limit, self.window = limit, window_s
        self._hits: dict[str, list[float]] = {}
        self._lock = threading.RLock()

    def _recent(self, key: str, now: float) -> list[float]:
        return [t for t in self._hits.get(key, []) if now - t < self.window]

    def blocked(self, key: str) -> bool:
        with self._lock:
            return len(self._recent(key, time.monotonic())) >= self.limit

    def record(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            self._hits[key] = self._recent(key, now) + [now]
            if len(self._hits) > 10_000:
                self._hits = {k: v for k, v in self._hits.items() if v and now - v[-1] < self.window}

    def hit(self, key: str) -> bool:
        with self._lock:
            if self.blocked(key):
                return False
            self.record(key)
            return True


class AuthStore:
    def __init__(self, path: Path, max_orgs: int = 50) -> None:
        self.path = path
        self.max_orgs = max_orgs
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA foreign_keys = ON")
        self._db.executescript(SCHEMA)
        self.login_limiter = RateLimiter(8, 300)
        self.client_limiter = RateLimiter(60, 300)
        self.signup_limiter = RateLimiter(5, 3600)

    def _q(self, sql: str, params: tuple = ()) -> list[tuple]:
        with self._lock:
            return self._db.execute(sql, params).fetchall()

    def org_count(self) -> int:
        return self._q("SELECT count(*) FROM orgs")[0][0]

    def orgs(self) -> list[dict]:
        return [{"id": r[0], "name": r[1], "sample": bool(r[2])} for r in self._q("SELECT id, name, sample FROM orgs ORDER BY created_at")]

    def create_org(self, name: str, sample: bool = False, org_id: str | None = None) -> str:
        name = name.strip()
        if not ORG_NAME_RE.match(name):
            raise AuthError(422, "organisation name must be 2-60 letters, digits, spaces or . , & ( ) ' -")
        if self.org_count() >= self.max_orgs:
            raise AuthError(409, "this deployment has reached its organisation limit")
        org_id = org_id or "org_" + secrets.token_hex(6)
        self._q("INSERT INTO orgs (id, name, created_at, sample) VALUES (?, ?, ?, ?)", (org_id, name, _now(), int(sample)))
        return org_id

    def create_user(self, username: str, password: str, org_id: str, role: str) -> str:
        username = username.strip().lower()
        if not USERNAME_RE.match(username):
            raise AuthError(422, "username must be 3-40 characters: lowercase letters, digits, . _ -")
        if role not in ROLES:
            raise AuthError(422, f"role must be one of {', '.join(ROLES)}")
        if len(password) < MIN_PASSWORD or len(password) > 200:
            raise AuthError(422, f"password must be {MIN_PASSWORD}-200 characters")
        if not self._q("SELECT 1 FROM orgs WHERE id = ?", (org_id,)):
            raise AuthError(404, "organisation not found")
        salt, digest = hash_password(password)
        uid = "usr_" + secrets.token_hex(6)
        try:
            self._q("INSERT INTO users (id, username, org_id, role, pw_salt, pw_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (uid, username, org_id, role, salt, digest, _now()))
        except sqlite3.IntegrityError:
            raise AuthError(409, "that username is taken") from None
        return uid

    def org_exists(self, org_id: str) -> bool:
        return bool(self._q("SELECT 1 FROM orgs WHERE id = ?", (org_id,)))

    def user_org(self, username: str) -> str | None:
        rows = self._q("SELECT org_id FROM users WHERE username = ?", (username.strip().lower(),))
        return rows[0][0] if rows else None

    def set_password(self, username: str, password: str) -> None:
        salt, digest = hash_password(password)
        self._q("UPDATE users SET pw_salt = ?, pw_hash = ? WHERE username = ?", (salt, digest, username.strip().lower()))

    def users(self, org_id: str) -> list[dict]:
        rows = self._q("SELECT username, role, created_at FROM users WHERE org_id = ? ORDER BY created_at", (org_id,))
        return [{"username": r[0], "role": r[1], "created_at": r[2]} for r in rows]

    def authenticate(self, username: str, password: str, client: str) -> str:
        uname = (username or "").strip().lower()
        akey, ckey = f"login:{uname}", f"client:{client}"
        if self.login_limiter.blocked(akey) or self.client_limiter.blocked(ckey):
            raise AuthError(429, "too many failed sign-in attempts; wait a few minutes")
        row = self._q("SELECT id, pw_salt, pw_hash FROM users WHERE username = ?", (uname,))
        ok = False
        if row:
            uid, salt, digest = row[0]
            ok = hmac.compare_digest(hash_password(password or "", salt)[1], digest)
        else:
            hash_password(password or "x")
        if not ok:
            self.login_limiter.record(akey)
            self.client_limiter.record(ckey)
            raise AuthError(401, "wrong username or password")
        token = secrets.token_urlsafe(32)
        expires = time.time() + SESSION_HOURS * 3600
        self._q("DELETE FROM sessions WHERE expires_at < ?", (time.time(),))
        self._q("INSERT INTO sessions (token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
                (_token_hash(token), uid, expires, _now()))
        return token

    def user_for_token(self, token: str | None) -> User | None:
        if not token or len(token) > 200:
            return None
        rows = self._q("SELECT u.id, u.username, u.org_id, o.name, u.role, s.expires_at FROM sessions s "
                       "JOIN users u ON u.id = s.user_id JOIN orgs o ON o.id = u.org_id WHERE s.token_hash = ?",
                       (_token_hash(token),))
        if not rows or rows[0][5] < time.time():
            return None
        r = rows[0]
        return User(id=r[0], username=r[1], org_id=r[2], org_name=r[3], role=r[4])

    def logout(self, token: str | None) -> None:
        if token:
            self._q("DELETE FROM sessions WHERE token_hash = ?", (_token_hash(token),))

    def create_device(self, org_id: str, name: str, location: str, dev_id: str | None = None, secret: str | None = None) -> dict:
        name, location = name.strip(), location.strip()
        if not re.match(r"^[A-Za-z0-9._-]{2,40}$", name):
            raise AuthError(422, "device name must be 2-40 letters, digits, . _ -")
        if not re.match(r"^[A-Za-z0-9 ._-]{2,60}$", location):
            raise AuthError(422, "location must be 2-60 letters, digits, spaces, . _ -")
        if self._q("SELECT 1 FROM devices WHERE org_id = ? AND name = ?", (org_id, name)):
            raise AuthError(409, "a device with that name already exists")
        dev_id = dev_id or "dev_" + secrets.token_hex(6)
        secret = secret or secrets.token_hex(32)
        self._q("INSERT INTO devices (id, org_id, name, location, secret, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (dev_id, org_id, name, location, secret, _now()))
        return {"id": dev_id, "name": name, "location": location, "secret": secret}

    def devices(self, org_id: str) -> list[dict]:
        rows = self._q("SELECT id, name, location, last_seq, created_at FROM devices WHERE org_id = ? ORDER BY created_at", (org_id,))
        return [{"id": r[0], "name": r[1], "location": r[2], "last_seq": r[3], "created_at": r[4]} for r in rows]

    def device(self, dev_id: str) -> dict | None:
        rows = self._q("SELECT id, org_id, name, location, secret, last_seq, last_hash FROM devices WHERE id = ?", (dev_id,))
        if not rows:
            return None
        r = rows[0]
        return {"id": r[0], "org_id": r[1], "name": r[2], "location": r[3], "secret": r[4], "last_seq": r[5], "last_hash": r[6]}

    def advance_device(self, dev_id: str, seq: int, last_hash: str) -> None:
        self._q("UPDATE devices SET last_seq = ?, last_hash = ? WHERE id = ?", (seq, last_hash, dev_id))


DEMO_ORG_A = "org_demo_nbfc"
DEMO_ORG_B = "org_demo_client_b"


def bootstrap_demo(store: AuthStore, password: str) -> list[dict]:
    """Make the evaluator accounts match AGL_DEMO_PASSWORD on every start: create the demo organisations and
    accounts that are missing and reset existing evaluator accounts to the configured password. Accounts that people
    created themselves are never touched; a username taken by another organisation is skipped with a warning."""
    if len(password) < MIN_PASSWORD:
        raise AuthError(422, f"AGL_DEMO_PASSWORD must be at least {MIN_PASSWORD} characters")
    if not store.org_exists(DEMO_ORG_A):
        store.create_org("Demo NBFC (synthetic data)", sample=True, org_id=DEMO_ORG_A)
    if not store.org_exists(DEMO_ORG_B):
        store.create_org("Second client (empty)", sample=False, org_id=DEMO_ORG_B)
    accounts = [("analyst", DEMO_ORG_A, "analyst"), ("itadmin", DEMO_ORG_A, "itadmin"), ("viewer", DEMO_ORG_A, "viewer"),
                ("client-b", DEMO_ORG_B, "analyst")]
    created = []
    for username, org, role in accounts:
        owner = store.user_org(username)
        if owner is None:
            store.create_user(username, password, org, role)
            created.append({"username": username, "role": role})
        elif owner == org:
            store.set_password(username, password)
        else:
            log.warning("evaluator account %s not created: the username belongs to another organisation", username)
    return created


def session_expiry() -> datetime:
    return datetime.now(UTC) + timedelta(hours=SESSION_HOURS)


def provision_devices(store: AuthStore, spec: str | None) -> list[str]:
    """AGL_EDGE_DEVICES: JSON list of {"id", "name", "location", "secret", "org"?}. Lets a device keep working on hosts
    whose disk is wiped on restart. The secret must be 64 hex characters."""
    if not spec:
        return []
    import json
    out = []
    for d in json.loads(spec):
        if not re.fullmatch(r"dev_[a-z0-9_]{3,40}", str(d.get("id", ""))) or not re.fullmatch(r"[0-9a-f]{64}", str(d.get("secret", ""))):
            raise ValueError("AGL_EDGE_DEVICES entries need id 'dev_...' and a 64-hex secret")
        if store.device(d["id"]) is None:
            store.create_device(d.get("org", DEMO_ORG_A), d["name"], d["location"], dev_id=d["id"], secret=d["secret"])
            out.append(d["id"])
    return out
