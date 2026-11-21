from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta

from .auth import AuthError, AuthStore, RateLimiter

MAX_ENVELOPE_BYTES = 256 * 1024
MAX_EVENTS = 200
CLOCK_TOLERANCE = timedelta(minutes=10)
LED_LEVEL = {"Critical": 3, "High": 2, "Moderate": 1, "Low": 0}

device_limiter = RateLimiter(240, 60)


def sign(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def verify_envelope(store: AuthStore, device_id: str, signature: str, body: bytes,
                    now: datetime | None = None) -> tuple[dict, dict, list[str]]:
    """Check signature, replay and hash chain. Returns (device, envelope, integrity flags).

    A bad signature or a replayed sequence number is rejected. A sequence gap or a broken hash chain is accepted but
    flagged, because the evidence that arrived is still genuine and the gap itself is worth investigating."""
    now = now or datetime.now(UTC)
    if len(body) > MAX_ENVELOPE_BYTES:
        raise AuthError(413, "envelope too large")
    dev = store.device(device_id or "")
    if dev is None:
        raise AuthError(401, "unknown device")
    if not device_limiter.hit(dev["id"]):
        raise AuthError(429, "device is sending too fast")
    if not hmac.compare_digest(sign(dev["secret"], body), (signature or "").lower()):
        raise AuthError(401, "bad signature")
    try:
        env = json.loads(body)
    except json.JSONDecodeError:
        raise AuthError(400, "envelope is not JSON") from None
    if not isinstance(env, dict) or env.get("device_id") != dev["id"]:
        raise AuthError(400, "envelope device_id does not match the signing device")
    seq = env.get("seq")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
        raise AuthError(400, "seq must be a positive integer")
    if seq <= dev["last_seq"]:
        raise AuthError(409, f"replayed or out-of-order envelope (seq {seq} <= {dev['last_seq']})")
    try:
        sent = datetime.fromisoformat(str(env.get("sent_at")).replace("Z", "+00:00"))
        if sent.tzinfo is None:
            raise ValueError
    except ValueError:
        raise AuthError(400, "sent_at must be an ISO-8601 time with a timezone") from None
    if abs(now - sent) > CLOCK_TOLERANCE:
        raise AuthError(400, "sent_at is more than 10 minutes from server time; check the device clock (NTP)")
    events = env.get("events", [])
    if not isinstance(events, list) or len(events) > MAX_EVENTS:
        raise AuthError(400, f"events must be a list of at most {MAX_EVENTS}")
    flags = []
    if dev["last_seq"] and seq != dev["last_seq"] + 1:
        flags.append(f"sequence gap: {seq - dev['last_seq'] - 1} envelope(s) missing before seq {seq}")
    if dev["last_seq"] and env.get("prev_hash") != dev["last_hash"]:
        flags.append("hash chain broken: prev_hash does not match the last envelope received")
    digest = hashlib.sha256(body).hexdigest()
    store.advance_device(dev["id"], seq, digest)
    env["_hash"] = digest
    return dev, env, flags


def to_records(dev: dict, env: dict, flags: list[str]) -> list[dict]:
    """Server-side fields win: the device's registered name and location are stamped on every event, so a device
    cannot claim to be somewhere else."""
    out = []
    for i, e in enumerate(env.get("events") or []):
        if not isinstance(e, dict):
            continue
        rec = {k: v for k, v in e.items() if isinstance(k, str) and len(k) <= 40}
        rec.update({"device_id": dev["name"], "location": dev["location"], "envelope_seq": env["seq"],
                    "envelope_sha256": env["_hash"], "signature": "verified"})
        rec.setdefault("host", dev["name"])
        rec["event_id"] = f"{dev['name']}-{env['seq']}-{i}" if not e.get("event_id") else f"{dev['name']}-{str(e['event_id'])[:60]}"
        out.append(rec)
    for j, flag in enumerate(flags):
        out.append({"device_id": dev["name"], "location": dev["location"], "host": dev["name"],
                    "event_id": f"{dev['name']}-{env['seq']}-integrity-{j}", "event_type": "integrity_alert",
                    "timestamp": env["sent_at"], "severity": "high", "detail": flag, "envelope_seq": env["seq"],
                    "envelope_sha256": env["_hash"], "signature": "verified"})
    return out
