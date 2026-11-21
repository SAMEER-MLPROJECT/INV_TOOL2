"""AttackGraph Lens edge agent for the Arduino UNO Q (Linux side). Python standard library only.

What it reports, as signed and hash-chained envelopes, to POST /api/edge/events:
  * usb_connect / usb_disconnect   from /sys/bus/usb/devices (works on the board and inside an App Lab container)
  * ssh_login / console_login / login_failed   from the systemd journal or /var/log/auth.log, when readable
  * tamper_test   a controlled test event you trigger on purpose (--self-test)
  * heartbeats     every --heartbeat seconds; the reply carries the organisation's top incident priority, which
                   is shown on the LED matrix when the Router Bridge is available (App Lab) or printed otherwise.

Configuration (environment variables or flags):
  AGL_URL            e.g. https://attackgraph-lens.onrender.com
  AGL_DEVICE_ID      dev_... (from Settings -> Edge devices)
  AGL_DEVICE_SECRET  the 64-hex secret shown once when the device was registered
  AGL_ALLOW_USB      comma-separated vendor:product pairs that are expected here, e.g. 046d:0825 (C270 webcam)

Events are evidence with provenance, not verdicts: an unexpected USB device gets severity "medium", an expected
one "info". The server decides nothing on a single physical event.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

LINUX_ROOT_HUB_VENDOR = "1d6b"
SSH_OK = re.compile(r"Accepted (\S+) for (\S+) from (\S+) port")
SSH_FAIL = re.compile(r"Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?(\S+) from (\S+) port")
CONSOLE_OK = re.compile(r"LOGIN ON (\S+) BY (\S+)")
CONSOLE_FAIL = re.compile(r"FAILED LOGIN (?:\(\d+\) )?ON '?(\S+?)'? FOR '?([^',]+)'?")
LED_LEVELS = {0: "Low", 1: "Moderate", 2: "High", 3: "Critical"}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Sender:
    def __init__(self, url: str, device_id: str, secret: str, state_file: Path, timeout: float = 10.0) -> None:
        self.url = url.rstrip("/") + "/api/edge/events"
        self.device_id, self.secret, self.timeout = device_id, secret, timeout
        self.state_file = state_file
        st = {}
        if state_file.is_file():
            try:
                st = json.loads(state_file.read_text())
            except (OSError, json.JSONDecodeError):
                st = {}
        self.seq = int(st.get("seq", 0))
        self.prev_hash = str(st.get("prev_hash", ""))
        self.lock = threading.Lock()

    def _save(self) -> None:
        tmp = self.state_file.with_suffix(".tmp")
        tmp.write_text(json.dumps({"seq": self.seq, "prev_hash": self.prev_hash}))
        os.replace(tmp, self.state_file)

    def send(self, events: list[dict]) -> dict | None:
        with self.lock:
            self.seq += 1
            env = {"device_id": self.device_id, "seq": self.seq, "prev_hash": self.prev_hash, "sent_at": now_iso(),
                   "events": events}
            body = json.dumps(env, separators=(",", ":")).encode()
            sig = hmac.new(self.secret.encode(), body, hashlib.sha256).hexdigest()
            req = urllib.request.Request(self.url, data=body, method="POST", headers={
                "Content-Type": "application/json", "X-AGL-Device": self.device_id, "X-AGL-Signature": sig})
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    out = json.loads(resp.read())
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode(errors="replace")[:300]
                if exc.code == 409:
                    m = re.search(r"<= (\d+)", detail)
                    if m:
                        self.seq = int(m.group(1))
                        self._save()
                        log(f"server is ahead (seq {self.seq}); resynchronised, the next envelope will be flagged as a gap")
                        return None
                self.seq -= 1
                log(f"server rejected envelope: HTTP {exc.code} {detail}")
                return None
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                self.seq -= 1
                log(f"server unreachable ({exc}); will retry")
                return None
            self.prev_hash = hashlib.sha256(body).hexdigest()
            self._save()
            if out.get("flags"):
                log("server flagged: " + "; ".join(out["flags"]))
            return out


def log(msg: str) -> None:
    print(f"{datetime.now().strftime('%H:%M:%S')} {msg}", flush=True)


def usb_snapshot(sysfs: Path) -> dict[str, dict]:
    out: dict[str, dict] = {}
    if not sysfs.is_dir():
        return out
    for d in sysfs.iterdir():
        if ":" in d.name or not (d / "idVendor").is_file():
            continue
        def rd(name: str, d: Path = d) -> str:
            try:
                return (d / name).read_text(errors="replace").strip()
            except OSError:
                return ""
        vid, pid = rd("idVendor").lower(), rd("idProduct").lower()
        if not vid or vid == LINUX_ROOT_HUB_VENDOR:
            continue
        serial = rd("serial") or "noserial"
        out[f"{d.name}|{vid}:{pid}:{serial}"] = {"vendor_id": vid, "product_id": pid, "serial": serial[:60],
                                                 "product": rd("product")[:80], "manufacturer": rd("manufacturer")[:80],
                                                 "port": d.name}
    return out


def watch_usb(q: queue.Queue, sysfs: Path, allow: set[str], interval: float, stop: threading.Event) -> None:
    prev = usb_snapshot(sysfs)
    log(f"USB watch on {sysfs}: {len(prev)} device(s) present at start")
    for key, info in prev.items():
        log(f"  present: {info['vendor_id']}:{info['product_id']} {info['product'] or info['manufacturer']}")
    while not stop.wait(interval):
        cur = usb_snapshot(sysfs)
        for key in cur.keys() - prev.keys():
            q.put(usb_event("usb_connect", cur[key], allow))
        for key in prev.keys() - cur.keys():
            q.put(usb_event("usb_disconnect", prev[key], allow))
        prev = cur


def usb_event(kind: str, info: dict, allow: set[str]) -> dict:
    expected = f"{info['vendor_id']}:{info['product_id']}" in allow
    ev = {"event_type": kind, "timestamp": now_iso(), **{k: info[k] for k in ("vendor_id", "product_id", "serial", "product",
                                                                              "manufacturer", "port")},
          "expected_device": expected, "severity": "info" if expected else ("medium" if kind == "usb_connect" else "low")}
    log(f"{kind}: {info['vendor_id']}:{info['product_id']} {info['product'] or info['manufacturer']} "
        f"({'expected' if expected else 'NOT on the allow-list'})")
    return ev


def parse_login(line: str) -> dict | None:
    for rx, kind in ((SSH_OK, "ssh_login"), (SSH_FAIL, "login_failed"), (CONSOLE_OK, "console_login"), (CONSOLE_FAIL, "login_failed")):
        m = rx.search(line)
        if not m:
            continue
        if rx is SSH_OK:
            return {"event_type": kind, "user": m.group(2), "src_ip": m.group(3), "method": m.group(1), "severity": "low"}
        if rx is SSH_FAIL:
            return {"event_type": kind, "user": m.group(1), "src_ip": m.group(2), "method": "ssh", "severity": "medium"}
        if rx is CONSOLE_OK:
            return {"event_type": kind, "user": m.group(2), "tty": m.group(1), "severity": "medium"}
        return {"event_type": kind, "user": m.group(2).strip(), "tty": m.group(1), "method": "console", "severity": "medium"}
    return None


def watch_logins(q: queue.Queue, stop: threading.Event) -> None:
    if shutil.which("journalctl"):
        cmd = ["journalctl", "-f", "-n", "0", "-o", "cat", "SYSLOG_IDENTIFIER=sshd", "+", "SYSLOG_IDENTIFIER=login"]
    elif Path("/var/log/auth.log").is_file():
        cmd = ["tail", "-n", "0", "-F", "/var/log/auth.log"]
    else:
        log("login watch disabled: no journalctl and no /var/log/auth.log readable here")
        return
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    except OSError as exc:
        log(f"login watch disabled: {exc}")
        return
    log("login watch: " + " ".join(cmd))
    for line in proc.stdout:
        if stop.is_set():
            break
        ev = parse_login(line)
        if ev:
            ev["timestamp"] = now_iso()
            log(f"{ev['event_type']}: user={ev.get('user')} from={ev.get('src_ip') or ev.get('tty')}")
            q.put(ev)
    proc.terminate()


class Led:
    """Shows the organisation's top incident priority on the UNO Q LED matrix via the Router Bridge (App Lab)."""

    def __init__(self) -> None:
        self.bridge = None
        try:
            from arduino.app_utils import Bridge  # type: ignore
            self.bridge = Bridge
        except Exception:  # noqa: BLE001
            self.bridge = None
        self.level = None

    def show(self, level: int) -> None:
        if level == self.level:
            return
        self.level = level
        if self.bridge is not None:
            try:
                self.bridge.call("set_level", int(level))
            except Exception as exc:  # noqa: BLE001
                log(f"LED bridge call failed: {exc}")
        log(f"top incident priority: {LED_LEVELS.get(level, level)} (LED level {level})")


def run(args: argparse.Namespace) -> int:
    for name in ("url", "device_id", "secret"):
        if not getattr(args, name):
            print(f"missing --{name.replace('_', '-')} (or the matching AGL_ environment variable)", file=sys.stderr)
            return 2
    sender = Sender(args.url, args.device_id, args.secret, Path(args.state))
    led = Led()
    allow = {a.strip().lower() for a in (args.allow_usb or "").split(",") if a.strip()}
    started = sender.send([{"event_type": "agent_start", "timestamp": now_iso(), "severity": "info",
                            "agent": "attackgraph-edge 1.0", "allow_list": sorted(allow)}])
    if started is None:
        log("first envelope was not accepted; check the URL, device id and secret")
    else:
        led.show(started.get("led_level", 0))
    if args.self_test:
        out = sender.send([{"event_type": "tamper_test", "timestamp": now_iso(), "severity": "medium",
                            "detail": "controlled test event triggered by the operator (--self-test)"}])
        log("self-test " + ("accepted" if out else "FAILED"))
        return 0 if out else 1

    q: queue.Queue = queue.Queue(maxsize=10_000)
    stop = threading.Event()
    threading.Thread(target=watch_usb, args=(q, Path(args.sysfs), allow, args.interval, stop), daemon=True).start()
    if not args.no_logins:
        threading.Thread(target=watch_logins, args=(q, stop), daemon=True).start()
    pending: list[dict] = []
    last_beat = 0.0
    try:
        while True:
            try:
                pending.append(q.get(timeout=0.5))
                while len(pending) < 100:
                    pending.append(q.get_nowait())
            except queue.Empty:
                pass
            due = time.monotonic() - last_beat >= args.heartbeat
            if pending or due:
                out = sender.send(pending)
                if out is not None:
                    pending = []
                    last_beat = time.monotonic()
                    led.show(out.get("led_level", 0))
                elif len(pending) > 5000:
                    pending = pending[-5000:]
                else:
                    time.sleep(min(30, args.heartbeat))
    except KeyboardInterrupt:
        stop.set()
        return 0


def _file_config() -> dict:
    for p in (Path(__file__).with_name("edge_config.json"), Path.home() / ".agl_edge_config.json"):
        if p.is_file():
            try:
                return {k.upper(): str(v) for k, v in json.loads(p.read_text()).items()}
            except (OSError, json.JSONDecodeError):
                log(f"could not read {p}")
    return {}


def main(argv: list[str] | None = None) -> int:
    for k, v in _file_config().items():
        os.environ.setdefault(k, v)
    ap = argparse.ArgumentParser(description="AttackGraph Lens UNO Q edge agent")
    ap.add_argument("--url", default=os.environ.get("AGL_URL"))
    ap.add_argument("--device-id", default=os.environ.get("AGL_DEVICE_ID"))
    ap.add_argument("--secret", default=os.environ.get("AGL_DEVICE_SECRET"))
    ap.add_argument("--allow-usb", default=os.environ.get("AGL_ALLOW_USB", ""))
    ap.add_argument("--state", default=os.environ.get("AGL_STATE", str(Path.home() / ".agl_edge_state.json")))
    ap.add_argument("--sysfs", default="/sys/bus/usb/devices")
    ap.add_argument("--interval", type=float, default=1.0)
    ap.add_argument("--heartbeat", type=float, default=15.0)
    ap.add_argument("--no-logins", action="store_true")
    ap.add_argument("--self-test", action="store_true", help="send one controlled tamper_test event and exit")
    return run(ap.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
