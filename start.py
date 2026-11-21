"""One-step launcher for AttackGraph Lens: python start.py   (or double-click START.bat / start.command).

First run: checks Python, creates a private environment (.venv), installs the packages, creates .env with a fresh
evaluator password shown on the sign-in page, starts the app and opens the browser. Later runs start in seconds.

    python start.py            local only: http://127.0.0.1:8000
    python start.py --uno      also reachable from the Arduino UNO Q on the same Wi-Fi (prints the address to use)
    python start.py --port 8001 --no-browser
"""
from __future__ import annotations

import argparse
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import venv
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV = ROOT / ".venv"
VPY = VENV / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
ENV = ROOT / ".env"


def say(msg: str) -> None:
    print(f"[AttackGraph Lens] {msg}", flush=True)


def fail(msg: str) -> None:
    say("ERROR: " + msg)
    sys.exit(1)


def ensure_python() -> None:
    if sys.version_info < (3, 11):
        fail(f"Python 3.11 or newer is needed (this is {sys.version.split()[0]}). "
             "Install it from https://www.python.org/downloads/ and tick 'Add python.exe to PATH'.")


def ensure_venv() -> None:
    marker = VENV / ".agl_installed"
    req = (ROOT / "requirements.txt").read_bytes()
    if marker.exists() and marker.read_bytes() == req and VPY.exists():
        return
    if not VPY.exists():
        say("First run: creating a private Python environment (.venv) ...")
        venv.EnvBuilder(with_pip=True).create(VENV)
    say("Installing packages (about 1-3 minutes the first time) ...")
    r = subprocess.run([str(VPY), "-m", "pip", "install", "--disable-pip-version-check", "-q",
                        "-r", str(ROOT / "requirements.txt")])
    if r.returncode != 0:
        fail("package installation failed. Check the internet connection and run this again.")
    marker.write_bytes(req)


def _set(lines: list[str], key: str, value: str) -> list[str]:
    for i, line in enumerate(lines):
        if line.split("=", 1)[0].strip() == key:
            lines[i] = f"{key}={value}"
            return lines
    return lines + [f"{key}={value}"]


def _get(lines: list[str], key: str) -> str:
    """Same rules as the app: first non-empty value wins; quotes removed; a note after ' #' is ignored."""
    for line in lines:
        if line.lstrip().startswith("#") or line.split("=", 1)[0].strip() != key:
            continue
        raw = line.split("=", 1)[1].strip()
        value = raw[1:-1] if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "\"'" else re.split(r"(?:^|\s+)#", raw, maxsplit=1)[0].strip()
        if value:
            return value
    return ""


def repair_files() -> None:
    """Fix two things Windows users hit: Notepad saving .env as .env.txt, and an account database that an older
    version stored under backend/'# default data/' (a note in .env was read as the path)."""
    txt = ROOT / ".env.txt"
    if txt.is_file() and not ENV.exists():
        txt.rename(ENV)
        say("Renamed .env.txt to .env (Notepad had added '.txt').")
    elif txt.is_file():
        say("Note: both .env and .env.txt exist. Only .env is used; copy your changes into it and delete .env.txt.")
    stray = ROOT / "backend" / "# default data" / "agl_auth.sqlite3"
    target = ROOT / "data" / "agl_auth.sqlite3"
    if stray.is_file() and not target.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
        stray.rename(target)
        try:
            stray.parent.rmdir()
        except OSError:
            pass
        say("Moved the sign-in database to data/agl_auth.sqlite3.")


def ensure_env() -> None:
    created = False
    if not ENV.exists():
        shutil.copyfile(ROOT / ".env.example", ENV)
        created = True
    lines = ENV.read_text(encoding="utf-8").splitlines()
    if not _get(lines, "AGL_DEMO_PASSWORD"):
        lines = _set(lines, "AGL_DEMO_PASSWORD", secrets.token_urlsafe(9))
        lines = _set(lines, "AGL_SHOW_DEMO_LOGINS", "1")
        ENV.write_text("\n".join(lines) + "\n", encoding="utf-8")
        db = ROOT / "data" / "agl_auth.sqlite3"
        if db.exists():  # evaluator accounts are only created into an empty account database
            db.rename(db.with_name(f"agl_auth.backup-{int(time.time())}.sqlite3"))
        say(("Created .env" if created else "Updated .env") + " with a new evaluator password "
            "(shown on the sign-in page; change it in .env if you like).")


def lan_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            return s.getsockname()[0]
    except OSError:
        return socket.gethostbyname(socket.gethostname())


def open_when_ready(port: int) -> None:
    url = f"http://127.0.0.1:{port}"
    for _ in range(120):
        try:
            urllib.request.urlopen(url + "/api/health", timeout=1)
            webbrowser.open(url)
            return
        except OSError:
            time.sleep(0.5)


def main() -> None:
    ap = argparse.ArgumentParser(description="Start AttackGraph Lens")
    ap.add_argument("--uno", action="store_true", help="listen on the local network so the UNO Q can connect")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--no-browser", action="store_true")
    a = ap.parse_args()

    ensure_python()
    if not (ROOT / "frontend" / "dist" / "index.html").exists():
        fail("frontend/dist is missing. Re-extract the zip, or build it with: cd frontend && npm ci && npm run build")
    ensure_venv()
    repair_files()
    ensure_env()

    host = "0.0.0.0" if a.uno else "127.0.0.1"
    pw = _get(ENV.read_text(encoding="utf-8").splitlines(), "AGL_DEMO_PASSWORD")
    say(f"Open http://127.0.0.1:{a.port}   sign in as: analyst / itadmin / viewer / client-b   password: {pw}")
    if a.uno:
        say(f"UNO Q setting: \"AGL_URL\": \"http://{lan_ip()}:{a.port}\"   (PC and board on the same Wi-Fi; "
            "allow Python through the Windows firewall if asked)")
    env_lines = ENV.read_text(encoding="utf-8").splitlines()
    if _get(env_lines, "AGL_GRAPH_BACKEND").lower() == "neo4j":
        say("Neo4j: " + ("configured (" + _get(env_lines, "NEO4J_URI").split("@")[-1] + ")" if _get(env_lines, "NEO4J_URI")
                         else "AGL_GRAPH_BACKEND=neo4j but NEO4J_URI is empty in .env"))
    say("Press Ctrl+C in this window to stop.")
    if not a.no_browser:
        threading.Thread(target=open_when_ready, args=(a.port,), daemon=True).start()
    proc = subprocess.Popen([str(VPY), "-m", "attackgraph", "serve", "--host", host, "--port", str(a.port)],
                            cwd=ROOT / "backend")
    try:
        sys.exit(proc.wait())
    except KeyboardInterrupt:
        proc.terminate()
        proc.wait(timeout=10)
        say("Stopped.")


if __name__ == "__main__":
    main()
