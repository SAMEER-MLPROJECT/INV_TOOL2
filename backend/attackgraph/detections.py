"""Built-in detection rules for raw host, network and memory evidence.

Each rule looks at one normalised event and, when it matches, emits an alert event that cites the matched event,
names the rule, the MITRE ATT&CK technique and the exact reason. Alerts are evidence for correlation and hypothesis
ranking, never verdicts on their own.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

from .models import NormalizedEvent

USER_DIR = re.compile(r"\\users\\[^\\]+\\(downloads|desktop|documents|appdata\\local\\temp)\\|\\windows\\temp\\|\\temp\\", re.I)
DISCOVERY = {"systeminfo.exe": ("T1082", "system information discovery"), "whoami.exe": ("T1033", "system owner/user discovery"),
             "tasklist.exe": ("T1057", "process discovery"), "quser.exe": ("T1033", "system owner/user discovery"),
             "nltest.exe": ("T1482", "domain trust discovery"), "ipconfig.exe": ("T1016", "network configuration discovery"),
             "net.exe": ("T1087", "account discovery"), "net1.exe": ("T1087", "account discovery")}
COMMON_PORTS = {20, 21, 22, 25, 53, 67, 68, 80, 88, 110, 123, 135, 137, 138, 139, 143, 389, 443, 445, 465, 587, 636, 993,
                995, 1900, 3268, 3269, 3389, 5355, 5985, 5986, 8080, 8443}
VM_READ = 0x10
BENIGN_LSASS_READERS = {"svchost.exe", "wmiprvse.exe", "msmpeng.exe", "vboxservice.exe", "csrss.exe", "wininit.exe"}
EXFIL_BYTES = 10 * 1024 * 1024


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    technique: str
    severity: float
    test: Callable[[NormalizedEvent], str | None]


def _image(ev: NormalizedEvent) -> str:
    return str(ev.raw.get("Image") or ev.raw.get("NewProcessName") or ev.raw.get("SourceImage") or "")


def _cmd(ev: NormalizedEvent) -> str:
    return str(ev.facts.get("cmdline") or "")


def d01(ev):
    if ev.action == "process_start" and USER_DIR.search(_image(ev)) and ev.process not in {"rundll32.exe"}:
        return f"{ev.process} started from {_image(ev)} by {ev.user or 'unknown user'} (parent {ev.parent_process})"


def d02(ev):
    if ev.action in {"process_start", "memory_cmdline"} and ev.process in DISCOVERY:
        t, what = DISCOVERY[ev.process]
        return f"{what}: {_cmd(ev) or ev.process} (parent {ev.parent_process})"


def d03(ev):
    det = str(ev.facts.get("details") or "")
    if ev.action == "service_install" and (re.search(r"rundll32|\\temp\\|\\users\\|powershell|cmd(\.exe)? /c|%comspec%", det, re.I)):
        return f"service {ev.service} runs: {det[:160]}"


def d04(ev):
    if ev.process == "rundll32.exe" and ev.action in {"process_start", "memory_cmdline"} and \
            re.search(r"\\temp\\|\\users\\|appdata", _cmd(ev), re.I) and "comsvcs" not in _cmd(ev).lower():
        return f"rundll32 loads a DLL from a user/temp folder: {_cmd(ev)[:160]}"


def d05(ev):
    c = _cmd(ev).lower()
    if ev.action in {"process_start", "memory_cmdline", "script_block"} and "comsvcs" in c and "minidump" in c:
        return f"comsvcs.dll MiniDump: {_cmd(ev)[:200]}"
    if ev.action == "script_block" and re.search(r"comsvcs.*minidump|mini[dD]ump.*lsass", str(ev.facts.get("script")), re.I):
        return "PowerShell script dumps LSASS"


def d06(ev):
    if ev.action != "lsass_access" or ev.process in BENIGN_LSASS_READERS:
        return None
    try:
        mask = int(str(ev.facts.get("granted") or "0"), 16)
    except ValueError:
        return None
    if mask & VM_READ:
        return f"{ev.process} opened lsass.exe with access mask {ev.facts.get('granted')} (includes PROCESS_VM_READ)"


def d07(ev):
    if ev.action == "lsass_access" and ev.facts.get("calltrace_unknown"):
        return f"{ev.process} accessed lsass.exe from code not backed by a file on disk (CallTrace UNKNOWN)"


def d08(ev):
    f = str(ev.facts.get("file") or "")
    if ev.action == "file_create" and f.lower().endswith(".dmp") and ("lsass" in f.lower() or ev.process == "rundll32.exe"):
        return f"{ev.process} wrote memory dump {f}"


def d09(ev):
    if ev.action == "script_block":
        return f"script block: {str(ev.facts.get('script'))[:160]}"


def d10(ev):
    if ev.action == "network_connect" and USER_DIR.search(_image(ev)):
        return f"{ev.process} (from {_image(ev)}) connected to {ev.dst_ip}:{ev.dst_port}"


def d11(ev):
    uri, mime = str(ev.facts.get("uri") or ""), str(ev.facts.get("mime") or "")
    if (ev.action.startswith("http:") and re.search(r"\.(exe|dll|ps1|hta|scr|bat)(\?|$)", uri, re.I)) or \
            "dosexec" in mime:
        return f"executable transferred from {ev.dst_ip}: {uri or mime}"


def d12(ev):
    if ev.action.startswith("flow:") and (ev.facts.get("orig_bytes") or 0) >= EXFIL_BYTES and ev.dst_port != 53:
        return f"{ev.facts['orig_bytes'] / 1e6:.1f} MB sent from {ev.src_ip} to {ev.dst_ip}:{ev.dst_port}"


def d13(ev):
    if ev.action.startswith("flow:tcp") and (ev.facts.get("duration") or 0) >= 60 and ev.dst_port not in COMMON_PORTS and \
            (ev.facts.get("orig_bytes") or 0) + (ev.facts.get("resp_bytes") or 0) >= 100_000:
        return (f"{ev.facts['duration']:.0f} s session {ev.src_ip} -> {ev.dst_ip}:{ev.dst_port}, "
                f"{((ev.facts.get('orig_bytes') or 0) + (ev.facts.get('resp_bytes') or 0)) / 1e3:.0f} kB")


def d14(ev):
    if ev.action == "memory_injection" and "EXECUTE_READWRITE" in str(ev.facts.get("protection") or "").upper():
        return (f"{ev.process} (PID {ev.process_id}) holds RWX memory"
                + (" starting with an MZ header" if ev.facts.get("mz") else ""))


RULES = [
    Rule("AGL-D01", "Executable launched from a user-writable folder", "T1204.002", 0.6, d01),
    Rule("AGL-D02", "Discovery command", "T1082", 0.3, d02),
    Rule("AGL-D03", "Service created that runs code from a temp or user folder", "T1543.003", 0.75, d03),
    Rule("AGL-D04", "rundll32 loading a DLL from a temp or user folder", "T1218.011", 0.7, d04),
    Rule("AGL-D05", "LSASS memory dump via comsvcs.dll MiniDump", "T1003.001", 0.95, d05),
    Rule("AGL-D06", "LSASS opened with memory-read rights", "T1003.001", 0.8, d06),
    Rule("AGL-D07", "LSASS accessed from injected (unbacked) code", "T1055", 0.85, d07),
    Rule("AGL-D08", "Process memory dump file written", "T1003.001", 0.8, d08),
    Rule("AGL-D09", "Suspicious PowerShell script block", "T1059.001", 0.6, d09),
    Rule("AGL-D10", "Binary from a user-writable folder opened a network connection", "T1071", 0.65, d10),
    Rule("AGL-D11", "Executable downloaded over the network", "T1105", 0.7, d11),
    Rule("AGL-D12", "Large outbound transfer (possible exfiltration)", "T1041", 0.75, d12),
    Rule("AGL-D13", "Long-lived session on a non-standard port (possible command and control)", "T1071", 0.55, d13),
    Rule("AGL-D14", "Executable code injected into process memory", "T1055", 0.85, d14),
]
RULES_BY_ID = {r.id: r for r in RULES}


def detect(ev: NormalizedEvent) -> list[NormalizedEvent]:
    out = []
    for rule in RULES:
        why = rule.test(ev)
        if not why:
            continue
        technique = DISCOVERY[ev.process][0] if rule.id == "AGL-D02" and ev.process in DISCOVERY else rule.technique
        ents = []
        if ev.user:
            ents.append(f"user:{ev.user}")
        host = ev.src_host or ev.dst_host
        if host:
            ents.append(f"{'ip' if re.fullmatch(r'[0-9.:a-fA-F]+', host) and any(ch.isdigit() for ch in host) and ('.' in host or ':' in host) else 'host'}:{host}")
        elif ev.src_ip:
            ents.append(f"ip:{ev.src_ip}")
        if rule.id in {"AGL-D10", "AGL-D11", "AGL-D12", "AGL-D13"} and ev.dst_ip:
            ents.append(f"ip:{ev.dst_ip}")
        out.append(NormalizedEvent(
            uid=f"agl_detect:{ev.uid}:{rule.id}", event_id=f"{ev.event_id}:{rule.id}", timestamp=ev.timestamp,
            source_system="agl_detect", source_file=ev.source_file, source_row=ev.source_row, category="alert",
            action="detection", outcome="open", severity=rule.severity, alert_name=rule.name, technique=technique,
            disposition="undetermined", related_event_ids=[ev.uid], alert_entities=sorted(set(ents)),
            facts={"rule_id": rule.id, "why": why, "matched_event": ev.uid},
            raw={"rule_id": rule.id, "rule": rule.name, "technique": technique, "why": why, "matched_event": ev.uid,
                 "generated_by": "AttackGraph Lens built-in detection rules"}))
    return out
