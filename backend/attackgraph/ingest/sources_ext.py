"""Adapters for heterogeneous real-world evidence: Windows / Sysmon event logs, Zeek network logs, packet captures
(via ingest.formats) and Volatility 3 memory-forensics output.

Events that carry no investigative value (image loads, registry noise, PowerShell module logging, benign LSASS reads by
the hypervisor agent ...) are *filtered*, not rejected: they are counted per reason in the file summary so an analyst
can see exactly what was left out and why.
"""
from __future__ import annotations

import re
from typing import Any

from .normalize import NormalizationError, clean, norm_host, norm_ip, norm_process, norm_user, to_int


class SkipRecord(Exception):
    """Record understood but deliberately not used (reported as 'filtered', not 'rejected')."""


def _host(r: dict[str, Any]) -> str:
    raw = clean(r.get("Hostname") or r.get("Computer") or r.get("host"))
    if raw and not norm_ip(raw):
        raw = raw.split(".")[0]
    h = norm_host(raw)
    if not h:
        raise NormalizationError("event has no Hostname/Computer")
    return h


def _sev(x: float) -> float:
    return round(max(0.0, min(1.0, x)), 2)


USER_DIRS = re.compile(r"\\users\\[^\\]+\\(downloads|desktop|appdata\\local\\temp|documents)\\|\\windows\\temp\\|\\temp\\", re.I)


# ---------------------------------------------------------------- Windows Security / Sysmon / PowerShell / System

def windows_event(r: dict[str, Any]) -> dict[str, Any]:
    ch = str(r.get("Channel") or r.get("SourceName") or "")
    try:
        eid = int(r.get("EventID"))
    except (TypeError, ValueError):
        raise NormalizationError("EventID missing or not a number") from None
    host = _host(r)
    sysmon = "Sysmon" in ch
    base = {"src_host": host, "outcome": "observed", "severity": 0.0}
    if sysmon and eid == 1 or ch == "Security" and eid == 4688:
        image = r.get("Image") or r.get("NewProcessName")
        cmd = clean(r.get("CommandLine"))
        sev = 0.05
        if image and USER_DIRS.search(str(image)):
            sev = 0.45
        return {**base, "category": "process", "action": "process_start", "severity": _sev(sev),
                "user": norm_user(r.get("User") or r.get("SubjectUserName")), "process": norm_process(image),
                "process_id": clean(r.get("ProcessId") or r.get("NewProcessId")),
                "parent_process": norm_process(r.get("ParentImage") or r.get("ParentProcessName")),
                "parent_process_id": clean(r.get("ParentProcessId")), "_cmdline": cmd}
    if sysmon and eid == 3:
        dst = norm_ip(r.get("DestinationIp"))
        if dst is None or str(r.get("Initiated")).lower() not in {"true", "1"}:
            raise SkipRecord("Sysmon 3: inbound or unparseable connection")
        if dst.startswith(("224.", "239.", "255.", "ff0")) or dst.endswith(".255"):
            raise SkipRecord("Sysmon 3: multicast/broadcast")
        return {**base, "category": "network", "action": "network_connect", "user": norm_user(r.get("User")),
                "process": norm_process(r.get("Image")), "process_id": clean(r.get("ProcessId")),
                "src_ip": norm_ip(r.get("SourceIp")), "dst_ip": dst, "dst_port": to_int(r.get("DestinationPort")),
                "severity": 0.45 if r.get("Image") and USER_DIRS.search(str(r.get("Image"))) else 0.0}
    if sysmon and eid == 10:
        tgt = str(r.get("TargetImage") or "").lower()
        if not tgt.endswith("lsass.exe"):
            raise SkipRecord("Sysmon 10: process access not targeting LSASS")
        src = str(r.get("SourceImage") or "")
        if norm_process(src) in {"vboxservice.exe", "msmpeng.exe", "csrss.exe", "wininit.exe", "lsm.exe"} and \
                "UNKNOWN" not in str(r.get("CallTrace")):
            raise SkipRecord("Sysmon 10: LSASS read by a known system/agent process")
        return {**base, "category": "privilege", "action": "lsass_access", "user": norm_user(r.get("SourceUser")),
                "process": norm_process(src), "process_id": clean(r.get("SourceProcessId")), "target_user": "system",
                "_granted": clean(r.get("GrantedAccess")), "_calltrace_unknown": "UNKNOWN" in str(r.get("CallTrace")),
                "severity": 0.2}
    if sysmon and eid == 11:
        fn = str(r.get("TargetFilename") or "")
        if not fn.lower().endswith((".dmp", ".exe", ".dll", ".ps1", ".bat")) or "\\windows\\winsxs\\" in fn.lower():
            raise SkipRecord("Sysmon 11: file type not tracked")
        return {**base, "category": "process", "action": "file_create", "user": norm_user(r.get("User")),
                "process": norm_process(r.get("Image")), "process_id": clean(r.get("ProcessId")), "_file": fn[-200:],
                "severity": 0.3 if fn.lower().endswith(".dmp") else 0.05}
    if sysmon and eid in (12, 13):
        obj = str(r.get("TargetObject") or "")
        m = re.search(r"\\Services\\([^\\]+)\\ImagePath$", obj, re.I)
        if not m:
            raise SkipRecord("Sysmon 12/13: registry change outside service configuration")
        return {**base, "category": "service", "action": "service_install", "process": norm_process(r.get("Image")),
                "process_id": clean(r.get("ProcessId")), "service": m.group(1)[:80], "_details": str(r.get("Details"))[:300],
                "user": norm_user(r.get("User")), "severity": 0.3}
    if ch == "System" and eid == 7045:
        return {**base, "category": "service", "action": "service_install", "process": "services.exe",
                "service": clean(r.get("ServiceName")) or "unknown", "_details": str(r.get("ImagePath"))[:300],
                "severity": 0.3}
    if sysmon and eid == 22:
        q = clean(r.get("QueryName"))
        if not q:
            raise SkipRecord("Sysmon 22: empty query")
        return {**base, "category": "dns", "action": "query", "domain": q.rstrip(".").lower()[:200],
                "process": norm_process(r.get("Image")), "src_ip": None, "_src_host": host}
    if ch == "Security" and eid in (4624, 4625):
        user = norm_user(r.get("TargetUserName"))
        if not user or user.endswith("$") or user in {"system", "local service", "network service", "dwm-1", "umfd-0"}:
            raise SkipRecord("Security 4624/4625: machine or service account logon")
        ip = norm_ip(r.get("IpAddress"))
        return {**base, "category": "authentication", "action": f"logon_type_{clean(r.get('LogonType')) or '?'}",
                "outcome": "success" if eid == 4624 else "failure", "user": user, "dst_host": host,
                "src_host": ip if ip and ip not in {"127.0.0.1", "::1"} else None, "src_ip": ip,
                "severity": 0.1 if eid == 4625 else 0.0}
    if ch == "Security" and eid == 4672:
        raise SkipRecord("Security 4672: special privileges at logon (context only)")
    if "PowerShell" in ch and eid == 4104:
        text = str(r.get("ScriptBlockText") or r.get("Message") or "")
        if not re.search(r"mimikatz|minidump|comsvcs|downloadstring|frombase64string|invoke-expression|iex\s*\(|-enc", text, re.I):
            raise SkipRecord("PowerShell 4104: script block without suspicious content")
        return {**base, "category": "process", "action": "script_block", "process": "powershell.exe",
                "_script": text[:500], "severity": 0.5}
    raise SkipRecord(f"{ch or 'unknown channel'} {eid}: event type not used by the analysis")


def windows_event_id(r: dict[str, Any]) -> str | None:
    rid = r.get("EventRecordID") or r.get("RecordNumber") or r.get("RecordId")
    return f"{_host(r)}-{r.get('Channel')}-{rid}" if rid not in (None, "") else None


# ---------------------------------------------------------------- Zeek

def _zeek_base(r: dict[str, Any]) -> dict[str, Any]:
    src, dst = norm_ip(r.get("id.orig_h")), norm_ip(r.get("id.resp_h"))
    if src is None or dst is None:
        raise NormalizationError("invalid id.orig_h / id.resp_h")
    return {"src_ip": src, "dst_ip": dst, "dst_port": to_int(r.get("id.resp_p"))}


def zeek_conn(r: dict[str, Any]) -> dict[str, Any]:
    b = _zeek_base(r)
    if b["dst_ip"].startswith(("224.", "239.", "255.", "ff0")) or b["dst_ip"].endswith(".255"):
        raise SkipRecord("conn: multicast/broadcast")
    return {**b, "category": "network", "action": f"flow:{(clean(r.get('proto')) or 'ip').lower()}"
            + (f"/{r['service']}" if clean(r.get("service")) else ""), "outcome": "allowed", "severity": 0.0,
            "_orig_bytes": to_int(r.get("orig_bytes")) or 0, "_resp_bytes": to_int(r.get("resp_bytes")) or 0,
            "_duration": float(r.get("duration") or 0)}


def zeek_dns(r: dict[str, Any]) -> dict[str, Any]:
    b = _zeek_base(r)
    q = clean(r.get("query"))
    if not q:
        raise SkipRecord("dns: no query name")
    answers = [a for a in str(r.get("answers") or "").split(",") if norm_ip(a)]
    return {"category": "dns", "action": f"query:{(clean(r.get('qtype_name')) or 'A').upper()}",
            "outcome": (clean(r.get("rcode_name")) or "NOERROR").upper(), "severity": 0.0, "src_ip": b["src_ip"],
            "domain": q.rstrip(".").lower()[:200], "dst_ip": norm_ip(answers[0]) if answers else None}


def zeek_http(r: dict[str, Any]) -> dict[str, Any]:
    b = _zeek_base(r)
    return {**b, "category": "network", "action": f"http:{(clean(r.get('method')) or '?').upper()}", "outcome": "allowed",
            "severity": 0.0, "_uri": str(r.get("uri") or "")[:300], "_host_header": clean(r.get("host")),
            "_mime": clean(r.get("resp_mime_types"))}


def zeek_files(r: dict[str, Any]) -> dict[str, Any]:
    tx, rx = norm_ip(r.get("tx_hosts")), norm_ip(r.get("rx_hosts"))
    if (tx is None or rx is None) and r.get("id.orig_h"):
        orig, resp = norm_ip(r.get("id.orig_h")), norm_ip(r.get("id.resp_h"))
        sent_by_orig = str(r.get("is_orig")).upper() in {"T", "TRUE"}
        tx, rx = (orig, resp) if sent_by_orig else (resp, orig)
    if tx is None or rx is None:
        raise NormalizationError("files.log needs tx_hosts/rx_hosts or id.orig_h/id.resp_h")
    return {"category": "network", "action": f"file_transfer:{(clean(r.get('source')) or '?').lower()}",
            "outcome": "allowed", "severity": 0.0, "src_ip": rx, "dst_ip": tx, "_mime": clean(r.get("mime_type")),
            "_size": to_int(r.get("seen_bytes")) or to_int(r.get("total_bytes"))}


def zeek_kerberos(r: dict[str, Any]) -> dict[str, Any]:
    b = _zeek_base(r)
    user = norm_user(str(r.get("client") or "").split("/")[0])
    if not user:
        raise SkipRecord("kerberos: no client principal")
    ok = str(r.get("success")).upper() in {"T", "TRUE"}
    return {"category": "authentication", "action": f"kerberos_{(clean(r.get('request_type')) or '?').lower()}",
            "outcome": "success" if ok else "failure", "user": user, "src_host": b["src_ip"], "dst_host": b["dst_ip"],
            "src_ip": b["src_ip"], "severity": 0.0, "_service": clean(r.get("service"))}


PCAP_KIND = {"conn": zeek_conn, "dns": zeek_dns, "http": zeek_http}


def pcap_record(r: dict[str, Any]) -> dict[str, Any]:
    fn = PCAP_KIND.get(str(r.get("kind")))
    if fn is None:
        raise NormalizationError(f"unknown capture record kind {r.get('kind')!r}")
    return fn(r)


# ---------------------------------------------------------------- Volatility 3 (memory forensics, JSON renderer)

def _mem_host(r: dict[str, Any]) -> str:
    h = norm_host(r.get("_memory_host"))
    if not h:
        raise NormalizationError("memory artefact needs a host: name the file HOST__plugin.json or wrap rows with a 'host'")
    return h


def vol_pslist(r: dict[str, Any]) -> dict[str, Any]:
    return {"category": "process", "action": "memory_process", "outcome": "observed", "src_host": _mem_host(r),
            "process": norm_process(r.get("ImageFileName")), "process_id": clean(r.get("PID")),
            "parent_process_id": clean(r.get("PPID")), "severity": 0.05, "_memory": True}


def vol_cmdline(r: dict[str, Any]) -> dict[str, Any]:
    return {"category": "process", "action": "memory_cmdline", "outcome": "observed", "src_host": _mem_host(r),
            "process": norm_process(r.get("Process")), "process_id": clean(r.get("PID")),
            "_cmdline": clean(r.get("Args")), "severity": 0.05, "_memory": True}


def vol_netscan(r: dict[str, Any]) -> dict[str, Any]:
    dst = norm_ip(r.get("ForeignAddr"))
    if dst is None or dst in {"0.0.0.0", "::", "*"}:
        raise SkipRecord("netscan: listening socket")
    return {"category": "network", "action": f"memory_socket:{str(r.get('Proto') or '').lower()}", "outcome": "observed",
            "src_host": _mem_host(r), "src_ip": norm_ip(r.get("LocalAddr")), "dst_ip": dst,
            "dst_port": to_int(r.get("ForeignPort")), "process": norm_process(r.get("Owner")),
            "process_id": clean(r.get("PID")), "severity": 0.1, "_memory": True}


def vol_malfind(r: dict[str, Any]) -> dict[str, Any]:
    return {"category": "privilege", "action": "memory_injection", "outcome": "observed", "src_host": _mem_host(r),
            "process": norm_process(r.get("Process")), "process_id": clean(r.get("PID")), "target_user": "system",
            "_protection": clean(r.get("Protection")), "_mz": "4d 5a" in str(r.get("Hexdump") or "").lower()[:12]
            or "MZ" in str(r.get("Hexdump") or "")[:80], "severity": 0.5, "_memory": True}
