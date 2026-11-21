"""Parsers for non-JSON/CSV evidence: Zeek TSV logs and packet captures (PCAP / PCAPNG).

Both produce plain dict records that the source adapters normalise like any other log, so a packet capture and the
Zeek logs derived from it land in the same evidence graph with the same rules.
"""
from __future__ import annotations

import io
import socket
from datetime import datetime, timezone
from typing import Any

ZEEK_UNSET = {"-", "(empty)"}


class FormatError(ValueError):
    pass


def parse_zeek(text: str, max_records: int) -> tuple[str, list[dict[str, Any]]]:
    """Zeek ASCII (TSV) log: '#fields' header, tab-separated rows. Returns (log path, records)."""
    sep, path, fields = "\t", None, None
    rows: list[dict[str, Any]] = []
    for line in text.splitlines():
        if not line:
            continue
        if line.startswith("#"):
            if line.startswith("#separator"):
                token = line.split(" ", 1)[1].strip() if " " in line else "\\x09"
                sep = bytes(token, "ascii").decode("unicode_escape") if token.startswith("\\x") else token
            elif line.startswith("#path"):
                path = line.split(sep, 1)[1].strip()
            elif line.startswith("#fields"):
                fields = line.split(sep)[1:]
            continue
        if fields is None:
            raise FormatError("Zeek log has no #fields header")
        if len(rows) >= max_records:
            raise FormatError(f"file exceeds the {max_records} record limit")
        values = line.split(sep)
        rec = {f: (None if v in ZEEK_UNSET else v) for f, v in zip(fields, values)}
        rec["_zeek_path"] = path
        rows.append(rec)
    if fields is None:
        raise FormatError("not a Zeek log (no #fields header)")
    return path or "unknown", rows


def is_zeek(text: str) -> bool:
    head = text[:400]
    return head.startswith("#separator") and "#fields" in text[:4000]


# ---------------------------------------------------------------- packet captures

def is_pcap(data: bytes) -> bool:
    return data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a")


def _ip(raw: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET6 if len(raw) == 16 else socket.AF_INET, raw)


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def parse_pcap(data: bytes, max_records: int) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Summarise a capture into connection, DNS and HTTP-request records (the same fields Zeek uses).

    Connections are keyed by 5-tuple; the side that sent the first packet (or the SYN) is the originator.
    Payloads are never stored: only addresses, ports, sizes, times, DNS names and HTTP request lines."""
    import dpkt

    reader = dpkt.pcapng.Reader(io.BytesIO(data)) if data[:4] == b"\x0a\x0d\x0d\x0a" else dpkt.pcap.Reader(io.BytesIO(data))
    try:
        linktype = reader.datalink()
    except Exception:  # noqa: BLE001
        linktype = 1
    conns: dict[tuple, dict[str, Any]] = {}
    dns: list[dict[str, Any]] = []
    http: list[dict[str, Any]] = []
    stats = {"packets": 0, "ip_packets": 0, "undecodable": 0}
    for ts, buf in reader:
        stats["packets"] += 1
        try:
            if linktype == 1:
                ip = dpkt.ethernet.Ethernet(buf).data
            elif linktype in (101, 12, 14):
                ip = dpkt.ip.IP(buf) if (buf[0] >> 4) == 4 else dpkt.ip6.IP6(buf)
            elif linktype == 113:
                ip = dpkt.sll.SLL(buf).data
            else:
                stats["undecodable"] += 1
                continue
        except (dpkt.UnpackError, IndexError, ValueError):
            stats["undecodable"] += 1
            continue
        if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
            continue
        stats["ip_packets"] += 1
        l4 = ip.data
        proto = "tcp" if isinstance(l4, dpkt.tcp.TCP) else "udp" if isinstance(l4, dpkt.udp.UDP) else None
        if proto is None:
            continue
        src, dst = _ip(ip.src), _ip(ip.dst)
        sport, dport = l4.sport, l4.dport
        key_f, key_r = (proto, src, sport, dst, dport), (proto, dst, dport, src, sport)
        payload = bytes(l4.data)
        # sizes come from the headers, so captures truncated by a snap length still report true volumes
        if isinstance(ip, dpkt.ip.IP):
            l4_len = ip.len - ip.hl * 4
        else:
            l4_len = ip.plen
        hdr = (l4.off * 4) if proto == "tcp" else 8
        size = max(0, l4_len - hdr) if l4_len else len(payload)
        if key_r in conns:
            c, outbound = conns[key_r], False
        else:
            c = conns.get(key_f)
            if c is None:
                if len(conns) >= max_records:
                    raise FormatError(f"capture exceeds the {max_records} connection limit")
                c = conns[key_f] = {"ts": ts, "last": ts, "id.orig_h": src, "id.orig_p": sport, "id.resp_h": dst,
                                    "id.resp_p": dport, "proto": proto, "orig_bytes": 0, "resp_bytes": 0,
                                    "orig_pkts": 0, "resp_pkts": 0, "service": None, "syn": False}
            outbound = True
        c["last"] = ts
        if outbound:
            c["orig_bytes"] += size
            c["orig_pkts"] += 1
        else:
            c["resp_bytes"] += size
            c["resp_pkts"] += 1
        if proto == "tcp" and outbound and (l4.flags & dpkt.tcp.TH_SYN) and not (l4.flags & dpkt.tcp.TH_ACK):
            c["syn"] = True
        if proto == "udp" and 53 in (sport, dport) and payload:
            c["service"] = "dns"
            try:
                msg = dpkt.dns.DNS(payload)
            except (dpkt.UnpackError, IndexError, ValueError):
                continue
            if msg.qr == dpkt.dns.DNS_R and msg.qd:
                answers = [_ip(a.rdata) for a in msg.an if a.type in (dpkt.dns.DNS_A, dpkt.dns.DNS_AAAA)]
                dns.append({"ts": ts, "uid": f"P{len(dns)}", "id.orig_h": dst, "id.orig_p": dport, "id.resp_h": src,
                            "id.resp_p": sport, "proto": "udp", "query": msg.qd[0].name, "qtype_name":
                            {1: "A", 28: "AAAA", 5: "CNAME", 12: "PTR", 33: "SRV", 16: "TXT"}.get(msg.qd[0].type, str(msg.qd[0].type)),
                            "rcode_name": {0: "NOERROR", 3: "NXDOMAIN", 2: "SERVFAIL"}.get(msg.rcode, str(msg.rcode)),
                            "answers": ",".join(answers) or None})
        elif proto == "tcp" and outbound and payload[:8].split(b" ", 1)[0] in (b"GET", b"POST", b"PUT", b"HEAD"):
            c["service"] = "http"
            try:
                head = payload.split(b"\r\n\r\n", 1)[0].decode("latin-1").split("\r\n")
                method, uri = head[0].split(" ")[:2]
                hdrs = {h.split(":", 1)[0].strip().lower(): h.split(":", 1)[1].strip() for h in head[1:] if ":" in h}
                http.append({"ts": ts, "uid": f"H{len(http)}", "id.orig_h": src, "id.orig_p": sport, "id.resp_h": dst,
                             "id.resp_p": dport, "method": method, "host": hdrs.get("host"), "uri": uri[:300],
                             "user_agent": (hdrs.get("user-agent") or "")[:200]})
            except (ValueError, IndexError):
                pass
    records: list[dict[str, Any]] = []
    for i, c in enumerate(sorted(conns.values(), key=lambda x: x["ts"])):
        records.append({"kind": "conn", "ts": _iso(c["ts"]), "uid": f"C{i}", "id.orig_h": c["id.orig_h"],
                        "id.orig_p": c["id.orig_p"], "id.resp_h": c["id.resp_h"], "id.resp_p": c["id.resp_p"],
                        "proto": c["proto"], "service": c["service"], "duration": round(c["last"] - c["ts"], 6),
                        "orig_bytes": c["orig_bytes"], "resp_bytes": c["resp_bytes"], "orig_pkts": c["orig_pkts"],
                        "resp_pkts": c["resp_pkts"], "conn_state": "S" if c["syn"] else "OTH"})
    for d in dns:
        records.append({"kind": "dns", **d, "ts": _iso(d["ts"])})
    for h in http:
        records.append({"kind": "http", **h, "ts": _iso(h["ts"])})
    if len(records) > max_records:
        raise FormatError(f"capture produced more than {max_records} records")
    stats.update({"connections": len(conns), "dns_answers": len(dns), "http_requests": len(http)})
    return records, stats
