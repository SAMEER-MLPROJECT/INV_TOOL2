"""Format-level tests for the heterogeneous importers. Memory rows below follow the Volatility 3 JSON renderer's
field names; they are format fixtures, not real memory evidence."""
import json

import pytest

from attackgraph.ingest.loader import IngestError, ingest_bytes

KW = dict(max_bytes=5_000_000, max_records=10_000, max_capture_bytes=5_000_000)


def test_zeek_conn_tsv():
    text = ("#separator \\x09\n#path\tconn\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\t"
            "duration\torig_bytes\tresp_bytes\tconn_state\n#types\ttime\tstring\n"
            "1692374360.86\tC1\t10.1.1.5\t50000\t203.0.113.9\t4444\ttcp\t-\t200.0\t30000000\t1000\tSF\n")
    r = ingest_bytes(text.encode(), "conn.log", **KW)
    assert r.adapter == "zeek_conn" and r.accepted == 1 and r.detections == 2
    rules = sorted(e.facts["rule_id"] for e in r.events if e.category == "alert")
    assert rules == ["AGL-D12", "AGL-D13"]


def test_unsupported_zeek_log_is_explained():
    text = "#separator \\x09\n#path\tweird\n#fields\tts\tname\n1692374360.86\tbad_checksum\n"
    with pytest.raises(IngestError, match="weird.log is not used"):
        ingest_bytes(text.encode(), "weird.log", **KW)


def test_pcap_magic_is_checked():
    with pytest.raises(IngestError, match="not a PCAP"):
        ingest_bytes(b"hello world", "x.pcap", **KW)


def test_windows_noise_is_filtered_with_reasons():
    recs = [{"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 7, "Hostname": "PC1.corp.local",
             "TimeCreated": "2024-01-01T10:00:00Z"},
            {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1, "Hostname": "PC1.corp.local",
             "TimeCreated": "2024-01-01T10:00:01Z", "Image": "C:\\Windows\\System32\\rundll32.exe", "User": "CORP\\ann",
             "ParentImage": "C:\\Windows\\System32\\svchost.exe",
             "CommandLine": "rundll32.exe C:\\windows\\System32\\comsvcs.dll MiniDump 640 C:\\temp\\l.dmp full"}]
    r = ingest_bytes("\n".join(json.dumps(x) for x in recs).encode(), "win.jsonl", **KW)
    assert r.adapter == "windows_events" and r.filtered == 1 and r.rejected == 0
    assert any("Sysmon/Operational 7" in k for k in r.filtered_reasons)
    alert = next(e for e in r.events if e.category == "alert")
    assert alert.technique == "T1003.001" and alert.alert_entities == ["host:PC1", "user:ann"]


def test_volatility_memory_rows_with_wrapper():
    doc = {"host": "PC1", "captured_at": "2024-01-01T11:00:00Z", "rows": [
        {"PID": 4242, "Process": "notepad.exe", "Start VPN": "0x1f0000", "End VPN": "0x1fffff", "Tag": "VadS",
         "Protection": "PAGE_EXECUTE_READWRITE", "CommitCharge": 16, "PrivateMemory": 1,
         "Hexdump": "4d 5a 90 00 03 00 00 00", "__children": []}]}
    r = ingest_bytes(json.dumps(doc).encode(), "malfind.json", **KW)
    assert r.adapter == "vol_malfind" and r.detections == 1
    assert next(e for e in r.events if e.category == "alert").technique == "T1055"


def test_volatility_host_from_file_name_and_missing_host():
    rows = [{"PID": 4, "PPID": 0, "ImageFileName": "System", "CreateTime": "2024-01-01T09:00:00+00:00", "__children": [
        {"PID": 900, "PPID": 4, "ImageFileName": "whoami.exe", "CreateTime": "2024-01-01T09:05:00+00:00", "__children": []}]}]
    r = ingest_bytes(json.dumps(rows).encode(), "PC1__windows.pslist.json", **KW)
    assert r.adapter == "vol_pslist" and r.accepted == 2
    with pytest.raises(IngestError, match="needs a host"):
        ingest_bytes(json.dumps(rows).encode(), "pslist.json", **KW)
