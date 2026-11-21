from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from ..detections import detect
from ..models import IngestIssue, NormalizedEvent
from .formats import FormatError, is_pcap, is_zeek, parse_pcap, parse_zeek
from .normalize import NormalizationError, clean, norm_host, norm_ip, norm_user, parse_timestamp, to_int
from .sources import ADAPTERS_BY_NAME, SourceAdapter, detect_adapter, map_record
from .sources_ext import SkipRecord

ALLOWED_EXTENSIONS = {".csv", ".json", ".jsonl", ".ndjson", ".log", ".pcap", ".pcapng", ".cap"}
CAPTURE_EXTENSIONS = {".pcap", ".pcapng", ".cap"}
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]")
MAX_ISSUES_PER_FILE = 500


class IngestError(ValueError):
    pass


def sanitize_filename(name: str) -> str:
    base = Path(str(name).replace("\\", "/")).name
    base = _SAFE_NAME.sub("_", base).lstrip(".")
    if not base:
        raise IngestError("empty file name")
    return base[:120]


@dataclass
class InventoryItem:
    asset_id: str
    asset_type: str
    name: str
    ip: str | None
    criticality: int
    owner: str | None
    tags: list[str]
    source_file: str
    source_row: int
    location: str | None = None


@dataclass
class FileResult:
    file_name: str
    sha256: str
    size_bytes: int
    adapter: str | None
    adapter_label: str | None
    records_read: int = 0
    accepted: int = 0
    rejected: int = 0
    duplicates: int = 0
    conflicts: int = 0
    warnings: int = 0
    filtered: int = 0
    detections: int = 0
    filtered_reasons: dict[str, int] = field(default_factory=dict)
    format_notes: list[str] = field(default_factory=list)
    first_event: datetime | None = None
    last_event: datetime | None = None
    issues: list[IngestIssue] = field(default_factory=list)
    events: list[NormalizedEvent] = field(default_factory=list)
    inventory: list[InventoryItem] = field(default_factory=list)
    conflicting: list[NormalizedEvent] = field(default_factory=list)
    loaded_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def add_issue(self, row: int | None, level: str, message: str) -> None:
        if len(self.issues) < MAX_ISSUES_PER_FILE:
            self.issues.append(IngestIssue(source_file=self.file_name, source_row=row, level=level, message=message))

    def summary(self) -> dict[str, Any]:
        return {
            "file_name": self.file_name,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "source_system": self.adapter,
            "source_label": self.adapter_label,
            "records_read": self.records_read,
            "accepted": self.accepted,
            "rejected": self.rejected,
            "duplicates": self.duplicates,
            "conflicts": self.conflicts,
            "warnings": self.warnings,
            "filtered": self.filtered,
            "filtered_reasons": dict(sorted(self.filtered_reasons.items(), key=lambda kv: -kv[1])[:25]),
            "detections": self.detections,
            "format_notes": self.format_notes,
            "first_event": self.first_event.isoformat() if self.first_event else None,
            "last_event": self.last_event.isoformat() if self.last_event else None,
            "loaded_at": self.loaded_at.isoformat(),
            "issues": [i.model_dump() for i in self.issues],
        }


def _records(name: str, text: str, max_records: int) -> list[Any]:
    ext = Path(name).suffix.lower()
    if ext == ".csv":
        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames:
            raise IngestError("CSV file has no header row")
        rows: list[Any] = []
        for row in reader:
            if len(rows) >= max_records:
                raise IngestError(f"file exceeds the {max_records} record limit")
            rows.append({k.strip(): v for k, v in row.items() if k is not None})
        return rows
    if ext in {".jsonl", ".ndjson"}:
        out: list[Any] = []
        for i, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            if len(out) >= max_records:
                raise IngestError(f"file exceeds the {max_records} record limit")
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                out.append(_Unparseable(i))
        return out
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise IngestError(f"invalid JSON at line {exc.lineno}") from exc
    if isinstance(doc, dict):
        for key in ("records", "events", "alerts", "data"):
            if isinstance(doc.get(key), list):
                doc = doc[key]
                break
        else:
            doc = [doc]
    if not isinstance(doc, list):
        raise IngestError("JSON must be an array of records or an object with a 'records' array")
    if len(doc) > max_records:
        raise IngestError(f"file exceeds the {max_records} record limit")
    return doc


@dataclass
class _Unparseable:
    line: int


def _inventory_item(rec: dict[str, Any], file_name: str, row: int) -> InventoryItem:
    for f in ("asset_id", "asset_type", "name", "criticality"):
        if clean(rec.get(f)) is None:
            raise NormalizationError(f"missing required field: {f}")
    crit = to_int(rec.get("criticality"))
    if crit is None or not 1 <= crit <= 5:
        raise NormalizationError("criticality must be an integer 1-5")
    atype = str(rec["asset_type"]).strip().lower()
    valid = {"workstation", "server", "domain_controller", "database", "user", "service_account", "admin_account", "network_device"}
    if atype not in valid:
        raise NormalizationError(f"unknown asset_type {atype!r}")
    ip = norm_ip(rec.get("ip"))
    if clean(rec.get("ip")) and ip is None:
        raise NormalizationError(f"invalid ip {rec.get('ip')!r}")
    name = norm_user(rec["name"]) if atype in {"user", "service_account", "admin_account"} else norm_host(rec["name"])
    tags = [t.strip() for t in str(rec.get("tags") or "").split(";") if t.strip()]
    return InventoryItem(
        asset_id=str(rec["asset_id"]).strip(), asset_type=atype, name=name or "", ip=ip, criticality=crit,
        owner=clean(rec.get("owner")), tags=tags, source_file=file_name, source_row=row,
        location=(clean(rec.get("location")) or None) and str(clean(rec.get("location")))[:60],
    )


def ingest_bytes(
    data: bytes,
    file_name: str,
    *,
    max_bytes: int,
    max_records: int,
    source_hint: str | None = None,
    max_capture_bytes: int | None = None,
) -> FileResult:
    safe = sanitize_filename(file_name)
    ext = Path(safe).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise IngestError(f"unsupported file type; allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}")
    if source_hint and source_hint not in ADAPTERS_BY_NAME:
        raise IngestError(f"unknown source type {source_hint!r}")
    result = FileResult(file_name=safe, sha256=hashlib.sha256(data).hexdigest(), size_bytes=len(data), adapter=None, adapter_label=None)

    if is_pcap(data) or ext in CAPTURE_EXTENSIONS:
        limit = max_capture_bytes or max_bytes
        if len(data) > limit:
            raise IngestError(f"capture is larger than the {limit // (1024 * 1024)} MB limit")
        if not is_pcap(data):
            raise IngestError("not a PCAP or PCAPNG file")
        try:
            records, stats = parse_pcap(data, max_records)
        except FormatError as exc:
            raise IngestError(str(exc)) from exc
        except Exception as exc:  # noqa: BLE001
            raise IngestError(f"could not decode the capture ({type(exc).__name__})") from exc
        for r in records:
            r["_pcap"] = True
        result.format_notes.append(
            f"packet capture: {stats['packets']} packets -> {stats['connections']} connections, {stats['dns_answers']} DNS "
            f"answers, {stats['http_requests']} HTTP requests (payloads are not stored)")
        adapter = ADAPTERS_BY_NAME["pcap"]
        return _finish(result, records, adapter, lambda idx: idx)

    if len(data) > max_bytes:
        raise IngestError(f"file is larger than the {max_bytes // (1024 * 1024)} MB limit")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise IngestError("file is not valid UTF-8 text") from exc

    if is_zeek(text):
        try:
            path, records = parse_zeek(text, max_records)
        except FormatError as exc:
            raise IngestError(str(exc)) from exc
        hint = source_hint or f"zeek_{path}"
        if hint not in ADAPTERS_BY_NAME:
            raise IngestError(f"Zeek {path}.log is not used; supported Zeek logs: conn, dns, http, files, kerberos")
        result.format_notes.append(f"Zeek {path}.log")
        return _finish(result, records, ADAPTERS_BY_NAME[hint], lambda idx: idx)
    if ext == ".log":
        raise IngestError(".log files must be Zeek ASCII logs (with a #fields header)")

    records = _records(safe, text, max_records)
    records = _memory_rows(safe, text, records, result)
    if not records:
        result.add_issue(None, "warning", "file contains no records")
        result.warnings += 1
        return result
    first = next((r for r in records if isinstance(r, dict)), None)
    adapter: SourceAdapter | None = detect_adapter(set(first.keys()) if first else set(), source_hint)
    if adapter is None:
        raise IngestError("could not recognise the log schema; choose a source type explicitly or use the common schema")
    return _finish(result, records, adapter, lambda idx: idx + 1 if safe.lower().endswith(".csv") else idx)


def _finish(result: FileResult, records: list[Any], adapter: SourceAdapter, row_of) -> FileResult:
    result.records_read = len(records)
    result.adapter, result.adapter_label = adapter.name, adapter.label
    _process_records(records, adapter, result, row_of=row_of)
    return result


_MEM_NAME = re.compile(r"^(?P<host>[A-Za-z0-9-]{1,40})__(?:(?P<time>\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z)__)?", re.I)


def _memory_rows(name: str, text: str, records: list[Any], result: FileResult) -> list[Any]:
    """Volatility 3 JSON output: flatten '__children' and attach the host and capture time, taken from a wrapper
    object {"host", "captured_at", "rows"} or from the file name HOST__YYYY-MM-DDTHH-MM-SSZ__plugin.json."""
    host = captured = None
    if text.lstrip().startswith("{"):
        try:
            doc = json.loads(text)
        except json.JSONDecodeError:
            doc = None
        if isinstance(doc, dict) and isinstance(doc.get("rows"), list):
            host, captured, records = doc.get("host"), doc.get("captured_at"), doc["rows"]
    first = next((r for r in records if isinstance(r, dict)), {})
    if not ({"PID"} <= set(first) and ({"ImageFileName", "Process", "Owner"} & set(first))):
        return records
    m = _MEM_NAME.match(name)
    if m:
        host = host or m.group("host")
        if m.group("time") and not captured:
            t = m.group("time")
            captured = f"{t[:10]}T{t[11:13]}:{t[14:16]}:{t[17:19]}Z"
    if not host:
        raise IngestError("memory artefact needs a host: name the file HOST__plugin.json or upload {\"host\": ..., \"rows\": [...]}")
    flat: list[Any] = []

    def walk(rows):
        for r in rows:
            if not isinstance(r, dict):
                continue
            kids = r.get("__children") or []
            flat.append({k: v for k, v in r.items() if k != "__children"} | {"_memory_host": host, "_memory_time": captured})
            walk(kids)
    walk(records)
    result.format_notes.append(f"memory forensics (Volatility 3) for host {host}" + (f", captured {captured}" if captured else ""))
    return flat


def _process_records(records: list[Any], adapter: SourceAdapter, result: FileResult, row_of) -> None:
    seen_ids: dict[str, str] = {}
    label = result.file_name
    for idx, rec in enumerate(records, start=1):
        row = row_of(idx)
        if isinstance(rec, _Unparseable):
            result.rejected += 1
            result.add_issue(rec.line, "error", "line is not valid JSON")
            continue
        if not isinstance(rec, dict):
            result.rejected += 1
            result.add_issue(row, "error", "record is not an object")
            continue
        try:
            if adapter.is_context:
                result.inventory.append(_inventory_item(rec, label, row))
                result.accepted += 1
                continue
            fields, notes = map_record(adapter, rec)
        except SkipRecord as skip:
            result.filtered += 1
            result.filtered_reasons[str(skip)] = result.filtered_reasons.get(str(skip), 0) + 1
            continue
        except NormalizationError as exc:
            result.rejected += 1
            result.add_issue(row, "error", str(exc))
            continue

        digest = hashlib.sha256(json.dumps(rec, sort_keys=True, default=str).encode()).hexdigest()
        eid = fields["event_id"]
        if eid in seen_ids:
            if seen_ids[eid] == digest:
                result.duplicates += 1
                result.add_issue(row, "duplicate", f"exact duplicate of event {eid}; ignored")
            else:
                result.conflicts += 1
                result.add_issue(row, "conflict", f"event id {eid} reused with different content; both copies kept, "
                                                  "the first is used for analysis")
                result.conflicting.append(NormalizedEvent(
                    uid=f"{fields['source_system']}:{eid}", source_file=label, source_row=row, notes=notes,
                    raw={k: v for k, v in rec.items()}, **fields))
            continue
        seen_ids[eid] = digest
        for n in notes:
            result.warnings += 1
            result.add_issue(row, "warning", n)
        ev = NormalizedEvent(
            uid=f"{fields['source_system']}:{eid}", source_file=label, source_row=row, notes=notes,
            raw={k: v for k, v in rec.items()}, **fields,
        )
        result.events.append(ev)
        result.accepted += 1
        if result.first_event is None or ev.timestamp < result.first_event:
            result.first_event = ev.timestamp
        if result.last_event is None or ev.timestamp > result.last_event:
            result.last_event = ev.timestamp
    if adapter.name == "windows_events":
        _align_windows_clock(result)
    if adapter.detect:
        seen: set[tuple] = set()
        found = []
        # Sysmon and Security often record the same process start: keep one alert per rule, second and reason.
        for ev in sorted(result.events, key=lambda e: (0 if "Sysmon" in str(e.raw.get("Channel")) else 1, e.timestamp)):
            for d in detect(ev):
                why = d.facts["why"].split(" by ")[0].split(" (parent")[0]
                key = (d.facts["rule_id"], d.timestamp.replace(microsecond=0), why)
                if key in seen:
                    continue
                seen.add(key)
                found.append(d)
        result.events.extend(found)
        result.detections = len(found)


def _align_windows_clock(result: FileResult) -> None:
    """Exported Windows logs often stamp local time as UTC. Sysmon process, file, registry and process-access events
    carry their own UtcTime; when those disagree with TimeCreated by a consistent offset, correct every event."""
    diffs = []
    for ev in result.events:
        raw = ev.raw
        if "Sysmon" in str(raw.get("Channel")) and str(raw.get("EventID")) in {"1", "10", "11", "12", "13"} and raw.get("UtcTime"):
            try:
                utc, _ = parse_timestamp(raw["UtcTime"])
            except NormalizationError:
                continue
            diffs.append((utc - ev.timestamp).total_seconds())
    if len(diffs) < 5:
        return
    diffs.sort()
    med = diffs[len(diffs) // 2]
    agree = sum(1 for d in diffs if abs(d - med) <= 60) / len(diffs)
    if abs(med) < 600 or agree < 0.8:
        return
    shift = timedelta(seconds=round(med / 900) * 900)
    note = (f"clock corrected by {shift}: TimeCreated differs from Sysmon UtcTime by a consistent offset in "
            f"{agree:.0%} of {len(diffs)} paired events")
    for ev in result.events:
        ev.timestamp = ev.timestamp + shift
        ev.notes.append(note)
    result.first_event = min(e.timestamp for e in result.events)
    result.last_event = max(e.timestamp for e in result.events)
    result.format_notes.append(note)
    result.warnings += 1
    result.add_issue(None, "warning", note)


def ingest_records(records: list[Any], *, source_hint: str | None, max_records: int, row_offset: int = 0) -> FileResult:
    if len(records) > max_records:
        raise IngestError(f"batch exceeds the {max_records} record limit")
    if source_hint and source_hint not in ADAPTERS_BY_NAME:
        raise IngestError(f"unknown source type {source_hint!r}")
    first = next((r for r in records if isinstance(r, dict)), None)
    adapter = detect_adapter(set(first.keys()) if first else set(), source_hint)
    if adapter is None:
        raise IngestError("could not recognise the record schema; set source_type or use the common schema")
    digest = hashlib.sha256(json.dumps(records, sort_keys=True, default=str).encode()).hexdigest()
    result = FileResult(file_name=f"live:{adapter.name}", sha256=digest, size_bytes=0, adapter=adapter.name,
                        adapter_label=adapter.label)
    result.records_read = len(records)
    _process_records(records, adapter, result, row_of=lambda idx: row_offset + idx)
    return result


def ingest_path(path: Path, *, max_bytes: int, max_records: int, source_hint: str | None = None) -> FileResult:
    if path.stat().st_size > max_bytes:
        raise IngestError(f"{path.name} is larger than the {max_bytes // (1024 * 1024)} MB limit")
    return ingest_bytes(path.read_bytes(), path.name, max_bytes=max_bytes, max_records=max_records, source_hint=source_hint)
