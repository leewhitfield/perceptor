from __future__ import annotations

import csv
import json
import re
from datetime import datetime
from pathlib import Path


SETUPAPI_FIELDS = [
    "source_path",
    "line_number",
    "section_title",
    "operation",
    "device_instance_id",
    "device_class",
    "vendor_id",
    "product_id",
    "serial",
    "service",
    "inf_path",
    "driver_package",
    "start_time_utc",
    "end_time_utc",
    "event_time_utc",
    "status",
    "confidence",
    "details_json",
    "error",
]

SECTION_RE = re.compile(r"^>>>\s+\[(?P<title>.+?)\]\s*$")
SECTION_START_RE = re.compile(r"^>>>\s+Section start\s+(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d\d:\d\d:\d\d(?:\.\d+)?)")
SECTION_END_RE = re.compile(r"^<<<\s+Section end\s+(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d\d:\d\d:\d\d(?:\.\d+)?)")
DEVICE_RE = re.compile(
    r"(?P<instance>(?:USB|USBSTOR|SCSI|SWD|WPDBUSENUM|HID|BTHENUM|PCI|ROOT)\\[^\]\r\n]+)",
    re.IGNORECASE,
)
VID_PID_RE = re.compile(r"VID_([0-9A-F]{4})&PID_([0-9A-F]{4})", re.IGNORECASE)
VEN_PROD_RE = re.compile(r"(?:Ven|VEN)_([^&\\]+)&(?:Prod|PROD)_([^&\\]+)", re.IGNORECASE)
SERVICE_RE = re.compile(r"\b(?:service|Service)\s*(?:=|:)\s*(?P<value>[A-Za-z0-9_.-]+)")
INF_RE = re.compile(r"(?P<path>[A-Z]:\\[^'\"\r\n]+\.inf|\\Windows\\INF\\[^'\"\r\n]+\.inf|[^'\"\s]+\.inf)", re.IGNORECASE)


def parse_setupapi_logs_to_csv(source: Path, output: Path) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, object]] = []
    for path in _setupapi_candidates(source):
        rows.extend(_parse_setupapi_log(path))
    csv_path = output / "SetupApiDeviceEvents.csv"
    _write_csv(csv_path, SETUPAPI_FIELDS, rows)
    return csv_path


def _setupapi_candidates(source: Path) -> list[Path]:
    if not source.exists():
        return []
    if source.is_file():
        return [source] if source.name.lower().startswith("setupapi") else []
    return sorted(
        path
        for path in source.rglob("setupapi*.log")
        if path.is_file() and path.name.lower() in {"setupapi.dev.log", "setupapi.dev.log.old", "setupapi.app.log"}
    )


def _parse_setupapi_log(path: Path) -> list[dict[str, object]]:
    try:
        lines = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
    except OSError as exc:
        return [_error_row(path, str(exc))]

    rows: list[dict[str, object]] = []
    current: dict[str, object] | None = None
    body: list[str] = []
    for line_number, line in enumerate(lines, start=1):
        section = SECTION_RE.match(line)
        if section:
            if current is not None:
                rows.append(_finalize_section(path, current, body))
            current = {
                "source_path": str(path),
                "line_number": line_number,
                "section_title": section.group("title").strip(),
            }
            body = []
            continue
        if current is None:
            continue
        body.append(line)
        start = SECTION_START_RE.match(line)
        if start:
            current["start_time_utc"] = _setupapi_timestamp(start.group("timestamp"))
            continue
        end = SECTION_END_RE.match(line)
        if end:
            current["end_time_utc"] = _setupapi_timestamp(end.group("timestamp"))
            continue
    if current is not None:
        rows.append(_finalize_section(path, current, body))
    return [row for row in rows if row.get("device_instance_id") or row.get("operation") or row.get("error")]


def _finalize_section(path: Path, section: dict[str, object], body: list[str]) -> dict[str, object]:
    title = str(section.get("section_title") or "")
    body_text = "\n".join(body)
    combined = "\n".join([title, body_text])
    device_instance_id = _device_instance_id(combined)
    vendor_id, product_id = _vendor_product(device_instance_id, combined)
    serial = _serial_from_instance(device_instance_id)
    inf_path = _first_match(INF_RE, combined, "path")
    service = _first_match(SERVICE_RE, combined, "value")
    operation = _operation_from_title(title)
    status = _status_from_text(combined)
    details = {
        "timestamp_basis": "setupapi_source_local_time",
        "note": "SetupAPI timestamps are stored as parsed local source times; no timezone conversion is applied.",
    }
    if body_text:
        details["matched_line_count"] = len(body)
    return {
        "source_path": str(path),
        "line_number": section.get("line_number"),
        "section_title": title,
        "operation": operation,
        "device_instance_id": device_instance_id,
        "device_class": _device_class(device_instance_id),
        "vendor_id": vendor_id,
        "product_id": product_id,
        "serial": serial,
        "service": service,
        "inf_path": inf_path,
        "driver_package": Path(inf_path).name if inf_path else "",
        "start_time_utc": section.get("start_time_utc") or "",
        "end_time_utc": section.get("end_time_utc") or "",
        "event_time_utc": section.get("start_time_utc") or section.get("end_time_utc") or "",
        "status": status,
        "confidence": "high" if device_instance_id else "medium",
        "details_json": json.dumps(details, sort_keys=True),
        "error": "",
    }


def _operation_from_title(title: str) -> str:
    lower = title.lower()
    if "device install" in lower:
        return "device_install"
    if "device started" in lower:
        return "device_started"
    if "device update" in lower:
        return "device_update"
    if "device remove" in lower or "device uninstall" in lower:
        return "device_remove"
    if "driver install" in lower:
        return "driver_install"
    return re.sub(r"[^a-z0-9]+", "_", lower).strip("_")[:80]


def _status_from_text(text: str) -> str:
    lower = text.lower()
    if "section end" in lower and "exit status: success" in lower:
        return "success"
    if "exit status: success" in lower or "completed successfully" in lower:
        return "success"
    if "exit status: failure" in lower or "error " in lower or " failed" in lower:
        return "failure"
    return ""


def _device_instance_id(text: str) -> str:
    match = DEVICE_RE.search(text)
    return match.group("instance").strip().rstrip(".") if match else ""


def _vendor_product(instance_id: str, text: str) -> tuple[str, str]:
    vid_pid = VID_PID_RE.search(instance_id) or VID_PID_RE.search(text)
    if vid_pid:
        return (vid_pid.group(1).upper(), vid_pid.group(2).upper())
    ven_prod = VEN_PROD_RE.search(instance_id) or VEN_PROD_RE.search(text)
    if ven_prod:
        return (ven_prod.group(1).strip(), ven_prod.group(2).strip())
    return ("", "")


def _serial_from_instance(instance_id: str) -> str:
    if not instance_id or "\\" not in instance_id:
        return ""
    parts = [part for part in re.split(r"\\+", instance_id) if part]
    if len(parts) < 3:
        return ""
    serial = parts[-1].strip()
    if "&" in serial and re.search(r"MI_\d\d|REV_", serial, re.IGNORECASE):
        return ""
    return serial


def _device_class(instance_id: str) -> str:
    if not instance_id:
        return ""
    return instance_id.split("\\", 1)[0].upper()


def _setupapi_timestamp(value: str) -> str:
    for fmt in ("%Y/%m/%d %H:%M:%S.%f", "%Y/%m/%d %H:%M:%S"):
        try:
            parsed = datetime.strptime(value, fmt)
            return parsed.isoformat(sep=" ")
        except ValueError:
            continue
    return value


def _first_match(pattern: re.Pattern[str], text: str, group: str) -> str:
    match = pattern.search(text)
    return match.group(group).strip() if match else ""


def _error_row(path: Path, error: str) -> dict[str, object]:
    return {
        "source_path": str(path),
        "line_number": "",
        "section_title": "",
        "operation": "",
        "device_instance_id": "",
        "device_class": "",
        "vendor_id": "",
        "product_id": "",
        "serial": "",
        "service": "",
        "inf_path": "",
        "driver_package": "",
        "start_time_utc": "",
        "end_time_utc": "",
        "event_time_utc": "",
        "status": "error",
        "confidence": "low",
        "details_json": "{}",
        "error": error,
    }


def _write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({name: row.get(name, "") for name in fieldnames})
