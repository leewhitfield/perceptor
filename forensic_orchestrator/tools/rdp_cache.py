from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from .image_analysis import analyze_image_file, build_contact_sheet, write_image_analysis_csv


RDP_CACHE_FIELDS = [
    "record_type",
    "user_profile",
    "source_cache_path",
    "fragment_path",
    "contact_sheet_path",
    "file_name",
    "sha256",
    "file_size",
    "width",
    "height",
    "image_format",
    "fragment_index",
    "parser_status",
    "parser_note",
    "details_json",
]

RDP_VISUAL_OBSERVATION_FIELDS = [
    "user_profile",
    "source_cache_path",
    "contact_sheet_path",
    "observation_time_utc",
    "time_basis",
    "observation_type",
    "observed_application",
    "observed_text",
    "observed_path",
    "certainty",
    "caveat",
    "details_json",
]

IMAGE_EXTENSIONS = {".bmp", ".png", ".jpg", ".jpeg"}
CONTACT_SHEET_TILE_LIMIT = 2048
OCR_TEXT_EXCERPT_LIMIT = 1000


def parse_rdp_cache_to_csv(source: Path, output: Path) -> list[Path]:
    output.mkdir(parents=True, exist_ok=True)
    rdp_rows: list[dict[str, object]] = []
    image_rows: list[dict[str, object]] = []
    visual_rows: list[dict[str, object]] = []
    cache_files = _rdp_cache_files(source)
    fragments_root = output / "fragments"
    sheets_root = output / "contact_sheets"
    extractor = _bmc_tools_command()
    for cache_file in cache_files:
        user_profile = _user_from_path(cache_file)
        rdp_rows.append(_cache_file_row(cache_file, user_profile))
        if cache_file.exists() and cache_file.stat().st_size == 0:
            rdp_rows.append(
                _status_row(
                    cache_file,
                    user_profile,
                    "empty_cache_file",
                    "Cache file is zero bytes; no bitmap fragments were extracted.",
                )
            )
            continue
        destination = fragments_root / _safe_name(user_profile or "unknown") / _safe_name(cache_file.stem)
        if extractor is None:
            rdp_rows.append(
                _status_row(
                    cache_file,
                    user_profile,
                    "bmc_tools_missing",
                    "Set BMC_TOOLS=/path/to/bmc-tools.py to extract RDP bitmap cache fragments.",
                )
            )
            continue
        status = _extract_cache_file(cache_file, destination, extractor)
        if status["returncode"] != 0:
            rdp_rows.append(_status_row(cache_file, user_profile, "extract_failed", status["error"]))
            continue
        fragments = _image_fragments(destination)
        sheet_path = sheets_root / f"{_safe_name(user_profile or 'unknown')}_{_safe_name(cache_file.stem)}.jpg"
        sheet_status = build_contact_sheet(fragments[:CONTACT_SHEET_TILE_LIMIT], sheet_path, columns=16, thumb_size=(64, 64))
        if sheet_status.get("status") == "created" and len(fragments) > CONTACT_SHEET_TILE_LIMIT:
            sheet_status["note"] = f"Contact sheet limited to first {CONTACT_SHEET_TILE_LIMIT} of {len(fragments)} fragments."
        contact_sheet_path = str(sheet_path) if sheet_status.get("status") == "created" else ""
        for index, fragment in enumerate(fragments, start=1):
            analysis = analyze_image_file(
                fragment,
                source_artifact_type="rdp_bitmap_cache",
                source_artifact_id=str(cache_file),
                source_path=str(cache_file),
                analysis_type="rdp_fragment_metadata",
                ocr=False,
            )
            image_rows.append(analysis)
            rdp_rows.append(_fragment_row(cache_file, user_profile, fragment, index, contact_sheet_path, analysis))
        if fragments:
            rdp_rows.append(
                {
                    "record_type": "contact_sheet",
                    "user_profile": user_profile,
                    "source_cache_path": str(cache_file),
                    "contact_sheet_path": str(sheet_path) if sheet_status.get("status") == "created" else "",
                    "parser_status": str(sheet_status.get("status", "")),
                    "parser_note": str(sheet_status.get("reason", "")),
                    "details_json": json.dumps(sheet_status),
                }
            )
        if contact_sheet_path:
            visual_rows.append(_contact_sheet_observation_row(cache_file, user_profile, contact_sheet_path, len(fragments), sheet_status))
            visual_rows.append(_contact_sheet_ocr_observation_row(cache_file, user_profile, Path(contact_sheet_path)))
    rdp_csv = output / "RdpCacheItems.csv"
    image_csv = output / "ImageAnalysisItems.csv"
    visual_csv = output / "RdpVisualObservations.csv"
    _write_csv(rdp_csv, RDP_CACHE_FIELDS, rdp_rows)
    write_image_analysis_csv(image_csv, image_rows)
    _write_csv(visual_csv, RDP_VISUAL_OBSERVATION_FIELDS, visual_rows)
    return [rdp_csv, image_csv, visual_csv]


def _rdp_cache_files(source: Path) -> list[Path]:
    if not source.exists():
        return []
    candidates: list[Path] = []
    for root, dirnames, filenames in os.walk(source, onerror=lambda _exc: None):
        root_path = Path(root)
        lower = root_path.as_posix().lower()
        if "/appdata/local/microsoft/terminal server client/cache" not in lower:
            continue
        for filename in filenames:
            name = filename.lower()
            if name.startswith("cache") and name.endswith(".bin"):
                candidates.append(root_path / filename)
            elif name.startswith("bcache") and name.endswith(".bmc"):
                candidates.append(root_path / filename)
        dirnames[:] = []
    return sorted(candidates)


def _bmc_tools_command() -> list[str] | None:
    configured = os.environ.get("BMC_TOOLS")
    if configured:
        path = Path(configured)
        if path.exists():
            return [sys.executable, str(path)] if path.suffix.lower() == ".py" else [str(path)]
    if os.environ.get("FORENSIC_DISABLE_BMC_TOOLS_DISCOVERY") != "1":
        project_candidate = Path(__file__).resolve().parents[2] / ".external" / "bmc-tools" / "bmc-tools.py"
        if project_candidate.exists():
            return [sys.executable, str(project_candidate)]
    path = shutil.which("bmc-tools.py") or shutil.which("bmc-tools")
    return [path] if path else None


def _extract_cache_file(cache_file: Path, destination: Path, extractor: list[str]) -> dict[str, object]:
    destination.mkdir(parents=True, exist_ok=True)
    command = [*extractor, "-s", str(cache_file), "-d", str(destination)]
    result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=300)
    error = result.stderr.strip() or result.stdout.strip()
    return {"returncode": result.returncode, "error": error, "command": command}


def _image_fragments(path: Path) -> list[Path]:
    if not path.exists():
        return []
    return sorted(item for item in path.rglob("*") if item.is_file() and item.suffix.lower() in IMAGE_EXTENSIONS)


def _cache_file_row(path: Path, user_profile: str) -> dict[str, object]:
    return {
        "record_type": "cache_file",
        "user_profile": user_profile,
        "source_cache_path": str(path),
        "file_name": path.name,
        "file_size": path.stat().st_size if path.exists() else "",
        "parser_status": "found",
        "parser_note": "",
        "details_json": "{}",
    }


def _fragment_row(
    cache_file: Path,
    user_profile: str,
    fragment: Path,
    index: int,
    contact_sheet_path: str,
    analysis: dict[str, object],
) -> dict[str, object]:
    return {
        "record_type": "fragment",
        "user_profile": user_profile,
        "source_cache_path": str(cache_file),
        "fragment_path": str(fragment),
        "contact_sheet_path": contact_sheet_path,
        "file_name": fragment.name,
        "sha256": analysis.get("sha256", ""),
        "file_size": analysis.get("file_size", ""),
        "width": analysis.get("width", ""),
        "height": analysis.get("height", ""),
        "image_format": analysis.get("image_format", ""),
        "fragment_index": index,
        "parser_status": "extracted",
        "parser_note": "",
        "details_json": "{}",
    }


def _status_row(path: Path, user_profile: str, status: str, note: str) -> dict[str, object]:
    return {
        "record_type": "extraction_status",
        "user_profile": user_profile,
        "source_cache_path": str(path),
        "file_name": path.name,
        "parser_status": status,
        "parser_note": note,
        "details_json": "{}",
    }


def _contact_sheet_observation_row(
    cache_file: Path,
    user_profile: str,
    contact_sheet_path: str,
    fragment_count: int,
    sheet_status: dict[str, object],
) -> dict[str, object]:
    observation_time = ""
    if cache_file.exists():
        observation_time = _utc_from_mtime(cache_file)
    details = dict(sheet_status)
    details["fragment_count"] = fragment_count
    return {
        "user_profile": user_profile,
        "source_cache_path": str(cache_file),
        "contact_sheet_path": contact_sheet_path,
        "observation_time_utc": observation_time,
        "time_basis": "source_cache_file_mtime",
        "observation_type": "contact_sheet_available",
        "observed_application": "",
        "observed_text": "",
        "observed_path": "",
        "certainty": "visual_material_available_not_semantic_interpretation",
        "caveat": "RDP bitmap cache fragments were extracted and a contact sheet was created; this row does not identify applications, text, or user intent without separate review/OCR/classification.",
        "details_json": json.dumps(details),
    }


def _contact_sheet_ocr_observation_row(
    cache_file: Path,
    user_profile: str,
    contact_sheet_path: Path,
) -> dict[str, object]:
    analysis = analyze_image_file(
        contact_sheet_path,
        source_artifact_type="rdp_bitmap_cache_contact_sheet",
        source_artifact_id=str(cache_file),
        source_path=str(cache_file),
        analysis_type="rdp_contact_sheet_ocr",
        ocr=True,
    )
    ocr_text = _compact_text(str(analysis.get("ocr_text") or ""))
    observed_text = _truncate_text(ocr_text, OCR_TEXT_EXCERPT_LIMIT)
    status = str(analysis.get("ocr_status") or "")
    details = {
        "ocr_status": status,
        "ocr_engine": str(analysis.get("ocr_engine") or ""),
        "ocr_text_length": len(ocr_text),
        "ocr_text_sha256": hashlib.sha256(ocr_text.encode("utf-8", errors="replace")).hexdigest() if ocr_text else "",
        "ocr_text_excerpt_truncated": len(ocr_text) > OCR_TEXT_EXCERPT_LIMIT,
    }
    if status == "ok" and ocr_text:
        observation_type = "contact_sheet_ocr_text"
        certainty = "ocr_text_from_contact_sheet_requires_review"
        caveat = "OCR text was extracted from an RDP bitmap-cache contact sheet and may contain tile-order artifacts, recognition errors, or unrelated cached screen fragments."
    elif status == "missing_dependency":
        observation_type = "contact_sheet_ocr_missing_dependency"
        certainty = "ocr_not_performed"
        caveat = "Tesseract was not available, so no OCR interpretation was generated for this RDP contact sheet."
    else:
        observation_type = "contact_sheet_ocr_no_text"
        certainty = "ocr_completed_no_text_or_error"
        caveat = "OCR produced no usable text or returned an error for this RDP contact sheet."
    return {
        "user_profile": user_profile,
        "source_cache_path": str(cache_file),
        "contact_sheet_path": str(contact_sheet_path),
        "observation_time_utc": _utc_from_mtime(cache_file) if cache_file.exists() else "",
        "time_basis": "source_cache_file_mtime",
        "observation_type": observation_type,
        "observed_application": "",
        "observed_text": observed_text,
        "observed_path": "",
        "certainty": certainty,
        "caveat": caveat,
        "details_json": json.dumps(details),
    }


def _compact_text(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def _truncate_text(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 3].rstrip() + "..."


def _utc_from_mtime(path: Path) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).replace(tzinfo=None).isoformat(sep=" ")


def _user_from_path(path: Path) -> str:
    parts = list(path.parts)
    lower = [part.lower() for part in parts]
    for marker in ("users", "documents and settings"):
        if marker in lower:
            index = lower.index(marker)
            if index + 1 < len(parts):
                return parts[index + 1]
    return ""


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or "unknown"


def _write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
