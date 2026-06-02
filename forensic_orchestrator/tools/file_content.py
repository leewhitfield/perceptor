from __future__ import annotations

import csv
import re
import subprocess
import zipfile
from pathlib import Path
from xml.etree import ElementTree


CONTENT_FIELDS = [
    "source_file",
    "item_path",
    "item_name",
    "item_type",
    "modified_utc",
    "content_field",
    "content_text",
    "extraction_status",
    "parser_error",
]

TEXT_EXTENSIONS = {".txt", ".csv", ".tsv", ".log", ".json", ".xml", ".html", ".htm", ".md", ".rtf", ".v2c"}
OFFICE_EXTENSIONS = {".docx", ".docm", ".pptx", ".pptm", ".ppsx", ".xlsx", ".xlsm"}
OFFICE_TEMP_EXTENSIONS = {".tmp"}
PDF_EXTENSIONS = {".pdf"}
SUPPORTED_EXTENSIONS = TEXT_EXTENSIONS | OFFICE_EXTENSIONS | PDF_EXTENSIONS
CONTENT_LIMIT = 1_000_000


def parse_file_content_to_csv(source: Path, output: Path) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    csv_path = output / "UserFileContent.csv"
    rows = []
    for path in _iter_supported_files(source):
        rows.append(_content_row(source, path))
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CONTENT_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return csv_path


def _iter_supported_files(source: Path) -> list[Path]:
    if source.is_file():
        return [source] if _is_supported_file(source) else []
    return sorted(
        path
        for path in source.rglob("*")
        if path.is_file()
        and _is_supported_file(path)
        and "_extract_jobs" not in path.parts
    )


def _is_supported_file(path: Path) -> bool:
    suffix = path.suffix.lower()
    if suffix in SUPPORTED_EXTENSIONS:
        return True
    if suffix in OFFICE_TEMP_EXTENSIONS:
        return bool(_office_members(path))
    return False


def _content_row(root: Path, path: Path) -> dict[str, object]:
    text, status, error = _extract_text(path)
    try:
        item_path = "/" + path.relative_to(root).as_posix()
    except ValueError:
        item_path = path.as_posix()
    try:
        modified = path.stat().st_mtime
    except OSError:
        modified = None
    return {
        "source_file": str(path),
        "item_path": item_path,
        "item_name": path.name,
        "item_type": path.suffix.lower().lstrip("."),
        "modified_utc": _unix_to_iso(modified),
        "content_field": "extracted_text",
        "content_text": text[:CONTENT_LIMIT],
        "extraction_status": status,
        "parser_error": error,
    }


def _extract_text(path: Path) -> tuple[str, str, str]:
    suffix = path.suffix.lower()
    if suffix in TEXT_EXTENSIONS:
        return _text_file(path)
    if suffix == ".pdf":
        return _pdf_text(path)
    if suffix in OFFICE_EXTENSIONS or suffix in OFFICE_TEMP_EXTENSIONS:
        return _office_text(path)
    return "", "unsupported", ""


def _text_file(path: Path) -> tuple[str, str, str]:
    try:
        payload = path.read_bytes()
    except OSError as exc:
        return "", "read_failed", str(exc)
    for encoding in ("utf-8", "utf-16", "latin-1"):
        try:
            text = payload.decode(encoding, errors="replace")
            if path.suffix.lower() in {".html", ".htm"}:
                text = _html_to_text(text)
            return text, "text_extracted", ""
        except Exception:
            continue
    return "", "decode_failed", ""


def _pdf_text(path: Path) -> tuple[str, str, str]:
    try:
        completed = subprocess.run(
            ["pdftotext", "-layout", str(path), "-"],
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
    except FileNotFoundError:
        return _pdf_text_pypdf(path)
    except subprocess.TimeoutExpired:
        return "", "timeout", "pdftotext timed out"
    if completed.returncode != 0:
        fallback_text, fallback_status, fallback_error = _pdf_text_pypdf(path)
        if fallback_text.strip() or fallback_status != "dependency_missing":
            return fallback_text, fallback_status, fallback_error or (completed.stderr or "pdftotext failed")[:1000]
        return "", "parse_failed", (completed.stderr or "pdftotext failed")[:1000]
    return completed.stdout, "text_extracted" if completed.stdout.strip() else "empty", ""


def _pdf_text_pypdf(path: Path) -> tuple[str, str, str]:
    try:
        from pypdf import PdfReader
    except Exception:
        return "", "dependency_missing", "pdftotext and pypdf were not found"
    try:
        reader = PdfReader(str(path))
        chunks = [(page.extract_text() or "") for page in reader.pages]
    except Exception as exc:
        return "", "parse_failed", str(exc)
    text = "\n".join(part for part in chunks if part)
    return text, "text_extracted" if text.strip() else "empty", ""


def _office_text(path: Path) -> tuple[str, str, str]:
    members = _office_members(path)
    if members is None:
        return "", "unsupported", ""
    try:
        with zipfile.ZipFile(path) as archive:
            chunks = []
            for member in members:
                try:
                    chunks.append(_xml_text(archive.read(member)))
                except KeyError:
                    continue
    except (OSError, zipfile.BadZipFile) as exc:
        return "", "parse_failed", str(exc)
    text = "\n".join(part for part in chunks if part)
    return text, "text_extracted" if text.strip() else "empty", ""


def _office_members(path: Path) -> list[str] | None:
    suffix = path.suffix.lower()
    if suffix in {".docx", ".docm"}:
        return ["word/document.xml"]
    if suffix in {".xlsx", ".xlsm"}:
        return ["xl/sharedStrings.xml"]
    if suffix in {".pptx", ".pptm", ".ppsx"}:
        return _office_zip_members(path, family="ppt")
    if suffix not in OFFICE_TEMP_EXTENSIONS:
        return None
    return _office_zip_members(path)


def _office_zip_members(path: Path, *, family: str | None = None) -> list[str] | None:
    try:
        with zipfile.ZipFile(path) as archive:
            names = set(archive.namelist())
    except (OSError, zipfile.BadZipFile):
        return None
    if family == "ppt" or (family is None and any(name.startswith("ppt/") for name in names)):
        slides = sorted(name for name in names if name.startswith("ppt/slides/slide") and name.endswith(".xml"))
        return slides or None
    if family is None and "word/document.xml" in names:
        return ["word/document.xml"]
    if family is None and "xl/sharedStrings.xml" in names:
        return ["xl/sharedStrings.xml"]
    return None


def _xml_text(payload: bytes) -> str:
    try:
        root = ElementTree.fromstring(payload)
    except ElementTree.ParseError:
        return ""
    return " ".join((text or "").strip() for text in root.itertext() if (text or "").strip())


def _html_to_text(value: str) -> str:
    text = re.sub(r"(?is)<(script|style).*?</\1>", " ", value)
    text = re.sub(r"(?is)<br\s*/?>", "\n", text)
    text = re.sub(r"(?is)</(?:p|div|tr|li|h[1-6])\s*>", "\n", text)
    text = re.sub(r"(?is)<[^>]+>", " ", text)
    return re.sub(r"[ \t\r\f\v]+", " ", text).replace(" \n", "\n").strip()


def _unix_to_iso(value: float | None) -> str:
    if value is None:
        return ""
    from datetime import datetime, timezone

    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()
