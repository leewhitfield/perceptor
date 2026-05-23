from __future__ import annotations

import csv
import os
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path


ARCHIVE_FIELDS = [
    "archive_path",
    "archive_file_name",
    "archive_extension",
    "archive_file_size",
    "archive_modified_time_utc",
    "archive_status",
    "archive_error",
    "member_path",
    "member_file_name",
    "member_extension",
    "member_size",
    "member_compressed_size",
    "member_crc",
    "member_modified_time_utc",
    "member_is_dir",
    "member_is_encrypted",
    "nested_evidence_format",
    "multipart_set_id",
    "multipart_part_number",
    "multipart_part_count",
    "multipart_is_first_part",
    "multipart_related_parts",
]

ZIP_EXTENSIONS = {".zip"}
UNSUPPORTED_ARCHIVE_EXTENSIONS = {".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".cab", ".z01", ".z02", ".z03"}
NESTED_DISK_EXTENSIONS = {
    ".e01": "ewf",
    ".ex01": "ewf",
    ".l01": "ewf",
    ".lx01": "ewf",
    ".dd": "raw",
    ".raw": "raw",
    ".img": "raw",
    ".001": "raw",
    ".vhd": "vhd",
    ".vhdx": "vhdx",
    ".vmdk": "vmdk",
}


def parse_archive_inventory_to_csv(source: Path, output: Path) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    csv_path = output / "ArchiveInventory.csv"
    rows: list[dict[str, object]] = []
    for archive in _iter_archive_candidates(source):
        rows.extend(_archive_rows(source, archive))
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=ARCHIVE_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return csv_path


def _iter_archive_candidates(source: Path) -> list[Path]:
    if _is_file(source):
        return [source] if _is_archive_candidate(source) else []
    return sorted(
        path
        for path in _walk_files(source)
        if _is_file(path)
        and "_extract_jobs" not in path.parts
        and _is_archive_candidate(path)
        and not _is_excluded_archive_path(source, path)
    )


def _walk_files(source: Path) -> list[Path]:
    files: list[Path] = []
    for dirpath, _dirnames, filenames in os.walk(source, onerror=lambda _exc: None):
        directory = Path(dirpath)
        for filename in filenames:
            files.append(directory / filename)
    return files


def _is_file(path: Path) -> bool:
    try:
        return path.is_file()
    except OSError:
        return False


def _is_archive_candidate(path: Path) -> bool:
    suffix = path.suffix.lower()
    name = path.name.lower()
    return (
        suffix in ZIP_EXTENSIONS | UNSUPPORTED_ARCHIVE_EXTENSIONS
        or re.search(r"\.z\d{2}$", name) is not None
        or re.search(r"\.7z\.\d{3}$", name) is not None
        or re.search(r"\.part\d+\.rar$", name) is not None
        or re.search(r"\.r\d{2}$", name) is not None
    )


def _is_excluded_archive_path(root: Path, path: Path) -> bool:
    try:
        relative = path.relative_to(root).as_posix().lower()
    except ValueError:
        relative = path.as_posix().lower()
    excluded_prefixes = (
        "windows/",
        "windows.old/",
        "program files/",
        "program files (x86)/",
        "programdata/microsoft/windows defender/",
    )
    return relative.startswith(excluded_prefixes)


def _archive_rows(root: Path, archive: Path) -> list[dict[str, object]]:
    base = _archive_base(root, archive)
    multipart = _multipart_archive_info(root, archive)
    suffix = archive.suffix.lower()
    if multipart and multipart["part_count"] > 1 and suffix == ".zip":
        return [
            {
                **base,
                **_multipart_archive_fields(multipart),
                "archive_status": "multipart_archive",
                "archive_error": "Split ZIP archive detected; member inventory requires multipart extraction support",
            }
        ]
    if multipart and suffix != ".zip":
        return [{**base, **_multipart_archive_fields(multipart), "archive_status": "unsupported_multipart_archive"}]
    if suffix in UNSUPPORTED_ARCHIVE_EXTENSIONS:
        return [{**base, **_multipart_archive_fields(multipart), "archive_status": "unsupported_archive_type"}]
    try:
        with zipfile.ZipFile(archive) as zf:
            infos = zf.infolist()
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        return [{**base, **_multipart_archive_fields(multipart), "archive_status": "damaged", "archive_error": str(exc)}]
    if not infos:
        return [{**base, **_multipart_archive_fields(multipart), "archive_status": "empty"}]
    rows = []
    for info in infos:
        member_path = info.filename
        member_name = Path(member_path.rstrip("/")).name
        member_extension = Path(member_name).suffix.lower()
        rows.append(
            {
                **base,
                **_multipart_archive_fields(multipart),
                "archive_status": "parsed",
                "archive_error": "",
                "member_path": member_path,
                "member_file_name": member_name,
                "member_extension": member_extension,
                "member_size": info.file_size,
                "member_compressed_size": info.compress_size,
                "member_crc": f"{info.CRC:08x}",
                "member_modified_time_utc": _zip_datetime(info),
                "member_is_dir": str(info.is_dir()).lower(),
                "member_is_encrypted": str(bool(info.flag_bits & 0x1)).lower(),
                "nested_evidence_format": NESTED_DISK_EXTENSIONS.get(member_extension, ""),
            }
        )
    return rows


def _archive_base(root: Path, archive: Path) -> dict[str, object]:
    try:
        relative = "/" + archive.relative_to(root).as_posix()
    except ValueError:
        relative = archive.as_posix()
    stat = None
    stat_error = ""
    try:
        stat = archive.stat()
    except OSError as exc:
        stat_error = str(exc)
    return {
        "archive_path": relative,
        "archive_file_name": archive.name,
        "archive_extension": archive.suffix.lower(),
        "archive_file_size": stat.st_size if stat else "",
        "archive_modified_time_utc": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat() if stat else "",
        "archive_status": "",
        "archive_error": stat_error,
        "member_path": "",
        "member_file_name": "",
        "member_extension": "",
        "member_size": "",
        "member_compressed_size": "",
        "member_crc": "",
        "member_modified_time_utc": "",
        "member_is_dir": "",
        "member_is_encrypted": "",
        "nested_evidence_format": "",
        "multipart_set_id": "",
        "multipart_part_number": "",
        "multipart_part_count": "",
        "multipart_is_first_part": "",
        "multipart_related_parts": "",
    }


def _zip_datetime(info: zipfile.ZipInfo) -> str:
    try:
        return datetime(*info.date_time, tzinfo=timezone.utc).isoformat()
    except ValueError:
        return ""


def _multipart_archive_info(root: Path, archive: Path) -> dict[str, object] | None:
    name = archive.name.lower()
    parent = archive.parent
    patterns: list[str] = []
    set_id = archive.stem
    part_number = 1
    is_first = True
    zip_part = re.match(r"(?P<stem>.+)\.z(?P<number>\d{2})$", name)
    if zip_part:
        set_id = zip_part.group("stem")
        part_number = int(zip_part.group("number"))
        is_first = False
        patterns = [f"{set_id}.z??", f"{set_id}.zip"]
    elif archive.suffix.lower() == ".zip":
        set_id = archive.stem.lower()
        patterns = [f"{set_id}.z??", f"{set_id}.zip"]
    seven_part = re.match(r"(?P<stem>.+\.7z)\.(?P<number>\d{3})$", name)
    if seven_part:
        set_id = seven_part.group("stem")
        part_number = int(seven_part.group("number"))
        is_first = part_number == 1
        patterns = [f"{set_id}.[0-9][0-9][0-9]"]
    rar_part = re.match(r"(?P<stem>.+)\.part(?P<number>\d+)\.rar$", name)
    if rar_part:
        set_id = rar_part.group("stem")
        part_number = int(rar_part.group("number"))
        is_first = part_number == 1
        patterns = [f"{set_id}.part*.rar"]
    r_part = re.match(r"(?P<stem>.+)\.r(?P<number>\d{2})$", name)
    if r_part:
        set_id = r_part.group("stem")
        part_number = int(r_part.group("number")) + 2
        is_first = False
        patterns = [f"{set_id}.rar", f"{set_id}.r??"]
    if not patterns:
        return None
    related = sorted({item.name for pattern in patterns for item in parent.glob(pattern)})
    if len(related) <= 1:
        return None
    try:
        relative_parent = parent.relative_to(root).as_posix()
    except ValueError:
        relative_parent = parent.as_posix()
    return {
        "set_id": f"{relative_parent}/{set_id}".strip("/"),
        "part_number": part_number,
        "part_count": len(related),
        "is_first_part": is_first,
        "related_parts": ",".join(related),
    }


def _multipart_archive_fields(info: dict[str, object] | None) -> dict[str, object]:
    if not info:
        return {}
    return {
        "multipart_set_id": info["set_id"],
        "multipart_part_number": info["part_number"],
        "multipart_part_count": info["part_count"],
        "multipart_is_first_part": str(bool(info["is_first_part"])).lower(),
        "multipart_related_parts": info["related_parts"],
    }
