from __future__ import annotations

import csv
import hashlib
from pathlib import Path
from typing import Iterable

from .sam import scan_registry_keys


REGISTRY_HIVE_FIELDS = [
    "source_path",
    "original_path",
    "hive_name",
    "hive_type",
    "size",
    "sha256",
    "header_valid",
    "key_count",
    "value_count",
    "parser_error",
]


def parse_registry_hives_to_csv(sources: Iterable[Path], output: Path) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, object]] = []
    for source in sources:
        if source.is_file():
            rows.append(_hive_row(source, source.parent))
        elif source.is_dir():
            for path in sorted(source.rglob("*")):
                if path.is_file() and path.name.lower() in {"system", "software", "security", "sam", "ntuser.dat", "usrclass.dat", "amcache.hve"}:
                    rows.append(_hive_row(path, source))
    csv_path = output / "RegistryHives.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=REGISTRY_HIVE_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    return csv_path


def _hive_row(path: Path, source_root: Path) -> dict[str, object]:
    parser_error = ""
    key_count = 0
    value_count = 0
    header_valid = False
    try:
        data = path.read_bytes()
        header_valid = data[:4] == b"regf"
        records = scan_registry_keys(data)
        key_count = len(records)
        value_count = sum(len(record.values) for record in records.values())
    except Exception as exc:
        parser_error = str(exc)
    return {
        "source_path": str(path),
        "original_path": _relative(path, source_root),
        "hive_name": path.name,
        "hive_type": _hive_type(path),
        "size": path.stat().st_size if path.exists() else "",
        "sha256": _sha256(path) if path.exists() else "",
        "header_valid": str(header_valid).lower(),
        "key_count": key_count,
        "value_count": value_count,
        "parser_error": parser_error,
    }


def _relative(path: Path, source_root: Path) -> str:
    try:
        return path.relative_to(source_root).as_posix()
    except ValueError:
        return path.name


def _hive_type(path: Path) -> str:
    lower_name = path.name.lower()
    if lower_name in {"system", "software", "security", "sam"}:
        return lower_name
    if lower_name == "ntuser.dat":
        return "ntuser"
    if lower_name == "usrclass.dat":
        return "usrclass"
    if lower_name == "amcache.hve":
        return "amcache"
    return "unknown"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
