from __future__ import annotations

import csv
import json
import os
from pathlib import Path


USER_DICTIONARY_FIELDS = [
    "source_path",
    "user_profile",
    "application",
    "office_version",
    "proofing_id",
    "dictionary_name",
    "word",
    "word_index",
    "timestamp_utc",
    "details_json",
]


def parse_user_dictionaries_to_csv(source: Path, output: Path) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, object]] = []
    if source.exists():
        candidates = [source] if source.is_file() else _dictionary_candidates(source)
        for path in candidates:
            if path.is_file() and path.name.lower() == "roamingcustom.dic":
                rows.extend(_rows_for_dictionary(path))
    csv_path = output / "UserDictionaries.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=USER_DICTIONARY_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return csv_path


def _dictionary_candidates(source: Path) -> list[Path]:
    candidates: list[Path] = []
    for root, dirs, files in os.walk(source, onerror=lambda exc: None):
        dirs.sort()
        files.sort()
        for name in files:
            if name.lower() == "roamingcustom.dic":
                candidates.append(Path(root) / name)
    return candidates


def _rows_for_dictionary(path: Path) -> list[dict[str, object]]:
    try:
        text = path.read_text(encoding="utf-16", errors="strict")
        encoding = "utf-16"
    except (OSError, UnicodeError):
        try:
            text = path.read_text(encoding="utf-8-sig", errors="replace")
            encoding = "utf-8-sig"
        except OSError:
            return []
    rows: list[dict[str, object]] = []
    seen: set[str] = set()
    for index, line in enumerate(text.splitlines(), start=1):
        word = line.strip().lstrip("\ufeff")
        if not word or word.startswith("#"):
            continue
        dedupe_key = word.casefold()
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        rows.append(
            {
                "source_path": str(path),
                "user_profile": _user_from_path(path),
                "application": "office",
                "office_version": _office_version(path),
                "proofing_id": _proofing_id(path),
                "dictionary_name": path.name,
                "word": word,
                "word_index": index,
                "timestamp_utc": _mtime(path),
                "details_json": json.dumps({"encoding": encoding}, sort_keys=True),
            }
        )
    return rows


def _office_version(path: Path) -> str:
    parts = path.parts
    for index, part in enumerate(parts[:-1]):
        if part.lower() == "office" and index + 1 < len(parts):
            return parts[index + 1]
    return ""


def _proofing_id(path: Path) -> str:
    parts = path.parts
    for index, part in enumerate(parts[:-1]):
        if part.lower() == "proofing" and index > 0:
            return parts[index - 1]
    return ""


def _user_from_path(path: Path) -> str:
    parts = path.parts
    for index, part in enumerate(parts[:-1]):
        if part.lower() == "users" and index + 1 < len(parts):
            return parts[index + 1]
    return ""


def _mtime(path: Path) -> str:
    try:
        import datetime

        return datetime.datetime.fromtimestamp(path.stat().st_mtime, tz=datetime.timezone.utc).isoformat().replace(
            "+00:00", "Z"
        )
    except OSError:
        return ""
