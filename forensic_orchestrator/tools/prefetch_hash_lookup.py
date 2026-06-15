from __future__ import annotations

import csv
import os
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


DEFAULT_LOOKUP_PATHS: tuple[Path, ...] = ()
DEFAULT_LOOKUP_DIRS = (
    Path("/opt/perceptor-reference"),
    Path("/opt/perceptor-reference"),
    Path.home() / "reference",
)
LOOKUP_FILE_RE = re.compile(r"(?i)(prefetch|pf).*(hash|lookup).*\.(txt|tsv|csv)$")


@dataclass(frozen=True)
class PrefetchHashReference:
    prefetch_name: str
    executable_name: str
    prefetch_hash: str
    resolved_path: str
    device_path: str
    command_line: str
    os_label: str
    description: str
    source: str


def resolve_prefetch_hash(
    *,
    prefetch_name: str | None = None,
    executable_name: str | None = None,
    prefetch_hash: str | None = None,
) -> dict[str, str | None]:
    matches = _lookup_matches(
        _normalize_prefetch_name(prefetch_name),
        _normalize_executable_name(executable_name),
        _normalize_hash(prefetch_hash),
    )
    if not matches:
        return {
            "reference_path": None,
            "reference_device_path": None,
            "reference_command_line": None,
            "reference_os": None,
            "reference_description": None,
            "reference_source": None,
            "reference_match_count": None,
        }

    paths = _unique_sorted(match.resolved_path for match in matches if match.resolved_path)
    device_paths = _unique_sorted(match.device_path for match in matches if match.device_path)
    command_lines = _unique_sorted(match.command_line.strip() for match in matches if match.command_line.strip())
    os_labels = _unique_sorted(match.os_label for match in matches if match.os_label)
    descriptions = _unique_sorted(match.description for match in matches if match.description)
    sources = _unique_sorted(match.source for match in matches if match.source)
    return {
        "reference_path": paths[0] if len(paths) == 1 else "; ".join(paths[:5]),
        "reference_device_path": device_paths[0] if len(device_paths) == 1 else "; ".join(device_paths[:5]),
        "reference_command_line": command_lines[0] if len(command_lines) == 1 else "; ".join(command_lines[:5]),
        "reference_os": os_labels[0] if len(os_labels) == 1 else "; ".join(os_labels[:5]),
        "reference_description": descriptions[0] if len(descriptions) == 1 else "; ".join(descriptions[:5]),
        "reference_source": sources[0] if len(sources) == 1 else "; ".join(sources[:5]),
        "reference_match_count": str(len(matches)),
    }


def prefetch_lookup_paths() -> tuple[Path, ...]:
    env_value = os.environ.get("FORENSIC_PREFETCH_HASH_LOOKUP_PATHS", "").strip()
    directory_value = os.environ.get("FORENSIC_PREFETCH_HASH_LOOKUP_DIRS", "").strip()
    discovered: list[Path] = []
    if env_value:
        discovered.extend(Path(part).expanduser() for part in env_value.split(os.pathsep) if part.strip())
        if not directory_value:
            return tuple(_unique_paths(discovered))
    else:
        discovered.extend(path for path in DEFAULT_LOOKUP_PATHS if path.exists())
    search_dirs = [
        Path(part).expanduser()
        for part in directory_value.split(os.pathsep)
        if part.strip()
    ] if directory_value else [path for path in DEFAULT_LOOKUP_DIRS if path.exists()]
    for directory in search_dirs:
        discovered.extend(_discover_lookup_files(directory))
    return tuple(_unique_paths(discovered))


def _discover_lookup_files(directory: Path) -> list[Path]:
    if not directory.exists():
        return []
    if directory.is_file():
        return [directory] if LOOKUP_FILE_RE.search(directory.name) else []
    try:
        return sorted(path for path in directory.rglob("*") if path.is_file() and LOOKUP_FILE_RE.search(path.name))
    except OSError:
        return []


def _unique_paths(paths: list[Path]) -> list[Path]:
    seen: set[str] = set()
    unique: list[Path] = []
    for path in paths:
        key = str(path.expanduser())
        if key in seen:
            continue
        seen.add(key)
        unique.append(path)
    return unique


@lru_cache(maxsize=1)
def load_prefetch_hash_references() -> tuple[PrefetchHashReference, ...]:
    references: list[PrefetchHashReference] = []
    for path in prefetch_lookup_paths():
        references.extend(_load_lookup_file(path))
    return tuple(references)


def _lookup_matches(
    prefetch_name: str | None,
    executable_name: str | None,
    prefetch_hash: str | None,
) -> list[PrefetchHashReference]:
    if not prefetch_hash:
        return []
    matches: list[PrefetchHashReference] = []
    for reference in load_prefetch_hash_references():
        if reference.prefetch_hash != prefetch_hash:
            continue
        if prefetch_name and reference.prefetch_name == prefetch_name:
            matches.append(reference)
            continue
        if executable_name and reference.executable_name == executable_name:
            matches.append(reference)
    return matches


def _load_lookup_file(path: Path) -> list[PrefetchHashReference]:
    references: list[PrefetchHashReference] = []
    try:
        with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
            reader = csv.reader(handle, delimiter="\t")
            for row in reader:
                reference = _reference_from_row(row, path)
                if reference is not None:
                    references.append(reference)
    except OSError:
        return []
    return references


def _reference_from_row(row: list[str], source_path: Path) -> PrefetchHashReference | None:
    if len(row) < 3:
        return None
    prefetch_name = _normalize_prefetch_name(row[1])
    if not prefetch_name:
        return None
    executable_name, prefetch_hash = _split_prefetch_name(prefetch_name)
    if not executable_name or not prefetch_hash:
        return None
    os_label, description = _split_os_description(row[0])
    return PrefetchHashReference(
        prefetch_name=prefetch_name,
        executable_name=executable_name,
        prefetch_hash=prefetch_hash,
        resolved_path=row[2].strip() if len(row) > 2 else "",
        command_line=row[3].strip() if len(row) > 3 else "",
        device_path=row[4].strip() if len(row) > 4 else "",
        os_label=os_label,
        description=description,
        source=str(source_path),
    )


def _split_prefetch_name(prefetch_name: str) -> tuple[str | None, str | None]:
    stem = prefetch_name[:-3] if prefetch_name.lower().endswith(".pf") else prefetch_name
    if "-" not in stem:
        return (_normalize_executable_name(stem), None)
    executable, hash_value = stem.rsplit("-", 1)
    return (_normalize_executable_name(executable), _normalize_hash(hash_value))


def _split_os_description(value: str) -> tuple[str, str]:
    text = value.strip()
    match = re.match(r"^(XP|Vista|W7|2003|2008)\s+\(([^)]+)\)(.*)$", text)
    if not match:
        return ("", text)
    return (f"{match.group(1)} ({match.group(2).strip()})", match.group(3).strip())


def _normalize_prefetch_name(value: str | None) -> str | None:
    if not value:
        return None
    normalized = Path(str(value).strip()).name.upper()
    return normalized or None


def _normalize_executable_name(value: str | None) -> str | None:
    if not value:
        return None
    normalized = Path(str(value).strip()).name.upper()
    return normalized or None


def _normalize_hash(value: str | None) -> str | None:
    if not value:
        return None
    normalized = str(value).strip().upper()
    if normalized.startswith("0X"):
        normalized = normalized[2:]
    return normalized if re.fullmatch(r"[0-9A-F]{8}", normalized) else None


def _unique_sorted(values: list[str]) -> list[str]:
    return sorted({value for value in values if value})
