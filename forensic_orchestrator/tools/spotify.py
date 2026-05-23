from __future__ import annotations

import csv
import os
import re
from pathlib import Path
from typing import Iterable


SPOTIFY_FIELDS = [
    "artifact_type",
    "user_profile",
    "source_path",
    "source_name",
    "source_file",
    "file_size",
    "modified_utc",
    "account_user_id",
    "spotify_user_id",
    "spotify_user_uri",
    "display_name",
    "key_name",
    "value",
    "evidence",
    "error",
]

ASCII_RE = re.compile(rb"[\x20-\x7e]{3,}")
SPOTIFY_USER_BYTES_RE = re.compile(rb"(?:spotify:)?user:([A-Za-z0-9]+)", re.IGNORECASE)
PREF_RE = re.compile(r'(?P<key>autologin\.(?:canonical_)?username)="(?P<value>[^"]+)"')
PROFILE_MARKERS = (
    b"identity.v3.UserProfile",
    b"type.googleapis.com/x.identity.v3.UserProfile",
    b"type.googleapis.com/identity.v3.UserProfile",
)


def parse_spotify_artifacts_to_csv(source: Path, output: Path) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, object]] = []
    seen_profiles: set[tuple[str, str, str]] = set()
    for package_dir in _spotify_package_dirs(source):
        rows.extend(_prefs_rows(source, package_dir))
        for path, error in _spotify_leveldb_files(package_dir):
            if error:
                rows.append(_error_row(source, path, error))
                continue
            if path is None:
                continue
            try:
                for row in _profile_rows(source, path):
                    key = (
                        str(row.get("spotify_user_id") or ""),
                        str(row.get("display_name") or ""),
                        str(row.get("source_file") or ""),
                    )
                    if key in seen_profiles:
                        continue
                    seen_profiles.add(key)
                    rows.append(row)
            except Exception as exc:  # pragma: no cover - per-file isolation
                rows.append(_error_row(source, path, f"{type(exc).__name__}: {exc}"))
    csv_path = output / "SpotifyArtifacts.csv"
    _write_csv(csv_path, rows)
    return csv_path


def _spotify_package_dirs(source: Path) -> Iterable[Path]:
    if not source.exists():
        return
    if source.is_dir() and source.name.lower().startswith("spotifyab.spotifymusic_"):
        yield source
        return
    for root, dirnames, _filenames in os.walk(source, onerror=lambda _exc: None):
        root_path = Path(root)
        kept = []
        for dirname in dirnames:
            candidate = root_path / dirname
            if dirname.lower().startswith("spotifyab.spotifymusic_"):
                yield candidate
                continue
            kept.append(dirname)
        dirnames[:] = kept


def _prefs_rows(source: Path, package_dir: Path) -> list[dict[str, object]]:
    prefs = package_dir / "LocalState" / "Spotify" / "prefs"
    if not prefs.exists():
        return []
    try:
        text = prefs.read_text(errors="replace")
    except OSError as exc:
        return [_error_row(source, prefs, str(exc))]
    rows: list[dict[str, object]] = []
    for match in PREF_RE.finditer(text):
        value = match.group("value").strip()
        if not value:
            continue
        row = _base_row(source, prefs, "spotify_account_pref")
        row.update(
            {
                "account_user_id": value,
                "spotify_user_id": value,
                "spotify_user_uri": f"spotify:user:{value}",
                "key_name": match.group("key"),
                "value": value,
                "evidence": "LocalState/Spotify/prefs",
            }
        )
        rows.append(row)
    return rows


def _spotify_leveldb_files(package_dir: Path) -> Iterable[tuple[Path | None, str]]:
    spotify_root = package_dir / "LocalState" / "Spotify"
    indexeddb_root = package_dir / "LocalCache" / "Spotify" / "Default" / "IndexedDB"
    local_storage_root = package_dir / "LocalCache" / "Spotify" / "Default" / "Local Storage" / "leveldb"
    roots = [spotify_root, indexeddb_root, local_storage_root]
    for root in roots:
        if not root.exists():
            continue
        for current_root, dirnames, filenames in os.walk(root, onerror=lambda _exc: None):
            current = Path(current_root)
            kept = []
            for dirname in dirnames:
                candidate = current / dirname
                try:
                    candidate.stat()
                except OSError as exc:
                    yield candidate, str(exc)
                    continue
                kept.append(dirname)
            dirnames[:] = kept
            for filename in filenames:
                path = current / filename
                if path.suffix.lower() not in {".ldb", ".log"}:
                    continue
                try:
                    path.stat()
                except OSError as exc:
                    yield path, str(exc)
                    continue
                yield path, ""


def _profile_rows(source: Path, path: Path) -> list[dict[str, object]]:
    data = path.read_bytes()
    rows: list[dict[str, object]] = []
    offsets = set()
    for marker in PROFILE_MARKERS:
        start = 0
        while True:
            idx = data.find(marker, start)
            if idx < 0:
                break
            offsets.add(idx)
            start = idx + 1
    for offset in sorted(offsets):
        window_start = max(0, offset - 1200)
        window_end = min(len(data), offset + 1600)
        window = data[window_start:window_end]
        user_id = _nearest_user_id(window, offset - window_start)
        display_name = _display_name_from_window(window, offset - window_start, user_id=user_id)
        if not user_id or not display_name:
            continue
        row = _base_row(source, path, "spotify_user_profile")
        row.update(
            {
                "spotify_user_id": user_id,
                "spotify_user_uri": f"spotify:user:{user_id}",
                "display_name": display_name,
                "evidence": "cached identity.v3.UserProfile",
            }
        )
        rows.append(row)
    return rows


def _nearest_user_id(window: bytes, marker_offset: int) -> str:
    matches = list(SPOTIFY_USER_BYTES_RE.finditer(window))
    if not matches:
        return ""
    closest = min(matches, key=lambda match: abs(match.start() - marker_offset))
    return closest.group(1).decode("ascii", errors="replace")


def _display_name_from_window(window: bytes, marker_offset: int, *, user_id: str) -> str:
    strings: list[tuple[int, str]] = []
    for match in ASCII_RE.finditer(window):
        value = _clean_string(match.group(0).decode("utf-8", errors="replace"))
        if value:
            strings.append((match.start(), value))
    after = [(pos, value) for pos, value in strings if pos >= marker_offset]
    before = [(pos, value) for pos, value in strings if pos < marker_offset]
    for _pos, value in after[:12]:
        if _is_display_name_candidate(value, user_id=user_id):
            return value
    for _pos, value in reversed(before[-6:]):
        if _is_display_name_candidate(value, user_id=user_id):
            return value
    return ""


def _is_display_name_candidate(value: str, *, user_id: str) -> bool:
    lowered = value.lower()
    if len(value) < 3 or len(value) > 80:
        return False
    if user_id and value.lower() == user_id.lower():
        return False
    if any(token in lowered for token in ("spotify:", "type.googleapis", "identity.v3", "https://", "http://")):
        return False
    if any(char in value for char in ("/", "\\", "#", "{", "}", "\x00")):
        return False
    if lowered in {"cache", "user", "profile", "public", "private"}:
        return False
    if re.fullmatch(r"[A-Za-z0-9+/=]{24,}", value):
        return False
    if re.fullmatch(r"[\W_]+", value):
        return False
    if len(value) <= 4 and not re.search(r"[A-Za-z]{3,}", value):
        return False
    return True


def _base_row(source: Path, path: Path, artifact_type: str) -> dict[str, object]:
    stat = path.stat()
    return {
        "artifact_type": artifact_type,
        "user_profile": _user_profile_from_path(path),
        "source_path": _relative_to_source(source, path),
        "source_name": _source_name(path),
        "source_file": str(path),
        "file_size": stat.st_size,
        "modified_utc": _unix_to_iso(stat.st_mtime),
        "account_user_id": "",
        "spotify_user_id": "",
        "spotify_user_uri": "",
        "display_name": "",
        "key_name": "",
        "value": "",
        "evidence": "",
        "error": "",
    }


def _error_row(source: Path, path: Path | None, error: str) -> dict[str, object]:
    source_path = _relative_to_source(source, path) if path else ""
    return {
        "artifact_type": "spotify_error",
        "user_profile": _user_profile_from_path(path) if path else "",
        "source_path": source_path,
        "source_name": path.name if path else "",
        "source_file": str(path) if path else "",
        "file_size": "",
        "modified_utc": "",
        "account_user_id": "",
        "spotify_user_id": "",
        "spotify_user_uri": "",
        "display_name": "",
        "key_name": "",
        "value": "",
        "evidence": "",
        "error": error,
    }


def _source_name(path: Path) -> str:
    lower_parts = [part.lower() for part in path.parts]
    if "primary.ldb" in lower_parts:
        return "primary.ldb"
    if "public.ldb" in lower_parts:
        return "public.ldb"
    if "indexeddb" in lower_parts:
        return "IndexedDB"
    if "leveldb" in lower_parts:
        return "Local Storage LevelDB"
    return path.name


def _user_profile_from_path(path: Path) -> str:
    parts = path.parts
    lowered = [part.lower() for part in parts]
    if "users" not in lowered:
        return ""
    index = lowered.index("users")
    if index + 1 >= len(parts):
        return ""
    candidate = parts[index + 1]
    if candidate.lower() in {"all users", "default", "default user", "public"}:
        return ""
    return candidate


def _relative_to_source(source: Path, path: Path | None) -> str:
    if path is None:
        return ""
    try:
        return path.relative_to(source).as_posix()
    except ValueError:
        return path.as_posix()


def _clean_string(value: str) -> str:
    value = value.strip().strip('"').strip("'").strip()
    value = re.sub(r"^[^A-Za-z0-9]+", "", value)
    value = re.sub(r"[^A-Za-z0-9 ._@+-]+$", "", value)
    return value.strip()


def _unix_to_iso(timestamp: float) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=SPOTIFY_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in SPOTIFY_FIELDS})
