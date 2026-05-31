from __future__ import annotations

import csv
import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import duckdb

from .db import Database
from .safety import require_dependency


@dataclass(frozen=True)
class DeletedFileCandidate:
    source_table: str
    source_id: str
    case_id: str
    computer_id: str | None
    image_id: str
    image_path: Path
    filesystem_type: str
    offset_sectors: int
    inode: str | None
    file_path: str
    file_name: str
    file_size: str | None
    source_status: str


def recover_deleted_files(
    db: Database,
    *,
    case_id: str,
    output_dir: Path,
    image_id: str | None = None,
    contains: str | None = None,
    name: str | None = None,
    source: str = "all",
    limit: int = 100,
    max_bytes: int | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    if source not in {"all", "filesystem_entries", "mft_entries"}:
        raise ValueError("source must be one of: all, filesystem_entries, mft_entries")
    db.get_case(case_id)
    if not dry_run:
        require_dependency("icat")
    output_dir.mkdir(parents=True, exist_ok=True)
    candidates = _deleted_file_candidates(
        db,
        case_id=case_id,
        image_id=image_id,
        contains=contains,
        name=name,
        source=source,
        limit=limit,
    )
    rows: list[dict[str, Any]] = []
    fls_cache: dict[tuple[str, int, str], dict[str, str]] = {}
    for index, candidate in enumerate(candidates, start=1):
        row = _recover_candidate(
            candidate,
            output_dir=output_dir,
            index=index,
            fls_cache=fls_cache,
            max_bytes=max_bytes,
            dry_run=dry_run,
        )
        rows.append(row)
    manifest_csv = output_dir / "deleted-file-recovery-manifest.csv"
    manifest_json = output_dir / "deleted-file-recovery-manifest.json"
    _write_manifest_csv(manifest_csv, rows)
    payload = {
        "case_id": case_id,
        "created_at": _now(),
        "filters": {
            "image_id": image_id,
            "contains": contains,
            "name": name,
            "source": source,
            "limit": limit,
            "max_bytes": max_bytes,
            "dry_run": dry_run,
        },
        "summary": {
            "candidate_count": len(candidates),
            "recovered_count": sum(1 for row in rows if row["status"] in {"recovered", "would_recover"}),
            "failed_count": sum(1 for row in rows if row["status"] == "failed"),
            "skipped_count": sum(1 for row in rows if row["status"].startswith("skipped")),
        },
        "manifest_csv": str(manifest_csv),
        "files": rows,
    }
    manifest_json.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    db.log_activity(
        case_id=case_id,
        event="deleted_files.recovery_completed",
        message="Deleted file recovery completed",
        details={**payload["summary"], "output_dir": str(output_dir), "manifest_json": str(manifest_json)},
    )
    return {**payload, "manifest_json": str(manifest_json), "output_dir": str(output_dir)}


def _deleted_file_candidates(
    db: Database,
    *,
    case_id: str,
    image_id: str | None,
    contains: str | None,
    name: str | None,
    source: str,
    limit: int,
) -> list[DeletedFileCandidate]:
    candidates: list[DeletedFileCandidate] = []
    if source in {"all", "filesystem_entries"}:
        candidates.extend(
            _filesystem_entry_candidates(
                db,
                case_id=case_id,
                image_id=image_id,
                contains=contains,
                name=name,
                limit=limit,
            )
        )
    if len(candidates) < limit and source in {"all", "mft_entries"}:
        candidates.extend(
            _mft_entry_candidates(
                db,
                case_id=case_id,
                image_id=image_id,
                contains=contains,
                name=name,
                limit=limit - len(candidates),
            )
        )
    return candidates[:limit]


def _filesystem_entry_candidates(
    db: Database,
    *,
    case_id: str,
    image_id: str | None,
    contains: str | None,
    name: str | None,
    limit: int,
) -> list[DeletedFileCandidate]:
    where = [
        "filesystem_entries.case_id = ?",
        "COALESCE(filesystem_entries.scan_status, '') = 'deleted'",
        "LOWER(COALESCE(filesystem_entries.is_directory, '')) NOT IN ('true', '1', 'yes')",
    ]
    params: list[Any] = [case_id]
    if image_id:
        where.append("filesystem_entries.image_id = ?")
        params.append(image_id)
    if contains:
        where.append("(filesystem_entries.file_path LIKE ? OR filesystem_entries.file_name LIKE ?)")
        params.extend([f"%{contains}%", f"%{contains}%"])
    if name:
        where.append("filesystem_entries.file_name = ?")
        params.append(name)
    rows = _candidate_rows(
        db,
        case_id,
        "filesystem_entries",
        f"""
        SELECT *
        FROM filesystem_entries
        WHERE {" AND ".join(where)}
        ORDER BY modified_utc DESC, file_path
        LIMIT ?
        """,
        [*params, limit],
    )
    image_paths = _image_paths(db, case_id)
    candidates = []
    for row in rows:
        fs_type = _tsk_filesystem_type(row["filesystem_type"])
        if not fs_type:
            continue
        candidates.append(
            DeletedFileCandidate(
                source_table="filesystem_entries",
                source_id=str(row["id"]),
                case_id=case_id,
                computer_id=row["computer_id"],
                image_id=row["image_id"],
                image_path=Path(image_paths.get(str(row["image_id"]), "")),
                filesystem_type=fs_type,
                offset_sectors=_offset_from_source_root(row["source_root"]) or _offset_sectors_for_image(db, case_id, row["image_id"]),
                inode=None,
                file_path=row["file_path"] or row["file_name"] or "",
                file_name=row["file_name"] or Path(str(row["file_path"] or "deleted")).name,
                file_size=row["file_size"],
                source_status=row["scan_status"] or "deleted",
            )
        )
    return candidates


def _mft_entry_candidates(
    db: Database,
    *,
    case_id: str,
    image_id: str | None,
    contains: str | None,
    name: str | None,
    limit: int,
) -> list[DeletedFileCandidate]:
    where = [
        "mft_entries.case_id = ?",
        "LOWER(COALESCE(mft_entries.in_use, '')) IN ('false', '0', 'no')",
        "LOWER(COALESCE(mft_entries.is_directory, '')) NOT IN ('true', '1', 'yes')",
        "COALESCE(mft_entries.entry_number, '') <> ''",
    ]
    params: list[Any] = [case_id]
    if image_id:
        where.append("mft_entries.image_id = ?")
        params.append(image_id)
    if contains:
        where.append("(mft_entries.parent_path LIKE ? OR mft_entries.file_name LIKE ?)")
        params.extend([f"%{contains}%", f"%{contains}%"])
    if name:
        where.append("mft_entries.file_name = ?")
        params.append(name)
    rows = _candidate_rows(
        db,
        case_id,
        "mft_entries",
        f"""
        SELECT *
        FROM mft_entries
        WHERE {" AND ".join(where)}
        ORDER BY COALESCE(modified_si, created_si, '') DESC,
                 parent_path,
                 file_name
        LIMIT ?
        """,
        [*params, limit],
    )
    image_paths = _image_paths(db, case_id)
    candidates = []
    for row in rows:
        file_path = _join_path(row["parent_path"], row["file_name"])
        candidates.append(
            DeletedFileCandidate(
                source_table="mft_entries",
                source_id=str(row["id"]),
                case_id=case_id,
                computer_id=row["computer_id"],
                image_id=row["image_id"],
                image_path=Path(image_paths.get(str(row["image_id"]), "")),
                filesystem_type="ntfs",
                offset_sectors=_offset_sectors_for_image(db, case_id, row["image_id"]),
                inode=str(row["entry_number"]),
                file_path=file_path,
                file_name=row["file_name"] or Path(file_path).name,
                file_size=row["file_size"],
                source_status="deleted",
            )
        )
    return candidates


def _recover_candidate(
    candidate: DeletedFileCandidate,
    *,
    output_dir: Path,
    index: int,
    fls_cache: dict[tuple[str, int, str], dict[str, str]],
    max_bytes: int | None,
    dry_run: bool,
) -> dict[str, Any]:
    base = {
        "source_table": candidate.source_table,
        "source_id": candidate.source_id,
        "case_id": candidate.case_id,
        "computer_id": candidate.computer_id,
        "image_id": candidate.image_id,
        "image_path": str(candidate.image_path),
        "filesystem_type": candidate.filesystem_type,
        "offset_sectors": candidate.offset_sectors,
        "original_path": candidate.file_path,
        "file_name": candidate.file_name,
        "source_status": candidate.source_status,
        "original_size": candidate.file_size,
        "inode": candidate.inode or "",
    }
    if max_bytes is not None and _int_or_none(candidate.file_size) is not None and _int_or_none(candidate.file_size) > max_bytes:
        return {**base, "status": "skipped_max_bytes", "reason": f"file_size exceeds max_bytes ({candidate.file_size} > {max_bytes})"}
    if not str(candidate.image_path):
        return {**base, "status": "failed", "reason": "No source image path is available for this candidate"}
    if not candidate.image_path.exists():
        return {**base, "status": "failed", "reason": f"Source image path is not accessible: {candidate.image_path}"}
    inode = candidate.inode
    if not inode:
        inode = _inode_for_filesystem_entry(candidate, fls_cache)
    if not inode:
        return {**base, "status": "failed", "reason": "Could not resolve deleted file metadata address/inode from stored listing"}
    destination = output_dir / _safe_recovery_name(index, candidate.file_path, candidate.file_name)
    command = ["icat", "-f", candidate.filesystem_type, "-o", str(candidate.offset_sectors), str(candidate.image_path), inode]
    if dry_run:
        return {**base, "status": "would_recover", "inode": inode, "command": command, "output_path": str(destination)}
    destination.parent.mkdir(parents=True, exist_ok=True)
    stderr = subprocess.PIPE
    try:
        with destination.open("wb") as handle:
            completed = subprocess.run(command, stdout=handle, stderr=stderr, check=False)
    except OSError as exc:
        destination.unlink(missing_ok=True)
        return {**base, "status": "failed", "inode": inode, "command": command, "reason": str(exc)}
    stderr_text = (completed.stderr or b"").decode("utf-8", errors="replace").strip()
    if completed.returncode != 0:
        destination.unlink(missing_ok=True)
        return {**base, "status": "failed", "inode": inode, "command": command, "reason": stderr_text or f"icat exited {completed.returncode}"}
    size = destination.stat().st_size if destination.exists() else 0
    if size == 0:
        destination.unlink(missing_ok=True)
        return {**base, "status": "failed", "inode": inode, "command": command, "reason": "icat produced an empty output file"}
    return {
        **base,
        "status": "recovered",
        "inode": inode,
        "command": command,
        "output_path": str(destination),
        "recovered_size": size,
        "sha256": _sha256(destination),
        "reason": "",
    }


def _inode_for_filesystem_entry(
    candidate: DeletedFileCandidate,
    fls_cache: dict[tuple[str, int, str], dict[str, str]],
) -> str | None:
    key = (str(candidate.image_path), candidate.offset_sectors, candidate.filesystem_type)
    if key not in fls_cache:
        command = ["fls", "-f", candidate.filesystem_type, "-r", "-p", "-o", str(candidate.offset_sectors), str(candidate.image_path)]
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        if completed.returncode != 0:
            fls_cache[key] = {}
        else:
            fls_cache[key] = _deleted_inode_map(completed.stdout)
    return fls_cache[key].get(_normalize_path(candidate.file_path))


def _deleted_inode_map(fls_output: str) -> dict[str, str]:
    pattern = re.compile(r"^(?P<kind>[-rdv]/[-rdv])\s+\*\s*(?P<inode>[^:]+):\s*(?P<path>.+)$")
    output: dict[str, str] = {}
    for line in fls_output.splitlines():
        match = pattern.match(line.strip())
        if not match:
            continue
        path = match.group("path").replace(" (deleted)", "")
        output[_normalize_path(path)] = match.group("inode").split("-")[0]
    return output


def _offset_from_source_root(value: Any) -> int | None:
    match = re.search(r"(?:^|[:;,])offset=(\d+)", str(value or ""))
    return int(match.group(1)) if match else None


def _offset_sectors_for_image(db: Database, case_id: str, image_id: str) -> int:
    row = db.conn.execute(
        """
        SELECT offset_bytes
        FROM mounts
        WHERE case_id = ? AND image_id = ? AND offset_bytes IS NOT NULL
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (case_id, image_id),
    ).fetchone()
    if not row or row["offset_bytes"] is None:
        return 0
    return int(row["offset_bytes"]) // 512


def _candidate_rows(
    db: Database,
    case_id: str,
    table: str,
    sql: str,
    params: list[Any],
) -> list[dict[str, Any]]:
    try:
        rows = [dict(row) for row in db.conn.execute(sql, params).fetchall()]
    except Exception:
        rows = []
    if rows:
        return rows
    case_row = db.conn.execute("SELECT root FROM cases WHERE id = ?", (case_id,)).fetchone()
    if not case_row:
        return []
    duckdb_path = Path(case_row["root"]) / "analytics" / "events.duckdb"
    if not duckdb_path.exists():
        return []
    try:
        conn = duckdb.connect(str(duckdb_path), read_only=True)
    except duckdb.Error:
        return []
    try:
        exists = conn.execute("SELECT 1 FROM information_schema.tables WHERE table_name = ? LIMIT 1", [table]).fetchone()
        if not exists:
            return []
        result = conn.execute(sql, params)
        names = [column[0] for column in result.description or []]
        return [dict(zip(names, row, strict=False)) for row in result.fetchall()]
    finally:
        conn.close()


def _image_paths(db: Database, case_id: str) -> dict[str, str]:
    rows = db.conn.execute("SELECT id, path FROM images WHERE case_id = ?", (case_id,)).fetchall()
    return {str(row["id"]): str(row["path"]) for row in rows}


def _tsk_filesystem_type(value: Any) -> str | None:
    text = str(value or "").casefold()
    if text in {"fat", "fat12", "fat16", "fat32", "vfat", "msdos"}:
        return "fat"
    if text in {"exfat"}:
        return "exfat"
    if text in {"ntfs"}:
        return "ntfs"
    return None


def _safe_recovery_name(index: int, path: str, name: str) -> str:
    suffix = Path(name).suffix
    stem = Path(name).stem or "deleted"
    safe_stem = re.sub(r"[^A-Za-z0-9._-]+", "_", stem).strip("._") or "deleted"
    path_hash = hashlib.sha256(path.encode("utf-8", errors="replace")).hexdigest()[:12]
    return f"{index:04d}_{path_hash}_{safe_stem}{suffix}"


def _normalize_path(value: str) -> str:
    return "/".join(part for part in value.replace("\\", "/").strip("/").split("/") if part)


def _join_path(parent: Any, name: Any) -> str:
    parent_text = str(parent or "").strip().replace("\\", "/").strip("/")
    name_text = str(name or "").strip()
    if not parent_text:
        return name_text
    if parent_text in {".", "/"}:
        return name_text
    return f"{parent_text}/{name_text}" if name_text else parent_text


def _int_or_none(value: Any) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_manifest_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fieldnames = [
        "status",
        "reason",
        "source_table",
        "source_id",
        "case_id",
        "computer_id",
        "image_id",
        "image_path",
        "filesystem_type",
        "offset_sectors",
        "inode",
        "original_path",
        "file_name",
        "source_status",
        "original_size",
        "recovered_size",
        "sha256",
        "output_path",
        "command",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            serializable = dict(row)
            if isinstance(serializable.get("command"), list):
                serializable["command"] = json.dumps(serializable["command"])
            writer.writerow(serializable)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
