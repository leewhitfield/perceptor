from __future__ import annotations

import json
import hashlib
import subprocess
import uuid
from pathlib import Path
from typing import Any

from .db import Database


def rebuild_ntfs_namespace_reconciliation(
    db: Database,
    *,
    case_id: str,
    image_id: str,
    raw_image: Path | None = None,
    offset_sectors: int = 0,
    mount_path: Path | None = None,
) -> int:
    rows = []
    for mft_row in _candidate_mft_rows(db, case_id=case_id, image_id=image_id):
        parent_path = _normalize_path(mft_row["parent_path"])
        file_name = str(mft_row["file_name"] or "")
        original_path = f"{parent_path}/{file_name}" if parent_path else file_name
        index_entries = _matching_index_entries(
            db,
            case_id=case_id,
            image_id=image_id,
            parent_path=parent_path,
            file_name=file_name,
            mft_entry_number=str(mft_row["entry_number"]),
            mft_sequence_number=str(mft_row["sequence_number"] or ""),
        )
        bitmap = _bitmap_for_directory(db, case_id=case_id, image_id=image_id, parent_path=parent_path)
        classification = _classify(index_entries=index_entries, bitmap=bitmap)
        recovery = _recover_mft_data(
            raw_image=raw_image,
            offset_sectors=offset_sectors,
            inode=str(mft_row["entry_number"]),
        )
        parent_access = _parent_access(mount_path=mount_path, parent_path=parent_path)
        rows.append(
            {
                "id": str(uuid.uuid4()),
                "case_id": case_id,
                "computer_id": mft_row["computer_id"],
                "image_id": image_id,
                "mft_entry_number": str(mft_row["entry_number"]),
                "mft_sequence_number": str(mft_row["sequence_number"] or ""),
                "parent_entry_number": str(mft_row["parent_entry_number"] or ""),
                "parent_path": parent_path,
                "file_name": file_name,
                "original_path": original_path,
                "mft_in_use": str(mft_row["in_use"] or ""),
                "mounted_present": _mounted_file_present(mount_path=mount_path, original_path=original_path),
                **parent_access,
                **classification,
                **recovery,
            }
        )
    db.replace_ntfs_namespace_reconciliation(case_id=case_id, image_id=image_id, rows=rows)
    if rows:
        counts: dict[str, int] = {}
        for row in rows:
            counts[row["index_status"]] = counts.get(row["index_status"], 0) + 1
        db.log_activity(
            case_id=case_id,
            computer_id=rows[0]["computer_id"],
            image_id=image_id,
            event="ntfs.namespace_reconciled",
            message=f"Reconciled {len(rows)} MFT-only namespace candidates against $I30/$BITMAP",
            details={"count": len(rows), "status_counts": counts},
        )
    return len(rows)


def _candidate_mft_rows(db: Database, *, case_id: str, image_id: str):
    paths = _skipped_live_orphan_paths(db, case_id=case_id, image_id=image_id)
    if not paths:
        return []
    names = sorted({Path(path).name for path in paths})
    placeholders = ", ".join("?" for _ in names)
    candidate_rows = db.conn.execute(
        f"""
        SELECT *
        FROM mft_entries
        WHERE case_id = ?
          AND image_id = ?
          AND entry_number IS NOT NULL
          AND COALESCE(is_directory, '') NOT IN ('True', 'true', '1')
          AND COALESCE(is_ads, '') NOT IN ('True', 'true', '1')
          AND COALESCE(in_use, '') IN ('True', 'true', '1')
          AND file_name IN ({placeholders})
        ORDER BY parent_path, file_name, entry_number
        """,
        [case_id, image_id, *names],
    ).fetchall()
    path_set = {_normalize_path(path) for path in paths}
    return [
        row
        for row in candidate_rows
        if _normalize_path(f"{_normalize_path(row['parent_path'])}/{row['file_name']}") in path_set
    ]


def _skipped_live_orphan_paths(db: Database, *, case_id: str, image_id: str) -> list[str]:
    rows = db.conn.execute(
        """
        SELECT details_json FROM activity_log
        WHERE case_id = ? AND image_id = ? AND event = 'artifact.skipped_live_orphan'
        ORDER BY created_at DESC
        """,
        (case_id, image_id),
    ).fetchall()
    paths: list[str] = []
    seen: set[str] = set()
    for row in rows:
        try:
            details = json.loads(row["details_json"] or "{}")
        except json.JSONDecodeError:
            continue
        for path in details.get("sample", []):
            normalized = _normalize_path(path)
            if normalized and normalized not in seen:
                seen.add(normalized)
                paths.append(normalized)
    return paths


def _matching_index_entries(
    db: Database,
    *,
    case_id: str,
    image_id: str,
    parent_path: str,
    file_name: str,
    mft_entry_number: str,
    mft_sequence_number: str,
):
    rows = [
        dict(row)
        for row in db.conn.execute(
        """
        SELECT *
        FROM ntfs_index_entries
        WHERE case_id = ?
          AND image_id = ?
          AND directory_path = ?
          AND file_name = ?
        ORDER BY
          CASE WHEN referenced_entry_number = ? THEN 0 ELSE 1 END,
          CASE WHEN from_slack = 'false' THEN 0 ELSE 1 END,
          entry_offset
        """,
        (case_id, image_id, parent_path, file_name, mft_entry_number),
        ).fetchall()
    ]
    if not rows:
        return []
    exact = [
        row
        for row in rows
        if str(row["referenced_entry_number"] or "") == mft_entry_number
        and (not mft_sequence_number or str(row["referenced_sequence_number"] or "") == mft_sequence_number)
    ]
    for row in exact:
        row["_exact_reference_match"] = "true"
    if exact:
        return exact
    for row in rows:
        row["_exact_reference_match"] = "false"
    return rows


def _bitmap_for_directory(db: Database, *, case_id: str, image_id: str, parent_path: str):
    return db.conn.execute(
        """
        SELECT *
        FROM ntfs_index_bitmaps
        WHERE case_id = ? AND image_id = ? AND directory_path = ?
        ORDER BY created_at DESC, row_number DESC
        LIMIT 1
        """,
        (case_id, image_id, parent_path),
    ).fetchone()


def _classify(*, index_entries: list[Any], bitmap: Any | None) -> dict[str, str | None]:
    bitmap_error = str(bitmap["error"] or "") if bitmap is not None else ""
    if index_entries:
        active = _first_entry(
            index_entries,
            from_slack="false",
            block_active="true",
            exact_reference_match="true",
        )
        if active is not None:
            return _result(
                "i30_active_match",
                "true",
                active,
                bitmap_error,
                "MFT record has a non-slack $I30 entry in a bitmap-active index block",
            )
        slack = _first_entry(index_entries, from_slack="true")
        if slack is not None:
            return _result(
                "i30_slack_only",
                "false",
                slack,
                bitmap_error,
                "MFT record only matched $I30 slack; not present as an active directory entry",
            )
        inactive = _first_entry(index_entries)
        status = "i30_reference_mismatch" if inactive and inactive.get("_exact_reference_match") == "false" else "i30_inactive_or_unresolved"
        return _result(
            status,
            "false",
            inactive,
            bitmap_error,
            "MFT record matched $I30 by name but did not have a matching active MFT reference",
        )
    if "contains no INDX records" in bitmap_error:
        return _result(
            "i30_no_indx_records",
            "false",
            None,
            bitmap_error,
            "$BITMAP exists, but $INDEX_ALLOCATION did not contain readable INDX records",
        )
    if bitmap_error:
        return _result(
            "i30_parse_error",
            "false",
            None,
            bitmap_error,
            "$I30 stream could not be parsed; active namespace status remains unverified",
        )
    if bitmap is not None:
        return _result(
            "missing_from_i30",
            "false",
            None,
            bitmap_error,
            "MFT record was not found in parsed $I30 entries for the parent directory",
        )
    return _result(
        "i30_not_collected",
        "false",
        None,
        bitmap_error,
        "No $I30/$BITMAP evidence was collected for the parent directory",
    )


def _first_entry(
    entries: list[Any],
    *,
    from_slack: str | None = None,
    block_active: str | None = None,
    exact_reference_match: str | None = None,
):
    for row in entries:
        if from_slack is not None and str(row["from_slack"] or "").lower() != from_slack:
            continue
        if block_active is not None and str(row["block_active"] or "").lower() != block_active:
            continue
        if exact_reference_match is not None and str(row.get("_exact_reference_match") or "").lower() != exact_reference_match:
            continue
        return row
    if from_slack is None and block_active is None and exact_reference_match is None:
        return entries[0] if entries else None
    return None


def _result(status: str, legit: str, entry: Any | None, bitmap_error: str, reason: str) -> dict[str, str | None]:
    return {
        "index_status": status,
        "legit_active_file": legit,
        "index_entry_id": entry["id"] if entry is not None else None,
        "index_from_slack": entry["from_slack"] if entry is not None else None,
        "index_block_active": entry["block_active"] if entry is not None else None,
        "index_bitmap_error": bitmap_error,
        "reason": reason,
    }


def _recover_mft_data(*, raw_image: Path | None, offset_sectors: int, inode: str) -> dict[str, str | None]:
    if raw_image is None:
        return _recovery_result("false", None, None, None, None)
    try:
        completed = subprocess.run(
            ["icat", "-f", "ntfs", "-o", str(offset_sectors), str(raw_image), inode],
            capture_output=True,
            check=False,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        return _recovery_result("false", None, None, None, None)
    if completed.returncode != 0:
        return _recovery_result("false", None, None, None, None)
    data = completed.stdout
    return _recovery_result(
        "true",
        str(len(data)),
        hashlib.sha256(data).hexdigest(),
        _header_type(data),
        str(_zero_prefix(data)).lower(),
    )


def _recovery_result(
    icat_recovered: str,
    recovered_size: str | None,
    recovered_sha256: str | None,
    header_type: str | None,
    zero_prefix: str | None,
) -> dict[str, str | None]:
    return {
        "icat_recovered": icat_recovered,
        "recovered_size": recovered_size,
        "recovered_sha256": recovered_sha256,
        "header_type": header_type,
        "zero_prefix": zero_prefix,
    }


def _header_type(data: bytes) -> str:
    if data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        return "gif"
    if data.startswith(b"BM"):
        return "bmp"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data[:4] == b"\x00\x00\x00\x18" and data[4:8] == b"ftyp":
        return "mp4"
    if data.startswith(b"PK\x03\x04"):
        return "zip"
    if data[:64] and all(byte == 0 for byte in data[: min(64, len(data))]):
        return "zero_prefix"
    return "unknown"


def _zero_prefix(data: bytes) -> bool:
    return bool(data) and all(byte == 0 for byte in data[: min(64, len(data))])


def _mounted_file_present(*, mount_path: Path | None, original_path: str) -> str:
    if mount_path is None:
        return "unknown"
    return str((mount_path / original_path).exists()).lower()


def _parent_access(*, mount_path: Path | None, parent_path: str) -> dict[str, str]:
    if mount_path is None:
        return {"parent_mounted_exists": "unknown", "parent_access_status": "not_checked"}
    parent = mount_path / parent_path
    if not parent.exists():
        return {"parent_mounted_exists": "false", "parent_access_status": "missing"}
    try:
        next(parent.iterdir(), None)
    except PermissionError:
        return {"parent_mounted_exists": "true", "parent_access_status": "permission_denied"}
    except OSError as exc:
        return {"parent_mounted_exists": "true", "parent_access_status": f"error:{type(exc).__name__}"}
    return {"parent_mounted_exists": "true", "parent_access_status": "readable"}


def _normalize_path(value: str | None) -> str:
    text = str(value or "").replace("\\", "/")
    if text.startswith("./"):
        text = text[2:]
    return text.strip("/")
