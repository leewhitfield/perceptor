from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
import re
import sqlite3
from typing import Any, Protocol

import duckdb


COMMON_DIALOG_GUID_RE = re.compile(
    r"^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$"
)

SHELL_JUMPLIST_DESCRIPTIONS = {
    "quick access",
    "windows explorer",
    "windows explorer windows 8.1",
    "file explorer",
}


class SupportsExecute(Protocol):
    def execute(self, query: str, parameters: Any | None = None) -> Any: ...


@dataclass(frozen=True)
class CommonDialogResolution:
    resolved_executable: str
    resolution_source: str
    resolution_confidence: str


def is_common_dialog_guid(value: object) -> bool:
    return COMMON_DIALOG_GUID_RE.fullmatch(str(value or "").strip()) is not None


def resolved_common_dialog_values(executable: object) -> dict[str, str | None]:
    text = str(executable or "").strip()
    if not text:
        return {
            "executable_is_guid": None,
            "resolved_executable": None,
            "executable_resolution_source": None,
            "executable_resolution_confidence": None,
        }
    if is_common_dialog_guid(text):
        return {
            "executable_is_guid": "true",
            "resolved_executable": None,
            "executable_resolution_source": None,
            "executable_resolution_confidence": None,
        }
    return {
        "executable_is_guid": "false",
        "resolved_executable": text,
        "executable_resolution_source": "direct",
        "executable_resolution_confidence": "high",
    }


def rebuild_common_dialog_application_resolutions(
    db: Any,
    *,
    case_id: str,
    image_id: str | None = None,
) -> int:
    conn = _common_dialog_connection(db, case_id)
    if conn is None or not _table_exists(conn, "registry_common_dialog_mru"):
        return 0
    _ensure_common_dialog_resolution_columns(conn)
    if not _table_exists(conn, "shortcut_items"):
        return _apply_direct_common_dialog_values(conn, case_id=case_id, image_id=image_id)

    updated = _apply_direct_common_dialog_values(conn, case_id=case_id, image_id=image_id)
    common_dialog_rows = _common_dialog_guid_rows(conn, case_id=case_id, image_id=image_id)
    if not common_dialog_rows:
        _commit_if_supported(conn)
        return updated
    shortcut_rows = _shortcut_rows(conn, case_id=case_id, image_id=image_id)
    resolutions = _resolve_guid_rows(common_dialog_rows, shortcut_rows)
    for row in common_dialog_rows:
        guid = str(row.get("executable") or "").strip()
        resolution = resolutions.get(str(row.get("id") or "")) or resolutions.get(guid.casefold())
        if resolution is None:
            continue
        _execute(
            conn,
            """
            UPDATE registry_common_dialog_mru
            SET resolved_executable = ?,
                executable_resolution_source = ?,
                executable_resolution_confidence = ?
            WHERE id = ?
            """,
            [
                resolution.resolved_executable,
                resolution.resolution_source,
                resolution.resolution_confidence,
                row["id"],
            ],
        )
        updated += 1
    _commit_if_supported(conn)
    return updated


def common_dialog_guid_resolution_map(
    db: Any,
    *,
    case_id: str,
    image_id: str | None = None,
) -> dict[str, CommonDialogResolution]:
    conn = _common_dialog_connection(db, case_id)
    if conn is None or not _table_exists(conn, "registry_common_dialog_mru"):
        return {}
    if not _has_column(conn, "registry_common_dialog_mru", "resolved_executable"):
        return {}
    where = ["case_id = ?", "executable IS NOT NULL", "resolved_executable IS NOT NULL"]
    params: list[object] = [case_id]
    if image_id is not None:
        where.append("image_id = ?")
        params.append(image_id)
    rows = _fetch_dicts(
        conn,
        f"""
        SELECT executable, resolved_executable, executable_resolution_source, executable_resolution_confidence
        FROM registry_common_dialog_mru
        WHERE {' AND '.join(where)}
        """,
        params,
    )
    resolved: dict[str, Counter[str]] = defaultdict(Counter)
    metadata: dict[tuple[str, str], tuple[str, str]] = {}
    for row in rows:
        executable = str(row.get("executable") or "").strip()
        app = str(row.get("resolved_executable") or "").strip()
        if not is_common_dialog_guid(executable) or not app:
            continue
        key = executable.casefold()
        resolved[key][app] += 1
        metadata[(key, app)] = (
            str(row.get("executable_resolution_source") or "guid_reuse"),
            str(row.get("executable_resolution_confidence") or "medium"),
        )
    results: dict[str, CommonDialogResolution] = {}
    for guid_key, counts in resolved.items():
        app, _ = counts.most_common(1)[0]
        source, confidence = metadata.get((guid_key, app), ("guid_reuse", "medium"))
        results[guid_key] = CommonDialogResolution(app, source, confidence)
    return results


def _resolve_guid_rows(
    common_dialog_rows: list[dict[str, Any]],
    shortcut_rows: list[dict[str, Any]],
) -> dict[str, CommonDialogResolution]:
    by_row: dict[str, CommonDialogResolution] = {}
    by_guid_votes: dict[str, Counter[str]] = defaultdict(Counter)
    by_guid_source: dict[tuple[str, str], tuple[str, str]] = {}
    for row in common_dialog_rows:
        guid = str(row.get("executable") or "").strip()
        row_id = str(row.get("id") or "")
        path = _normalize_path(row.get("absolute_path"))
        if not guid or not row_id or not path or path.startswith("unmapped guid:"):
            continue
        candidates: Counter[str] = Counter()
        best_score: dict[str, int] = {}
        for shortcut in shortcut_rows:
            app = _shortcut_application(shortcut)
            if not app:
                continue
            shortcut_path = _normalize_path(shortcut.get("file_location"))
            if not shortcut_path:
                continue
            score = _path_match_score(path, shortcut_path)
            if score <= 0:
                continue
            candidates[app] += score
            best_score[app] = max(best_score.get(app, 0), score)
        if not candidates:
            continue
        app, score_sum = candidates.most_common(1)[0]
        confidence = "high" if best_score.get(app, 0) >= 95 else "medium"
        resolution = CommonDialogResolution(app, "jumplist_path_match", confidence)
        by_row[row_id] = resolution
        guid_key = guid.casefold()
        by_guid_votes[guid_key][app] += score_sum
        by_guid_source[(guid_key, app)] = (resolution.resolution_source, resolution.resolution_confidence)

    for guid_key, votes in by_guid_votes.items():
        app, _ = votes.most_common(1)[0]
        source, confidence = by_guid_source.get((guid_key, app), ("guid_reuse", "medium"))
        by_row[guid_key] = CommonDialogResolution(app, source, confidence)
    return by_row


def _path_match_score(common_dialog_path: str, shortcut_path: str) -> int:
    if not common_dialog_path or not shortcut_path:
        return 0
    if _is_drive_root(common_dialog_path):
        return 0
    if common_dialog_path == shortcut_path:
        return 120
    if shortcut_path.startswith(common_dialog_path.rstrip("/") + "/"):
        return 100
    parent = shortcut_path.rsplit("/", 1)[0] if "/" in shortcut_path else shortcut_path
    if parent == common_dialog_path:
        return 95
    if _suffix_path_match(common_dialog_path, shortcut_path):
        return 85
    if _suffix_path_match(common_dialog_path, parent):
        return 80
    return 0


def _is_drive_root(value: str) -> bool:
    return bool(re.fullmatch(r"[a-z]:", value))


def _suffix_path_match(left: str, right: str) -> bool:
    left_parts = [part for part in left.split("/") if part]
    right_parts = [part for part in right.split("/") if part]
    if len(left_parts) < 2 or len(right_parts) < len(left_parts):
        return False
    return right_parts[-len(left_parts) :] == left_parts


def _shortcut_application(row: dict[str, Any]) -> str:
    app = str(row.get("app_id_description") or "").strip()
    if not app:
        return ""
    if app.casefold() in SHELL_JUMPLIST_DESCRIPTIONS:
        return ""
    return app


def _normalize_path(value: object) -> str:
    text = str(value or "").replace("\x00", "").strip()
    if not text:
        return ""
    text = text.replace("\\\\", "\\")
    for prefix in ("This PC\\", "This PC/"):
        if text.startswith(prefix):
            text = text[len(prefix) :]
    text = text.replace("\\", "/")
    text = re.sub(r"/+", "/", text)
    text = text.rstrip("/")
    text = text.replace("/DOCUME~1/", "/Documents/")
    if text.startswith("OneDrive/"):
        text = text.replace("OneDrive/", "OneDrive/Documents/", 1) if "/Documents/" not in text else text
    return text.casefold()


def _common_dialog_connection(db: Any, case_id: str) -> Any | None:
    analytics = getattr(db, "analytics", None)
    if analytics is not None and hasattr(analytics, "_connect"):
        return analytics._connect(case_id)
    if getattr(db, "analytics_only", False):
        row = db.conn.execute("SELECT root FROM cases WHERE id = ?", (case_id,)).fetchone()
        if row is None:
            return None
        return duckdb.connect(str(Path(row["root"]) / "analytics" / "events.duckdb"))
    return db.conn


def _apply_direct_common_dialog_values(conn: SupportsExecute, *, case_id: str, image_id: str | None) -> int:
    where = ["case_id = ?"]
    params: list[object] = [case_id]
    if image_id is not None:
        where.append("image_id = ?")
        params.append(image_id)
    rows = _fetch_dicts(
        conn,
        f"SELECT id, executable FROM registry_common_dialog_mru WHERE {' AND '.join(where)}",
        params,
    )
    updated = 0
    for row in rows:
        values = resolved_common_dialog_values(row.get("executable"))
        _execute(
            conn,
            """
            UPDATE registry_common_dialog_mru
            SET executable_is_guid = ?,
                resolved_executable = ?,
                executable_resolution_source = ?,
                executable_resolution_confidence = ?
            WHERE id = ?
            """,
            [
                values["executable_is_guid"],
                values["resolved_executable"],
                values["executable_resolution_source"],
                values["executable_resolution_confidence"],
                row["id"],
            ],
        )
        updated += 1
    return updated


def _common_dialog_guid_rows(conn: SupportsExecute, *, case_id: str, image_id: str | None) -> list[dict[str, Any]]:
    where = ["case_id = ?", "executable_is_guid = 'true'"]
    params: list[object] = [case_id]
    if image_id is not None:
        where.append("image_id = ?")
        params.append(image_id)
    return _fetch_dicts(
        conn,
        f"""
        SELECT id, executable, absolute_path, opened_on, user_profile
        FROM registry_common_dialog_mru
        WHERE {' AND '.join(where)}
        """,
        params,
    )


def _shortcut_rows(conn: SupportsExecute, *, case_id: str, image_id: str | None) -> list[dict[str, Any]]:
    columns = _table_columns(conn, "shortcut_items")
    if "app_id_description" not in columns or "file_location" not in columns:
        return []
    where = ["case_id = ?", "artifact_type = 'jumplist'", "app_id_description IS NOT NULL"]
    params: list[object] = [case_id]
    if image_id is not None:
        where.append("image_id = ?")
        params.append(image_id)
    return _fetch_dicts(
        conn,
        f"""
        SELECT app_id_description, file_location, target_created, target_modified, target_accessed
        FROM shortcut_items
        WHERE {' AND '.join(where)}
        """,
        params,
    )


def _ensure_common_dialog_resolution_columns(conn: SupportsExecute) -> None:
    for column, definition in {
        "executable_is_guid": "TEXT",
        "resolved_executable": "TEXT",
        "executable_resolution_source": "TEXT",
        "executable_resolution_confidence": "TEXT",
    }.items():
        _add_column_if_missing(conn, "registry_common_dialog_mru", column, definition)


def _table_exists(conn: SupportsExecute, table: str) -> bool:
    if isinstance(conn, sqlite3.Connection):
        row = conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ? LIMIT 1", (table,)).fetchone()
        return row is not None
    return bool(
        conn.execute(
            "SELECT 1 FROM information_schema.tables WHERE table_name = ? LIMIT 1",
            [table],
        ).fetchone()
    )


def _has_column(conn: SupportsExecute, table: str, column: str) -> bool:
    return column in _table_columns(conn, table)


def _add_column_if_missing(conn: SupportsExecute, table: str, column: str, definition: str) -> None:
    if column not in _table_columns(conn, table):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def _table_columns(conn: SupportsExecute, table: str) -> set[str]:
    if isinstance(conn, sqlite3.Connection):
        return {str(row["name"]) for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    return {str(row[1]) for row in conn.execute(f"PRAGMA table_info('{table}')").fetchall()}


def _fetch_dicts(conn: SupportsExecute, query: str, params: list[object]) -> list[dict[str, Any]]:
    cursor = conn.execute(query, params)
    rows = cursor.fetchall()
    if not rows:
        return []
    if isinstance(rows[0], sqlite3.Row):
        return [dict(row) for row in rows]
    columns = [description[0] for description in cursor.description]
    return [dict(zip(columns, row)) for row in rows]


def _execute(conn: SupportsExecute, query: str, params: list[object]) -> None:
    conn.execute(query, params)


def _commit_if_supported(conn: Any) -> None:
    if hasattr(conn, "commit"):
        conn.commit()
