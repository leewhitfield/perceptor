from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

import duckdb

from forensic_orchestrator.db import Database, utc_now
from forensic_orchestrator.models import EvidenceImage
from forensic_orchestrator.paths import WorkspacePaths
from forensic_orchestrator.safety import MountError
from forensic_orchestrator.tools import chromium, firefox
from forensic_orchestrator.tools.normalized import (
    normalized_browser_download_row,
    normalized_browser_history_row,
    normalized_firefox_history_row,
)

from .vshadow import VscSnapshot, discover_vsc_snapshots, mount_vsc_snapshot, unmount_vsc
from .vsc_promote import add_vsc_provenance, clear_vsc_rows, promote_deduped_rows


VSC_BROWSER_HISTORY_COLUMNS = [
    "case_id",
    "image_id",
    "snapshot_id",
    "snapshot_index",
    "snapshot_created_utc",
    "browser",
    "source_path",
    "profile_path",
    "url",
    "title",
    "visit_time_utc",
    "visit_count",
    "typed_count",
    "visit_source",
    "visit_source_label",
    "local_vs_synced",
    "record_signature",
    "parsed_at",
]

VSC_BROWSER_DOWNLOAD_COLUMNS = [
    "case_id",
    "image_id",
    "snapshot_id",
    "snapshot_index",
    "snapshot_created_utc",
    "browser",
    "source_path",
    "profile_path",
    "target_path",
    "tab_url",
    "site_url",
    "referrer",
    "start_time_utc",
    "end_time_utc",
    "received_bytes",
    "total_bytes",
    "state",
    "danger_type",
    "interrupt_reason",
    "record_signature",
    "parsed_at",
]

VSC_FIREFOX_HISTORY_COLUMNS = [
    "case_id",
    "image_id",
    "snapshot_id",
    "snapshot_index",
    "snapshot_created_utc",
    "source_path",
    "profile_path",
    "url",
    "title",
    "visit_time_utc",
    "visit_type",
    "visit_count",
    "typed",
    "hidden",
    "frecency",
    "visit_source",
    "visit_source_label",
    "local_vs_synced",
    "record_signature",
    "parsed_at",
]


def run_vsc_browser_scan(
    *,
    db: Database,
    paths: WorkspacePaths,
    case_id: str,
    image: EvidenceImage,
    snapshot_indexes: list[int] | None = None,
    use_sudo_mount: bool = False,
) -> dict[str, Any]:
    paths.ensure_case_tree(case_id)
    started_at = utc_now()
    inventory = discover_vsc_snapshots(db=db, paths=paths, case_id=case_id, image=image)
    snapshots = [_snapshot_from_payload(item) for item in inventory.get("snapshots", [])]
    if snapshot_indexes:
        wanted = set(snapshot_indexes)
        snapshots = [snapshot for snapshot in snapshots if snapshot.index in wanted]
    if not snapshots:
        raise MountError("No VSC snapshots selected for browser scan")

    db_path = paths.vsc_parsed_db_path(case_id)
    conn = duckdb.connect(str(db_path))
    try:
        _ensure_browser_tables(conn)
        snapshot_ids = [f"vss{snapshot.index}" for snapshot in snapshots]
        _clear_snapshot_rows(conn, case_id=case_id, image_id=image.id, snapshot_ids=snapshot_ids)
        clear_vsc_rows(db, table="browser_history", case_id=case_id, image_id=image.id, snapshot_ids=snapshot_ids)
        clear_vsc_rows(db, table="browser_downloads", case_id=case_id, image_id=image.id, snapshot_ids=snapshot_ids)
        clear_vsc_rows(db, table="firefox_history", case_id=case_id, image_id=image.id, snapshot_ids=snapshot_ids)
        live_signatures = _live_browser_signatures(db, case_id=case_id)
        snapshot_results: list[dict[str, Any]] = []
        failures: list[dict[str, Any]] = []
        all_browser_history: list[dict[str, Any]] = []
        all_browser_downloads: list[dict[str, Any]] = []
        all_firefox_history: list[dict[str, Any]] = []
        for snapshot in snapshots:
            snapshot_id = f"vss{snapshot.index}"
            step_started_at = utc_now()
            try:
                mount = mount_vsc_snapshot(
                    db=db,
                    paths=paths,
                    case_id=case_id,
                    image=image,
                    snapshot_index=snapshot.index,
                    use_sudo_mount=use_sudo_mount,
                )
                rows = parse_vsc_browser_snapshot(
                    case_id=case_id,
                    computer_id=image.computer_id or "vsc",
                    image_id=image.id,
                    snapshot=snapshot,
                    snapshot_id=snapshot_id,
                    mount_path=Path(mount["volume_mount_path"]),
                )
                _insert_rows(conn, "vsc_browser_history", VSC_BROWSER_HISTORY_COLUMNS, rows["browser_history"])
                _insert_rows(conn, "vsc_browser_downloads", VSC_BROWSER_DOWNLOAD_COLUMNS, rows["browser_downloads"])
                _insert_rows(conn, "vsc_firefox_history", VSC_FIREFOX_HISTORY_COLUMNS, rows["firefox_history"])
                all_browser_history.extend(rows["browser_history"])
                all_browser_downloads.extend(rows["browser_downloads"])
                all_firefox_history.extend(rows["firefox_history"])
                snapshot_results.append(
                    {
                        "snapshot_id": snapshot_id,
                        "snapshot_index": snapshot.index,
                        "snapshot_created_utc": snapshot.created_utc,
                        "browser_history_rows": len(rows["browser_history"]),
                        "browser_download_rows": len(rows["browser_downloads"]),
                        "firefox_history_rows": len(rows["firefox_history"]),
                        "mount_path": mount["volume_mount_path"],
                        "started_at": step_started_at,
                        "ended_at": utc_now(),
                    }
                )
            except Exception as exc:
                failures.append(
                    {
                        "snapshot_id": snapshot_id,
                        "snapshot_index": snapshot.index,
                        "snapshot_created_utc": snapshot.created_utc,
                        "error": str(exc),
                        "started_at": step_started_at,
                        "ended_at": utc_now(),
                    }
                )
            finally:
                unmount_vsc(paths=paths, case_id=case_id, snapshot_id=snapshot_id, use_sudo_mount=use_sudo_mount)

        promote_deduped_rows(
            db,
            table="browser_history",
            rows=[add_vsc_provenance(row, source_csv=f"vsc://{row.get('snapshot_id')}/ChromiumParser") for row in all_browser_history],
            key_func=browser_history_signature,
        )
        promote_deduped_rows(
            db,
            table="browser_downloads",
            rows=[add_vsc_provenance(row, source_csv=f"vsc://{row.get('snapshot_id')}/ChromiumParser") for row in all_browser_downloads],
            key_func=browser_download_signature,
        )
        promote_deduped_rows(
            db,
            table="firefox_history",
            rows=[add_vsc_provenance(row, source_csv=f"vsc://{row.get('snapshot_id')}/FirefoxParser") for row in all_firefox_history],
            key_func=firefox_history_signature,
        )
        snapshot_rows = _snapshot_rows(conn, case_id=case_id, image_id=image.id)
        comparison = compare_browser_snapshots(live_signatures=live_signatures, snapshot_rows=snapshot_rows)
        ended_at = utc_now()
        report_path = paths.vsc_reports_dir(case_id) / "browser-vsc-comparison.md"
        report_path.write_text(
            _browser_comparison_markdown(
                comparison,
                snapshot_results,
                failures,
                started_at=started_at,
                ended_at=ended_at,
            ),
            encoding="utf-8",
        )
        payload = {
            "case_id": case_id,
            "image_id": image.id,
            "started_at": started_at,
            "ended_at": ended_at,
            "vsc_db_path": str(db_path),
            "report_path": str(report_path),
            "snapshot_count": len(snapshots),
            "successful_snapshots": len(snapshot_results),
            "failed_snapshots": len(failures),
            "snapshot_results": snapshot_results,
            "failures": failures,
            "comparison_summary": comparison["summary"],
        }
        _write_json(paths.vsc_work_dir(case_id) / "browser-scan.json", payload)
        return payload
    finally:
        conn.close()


def parse_vsc_browser_snapshot(
    *,
    case_id: str,
    computer_id: str = "vsc",
    image_id: str,
    snapshot: VscSnapshot,
    snapshot_id: str,
    mount_path: Path,
) -> dict[str, list[dict[str, Any]]]:
    roots = [mount_path / "Users", mount_path / "Windows.old" / "Users"]
    browser_history: list[dict[str, Any]] = []
    browser_downloads: list[dict[str, Any]] = []
    firefox_history: list[dict[str, Any]] = []
    for root in roots:
        if not root.exists():
            continue
        for history_path in chromium._rglob(root, "History"):
            parsed_history = chromium._history_rows(history_path, root)
            for row_number, row in enumerate(parsed_history, start=1):
                normalized = normalized_browser_history_row(
                    case_id=case_id,
                    computer_id=computer_id,
                    image_id=image_id,
                    tool_output_id=f"{snapshot_id}-ChromiumParser",
                    tool_name="ChromiumParser",
                    source_csv=root / "BrowserHistory.csv",
                    row_number=row_number,
                    row=dict(row),
                )
                _add_snapshot_fields(normalized, snapshot=snapshot, snapshot_id=snapshot_id)
                _normalize_source_path(normalized, mount_path=mount_path)
                normalized["record_signature"] = browser_history_signature(normalized)
                browser_history.append(normalized)
            parsed_downloads = chromium._download_rows(history_path, root)
            for row_number, row in enumerate(parsed_downloads, start=1):
                normalized = normalized_browser_download_row(
                    case_id=case_id,
                    computer_id=computer_id,
                    image_id=image_id,
                    tool_output_id=f"{snapshot_id}-ChromiumParser",
                    tool_name="ChromiumParser",
                    source_csv=root / "BrowserDownloads.csv",
                    row_number=row_number,
                    row=dict(row),
                )
                _add_snapshot_fields(normalized, snapshot=snapshot, snapshot_id=snapshot_id)
                _normalize_source_path(normalized, mount_path=mount_path)
                normalized["record_signature"] = browser_download_signature(normalized)
                browser_downloads.append(normalized)
        for places_path in firefox._rglob(root, "places.sqlite"):
            parsed_firefox = firefox._history_rows(places_path, root)
            for row_number, row in enumerate(parsed_firefox, start=1):
                normalized = normalized_firefox_history_row(
                    case_id=case_id,
                    computer_id=computer_id,
                    image_id=image_id,
                    tool_output_id=f"{snapshot_id}-FirefoxParser",
                    tool_name="FirefoxParser",
                    source_csv=root / "FirefoxHistory.csv",
                    row_number=row_number,
                    row=dict(row),
                )
                _add_snapshot_fields(normalized, snapshot=snapshot, snapshot_id=snapshot_id)
                _normalize_source_path(normalized, mount_path=mount_path)
                normalized["record_signature"] = firefox_history_signature(normalized)
                firefox_history.append(normalized)
    return {
        "browser_history": browser_history,
        "browser_downloads": browser_downloads,
        "firefox_history": firefox_history,
    }


def compare_browser_snapshots(*, live_signatures: set[str], snapshot_rows: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    by_snapshot: dict[str, dict[str, Any]] = {}
    type_counts: Counter[str] = Counter()
    for artifact_type, rows in snapshot_rows.items():
        for row in rows:
            summary = by_snapshot.setdefault(
                row["snapshot_id"],
                {
                    "snapshot_id": row["snapshot_id"],
                    "snapshot_index": row["snapshot_index"],
                    "snapshot_created_utc": row.get("snapshot_created_utc") or "",
                    "row_count": 0,
                    "unique_not_live_count": 0,
                },
            )
            summary["row_count"] += 1
            signature = row.get("record_signature") or ""
            if not signature or signature in live_signatures:
                continue
            summary["unique_not_live_count"] += 1
            type_counts[artifact_type] += 1
            findings.append({"artifact_type": artifact_type, **row})
    unique: dict[str, dict[str, Any]] = {}
    for finding in findings:
        unique.setdefault(finding["record_signature"], finding)
    unique_findings = sorted(unique.values(), key=lambda item: (item["artifact_type"], item.get("visit_time_utc") or item.get("start_time_utc") or "", item.get("url") or item.get("target_path") or ""))
    return {
        "summary": {
            "vsc_browser_rows": sum(len(rows) for rows in snapshot_rows.values()),
            "unique_vsc_records_not_live": len(unique_findings),
            "artifact_type_count": len(type_counts),
            "artifact_counts": dict(sorted(type_counts.items())),
        },
        "snapshots": sorted(by_snapshot.values(), key=lambda item: int(item["snapshot_index"])),
        "findings": unique_findings,
    }


def browser_history_signature(row: dict[str, Any]) -> str:
    url = _text(row.get("url"))
    visit_time = _text(row.get("visit_time_utc"))
    if not url or not visit_time:
        return ""
    return "|".join(("browser_history", _text(row.get("browser")), _normalize_profile(row.get("profile_path")), url, visit_time))


def browser_download_signature(row: dict[str, Any]) -> str:
    start_time = _text(row.get("start_time_utc"))
    target = _normalize_windows_path(row.get("target_path"))
    tab_url = _text(row.get("tab_url"))
    site_url = _text(row.get("site_url"))
    if not start_time and not target:
        return ""
    return "|".join(
        (
            "browser_download",
            _text(row.get("browser")),
            _normalize_profile(row.get("profile_path")),
            target,
            tab_url,
            site_url,
            start_time,
            _text(row.get("end_time_utc")),
        )
    )


def firefox_history_signature(row: dict[str, Any]) -> str:
    url = _text(row.get("url"))
    visit_time = _text(row.get("visit_time_utc"))
    if not url or not visit_time:
        return ""
    return "|".join(("firefox_history", _normalize_profile(row.get("profile_path")), url, visit_time, _text(row.get("visit_type"))))


def _live_browser_signatures(db: Database, *, case_id: str) -> set[str]:
    case = db.get_case(case_id)
    duckdb_path = case.root / "analytics" / "events.duckdb"
    signatures: set[str] = set()
    if not duckdb_path.exists():
        return signatures
    conn = duckdb.connect(str(duckdb_path), read_only=True)
    try:
        for row in conn.execute(
            """
            SELECT browser, profile_path, url, visit_time_utc
            FROM browser_history
            WHERE case_id = ?
            """,
            [case_id],
        ).fetchall():
            signatures.add(browser_history_signature({"browser": row[0], "profile_path": row[1], "url": row[2], "visit_time_utc": row[3]}))
        for row in conn.execute(
            """
            SELECT browser, profile_path, target_path, tab_url, site_url, start_time_utc, end_time_utc
            FROM browser_downloads
            WHERE case_id = ?
            """,
            [case_id],
        ).fetchall():
            signatures.add(
                browser_download_signature(
                    {
                        "browser": row[0],
                        "profile_path": row[1],
                        "target_path": row[2],
                        "tab_url": row[3],
                        "site_url": row[4],
                        "start_time_utc": row[5],
                        "end_time_utc": row[6],
                    }
                )
            )
        for row in conn.execute(
            """
            SELECT profile_path, url, visit_time_utc, visit_type
            FROM firefox_history
            WHERE case_id = ?
            """,
            [case_id],
        ).fetchall():
            signatures.add(firefox_history_signature({"profile_path": row[0], "url": row[1], "visit_time_utc": row[2], "visit_type": row[3]}))
    finally:
        conn.close()
    signatures.discard("")
    return signatures


def _ensure_browser_tables(conn: duckdb.DuckDBPyConnection) -> None:
    _ensure_table(conn, "vsc_browser_history", VSC_BROWSER_HISTORY_COLUMNS)
    _ensure_table(conn, "vsc_browser_downloads", VSC_BROWSER_DOWNLOAD_COLUMNS)
    _ensure_table(conn, "vsc_firefox_history", VSC_FIREFOX_HISTORY_COLUMNS)


def _ensure_table(conn: duckdb.DuckDBPyConnection, table: str, columns: list[str]) -> None:
    column_defs = ", ".join(f"{column} VARCHAR" for column in columns)
    conn.execute(f"CREATE TABLE IF NOT EXISTS {table} ({column_defs})")
    existing = {row[1] for row in conn.execute(f"PRAGMA table_info('{table}')").fetchall()}
    for column in columns:
        if column not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} VARCHAR")


def _clear_snapshot_rows(
    conn: duckdb.DuckDBPyConnection,
    *,
    case_id: str,
    image_id: str,
    snapshot_ids: list[str],
) -> None:
    if not snapshot_ids:
        return
    placeholders = ", ".join("?" for _ in snapshot_ids)
    params = [case_id, image_id, *snapshot_ids]
    for table in ("vsc_browser_history", "vsc_browser_downloads", "vsc_firefox_history"):
        conn.execute(f"DELETE FROM {table} WHERE case_id = ? AND image_id = ? AND snapshot_id IN ({placeholders})", params)


def _insert_rows(conn: duckdb.DuckDBPyConnection, table: str, columns: list[str], rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    placeholders = ", ".join("?" for _ in columns)
    conn.executemany(
        f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders})",
        [[_text(row.get(column)) for column in columns] for row in rows],
    )


def _snapshot_rows(conn: duckdb.DuckDBPyConnection, *, case_id: str, image_id: str) -> dict[str, list[dict[str, Any]]]:
    results: dict[str, list[dict[str, Any]]] = {}
    for artifact_type, table in (
        ("browser_history", "vsc_browser_history"),
        ("browser_download", "vsc_browser_downloads"),
        ("firefox_history", "vsc_firefox_history"),
    ):
        rows = conn.execute(f"SELECT * FROM {table} WHERE case_id = ? AND image_id = ?", [case_id, image_id]).fetchall()
        columns = [desc[0] for desc in conn.description]
        results[artifact_type] = [dict(zip(columns, row, strict=False)) for row in rows]
    return results


def _browser_comparison_markdown(
    comparison: dict[str, Any],
    snapshot_results: list[dict[str, Any]],
    failures: list[dict[str, Any]],
    *,
    started_at: str,
    ended_at: str,
) -> str:
    summary = comparison["summary"]
    lines = [
        "# VSC Browser Comparison",
        "",
        "## Summary",
        "",
        f"- Started: {started_at}",
        f"- Ended: {ended_at}",
        f"- VSC browser rows parsed: {summary['vsc_browser_rows']}",
        f"- Unique VSC browser records not present live: {summary['unique_vsc_records_not_live']}",
        f"- Artifact types with VSC-only records: {summary['artifact_type_count']}",
        "",
        "## Artifact Counts",
        "",
        "| Artifact | Unique not live |",
        "| --- | ---: |",
    ]
    for artifact_type, count in summary["artifact_counts"].items():
        lines.append(f"| `{artifact_type}` | {count} |")
    lines.extend(
        [
            "",
            "## Snapshot Counts",
            "",
            "| Snapshot | Created | Rows | Unique not live |",
            "| --- | --- | ---: | ---: |",
        ]
    )
    unique_by_snapshot = {row["snapshot_id"]: row["unique_not_live_count"] for row in comparison["snapshots"]}
    for result in snapshot_results:
        row_count = result["browser_history_rows"] + result["browser_download_rows"] + result["firefox_history_rows"]
        lines.append(
            f"| {result['snapshot_id']} | {result['snapshot_created_utc']} | {row_count} | {unique_by_snapshot.get(result['snapshot_id'], 0)} |"
        )
    findings = comparison["findings"][:50]
    lines.extend(
        [
            "",
            "## Examples",
            "",
            "| Type | Snapshot | Time | Browser/Profile | URL or Target | Title / Source |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )
    for finding in findings:
        artifact_type = finding["artifact_type"]
        time_value = finding.get("visit_time_utc") or finding.get("start_time_utc") or ""
        location = finding.get("url") or finding.get("target_path") or ""
        title = finding.get("title") or finding.get("tab_url") or finding.get("site_url") or ""
        browser_profile = f"{finding.get('browser') or 'firefox'} / {finding.get('profile_path') or ''}"
        lines.append(
            f"| `{artifact_type}` | {finding['snapshot_id']} | {time_value} | `{_md(browser_profile)}` | `{_md(location)}` | `{_md(title)}` |"
        )
    if failures:
        lines.extend(["", "## Failures", "", "| Snapshot | Error |", "| --- | --- |"])
        for failure in failures:
            lines.append(f"| {failure['snapshot_id']} | `{_md(failure['error'])}` |")
    lines.extend(["", "## Processing", ""])
    for result in snapshot_results:
        lines.append(
            f"- `{result['snapshot_id']}` parsed {result['browser_history_rows']} Chromium history rows, "
            f"{result['browser_download_rows']} Chromium download rows, and {result['firefox_history_rows']} Firefox history rows "
            f"from {result['started_at']} to {result['ended_at']}"
        )
    return "\n".join(lines) + "\n"


def _add_snapshot_fields(row: dict[str, Any], *, snapshot: VscSnapshot, snapshot_id: str) -> None:
    row["snapshot_id"] = snapshot_id
    row["snapshot_index"] = str(snapshot.index)
    row["snapshot_created_utc"] = snapshot.created_utc
    row["parsed_at"] = utc_now()


def _normalize_source_path(row: dict[str, Any], *, mount_path: Path) -> None:
    source_path = Path(_text(row.get("source_path")))
    try:
        row["source_path"] = "/" + source_path.relative_to(mount_path).as_posix()
    except ValueError:
        row["source_path"] = str(source_path)


def _normalize_profile(value: object) -> str:
    text = _text(value).replace("\\", "/").strip("/")
    parts = [part for part in text.split("/") if part]
    if len(parts) >= 2 and parts[0].lower() == "users":
        parts = parts[1:]
    return "/".join(parts).casefold()


def _normalize_windows_path(value: object) -> str:
    text = _text(value).replace("\\", "/")
    if len(text) >= 2 and text[1] == ":":
        text = text[2:]
    return text.strip("/").casefold()


def _snapshot_from_payload(payload: dict[str, Any]) -> VscSnapshot:
    return VscSnapshot(
        index=int(payload["index"]),
        snapshot_id=str(payload.get("snapshot_id") or ""),
        identifier=str(payload.get("identifier") or ""),
        shadow_copy_set_id=str(payload.get("shadow_copy_set_id") or ""),
        created_utc=str(payload.get("created_utc") or ""),
    )


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    import json

    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _text(value: object) -> str:
    if value is None:
        return ""
    return str(value)


def _md(value: object, limit: int = 120) -> str:
    text = _text(value).replace("|", "\\|").replace("\n", " ")
    if len(text) > limit:
        return text[: limit - 1] + "..."
    return text
