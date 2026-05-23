from __future__ import annotations

import csv
import subprocess
import shutil
from collections import Counter
from pathlib import Path
from typing import Any

import duckdb

from forensic_orchestrator.config import default_plugin_path
from forensic_orchestrator.db import Database, utc_now
from forensic_orchestrator.models import EvidenceImage
from forensic_orchestrator.paths import WorkspacePaths
from forensic_orchestrator.safety import MountError
from forensic_orchestrator.tools.ez_registry import normalized_amcache_row, normalized_shimcache_row
from forensic_orchestrator.tools.registry import ToolRegistry, build_tool_command
from forensic_orchestrator.tools.runner import prepare_registry_transaction_logs

from .vshadow import VscSnapshot, discover_vsc_snapshots, mount_vsc_snapshot, unmount_vsc
from .vsc_promote import add_vsc_provenance, clear_vsc_rows, promote_deduped_rows


AMCACHE_COLUMNS = [
    "case_id",
    "image_id",
    "snapshot_id",
    "snapshot_index",
    "snapshot_created_utc",
    "id",
    "computer_id",
    "tool_output_id",
    "tool_name",
    "source_csv",
    "row_number",
    "entry_type",
    "source_file",
    "path",
    "name",
    "publisher",
    "product_name",
    "product_version",
    "file_version",
    "sha1",
    "sha256",
    "binary_type",
    "size",
    "created_utc",
    "modified_utc",
    "link_date",
    "compile_time",
    "program_id",
    "install_date",
    "unassociated",
    "record_signature",
    "parsed_at",
]

SHIMCACHE_COLUMNS = [
    "case_id",
    "image_id",
    "snapshot_id",
    "snapshot_index",
    "snapshot_created_utc",
    "id",
    "computer_id",
    "tool_output_id",
    "tool_name",
    "source_csv",
    "row_number",
    "source_file",
    "control_set",
    "entry_number",
    "path",
    "last_modified_utc",
    "executed",
    "source_key",
    "record_signature",
    "parsed_at",
]


def run_vsc_appcompat_scan(
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
        raise MountError("No VSC snapshots selected for Amcache/ShimCache scan")

    db_path = paths.vsc_parsed_db_path(case_id)
    conn = duckdb.connect(str(db_path))
    try:
        _ensure_tables(conn)
        snapshot_ids = [f"vss{snapshot.index}" for snapshot in snapshots]
        _clear_snapshot_rows(conn, case_id=case_id, image_id=image.id, snapshot_ids=snapshot_ids)
        clear_vsc_rows(db, table="amcache_entries", case_id=case_id, image_id=image.id, snapshot_ids=snapshot_ids)
        clear_vsc_rows(db, table="shimcache_entries", case_id=case_id, image_id=image.id, snapshot_ids=snapshot_ids)
        live_signatures = _live_signatures(db, case_id=case_id)
        snapshot_results: list[dict[str, Any]] = []
        failures: list[dict[str, Any]] = []
        all_amcache_rows: list[dict[str, Any]] = []
        all_shimcache_rows: list[dict[str, Any]] = []
        registry = ToolRegistry.from_files([default_plugin_path()])
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
                rows = parse_vsc_appcompat_snapshot(
                    paths=paths,
                    registry=registry,
                    case_id=case_id,
                    computer_id=image.computer_id or "vsc",
                    image_id=image.id,
                    snapshot=snapshot,
                    snapshot_id=snapshot_id,
                    mount_path=Path(mount["volume_mount_path"]),
                )
                _insert_rows(conn, "vsc_amcache_entries", AMCACHE_COLUMNS, rows["amcache"])
                _insert_rows(conn, "vsc_shimcache_entries", SHIMCACHE_COLUMNS, rows["shimcache"])
                all_amcache_rows.extend(rows["amcache"])
                all_shimcache_rows.extend(rows["shimcache"])
                snapshot_results.append(
                    {
                        "snapshot_id": snapshot_id,
                        "snapshot_index": snapshot.index,
                        "snapshot_created_utc": snapshot.created_utc,
                        "amcache_rows": len(rows["amcache"]),
                        "shimcache_rows": len(rows["shimcache"]),
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
            table="amcache_entries",
            rows=[add_vsc_provenance(row, source_csv=f"vsc://{row.get('snapshot_id')}/AmcacheParser") for row in all_amcache_rows],
            key_func=amcache_signature,
        )
        promote_deduped_rows(
            db,
            table="shimcache_entries",
            rows=[add_vsc_provenance(row, source_csv=f"vsc://{row.get('snapshot_id')}/AppCompatCacheParser") for row in all_shimcache_rows],
            key_func=shimcache_signature,
        )
        comparison = compare_appcompat_snapshots(
            live_signatures=live_signatures,
            snapshot_rows=_snapshot_rows(conn, case_id=case_id, image_id=image.id),
        )
        ended_at = utc_now()
        report_path = paths.vsc_reports_dir(case_id) / "appcompat-vsc-comparison.md"
        report_path.write_text(
            _comparison_markdown(comparison, snapshot_results, failures, started_at=started_at, ended_at=ended_at),
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
        _write_json(paths.vsc_work_dir(case_id) / "appcompat-scan.json", payload)
        return payload
    finally:
        conn.close()


def parse_vsc_appcompat_snapshot(
    *,
    paths: WorkspacePaths,
    registry: ToolRegistry,
    case_id: str,
    image_id: str,
    computer_id: str = "vsc",
    snapshot: VscSnapshot,
    snapshot_id: str,
    mount_path: Path,
) -> dict[str, list[dict[str, Any]]]:
    extract_dir = paths.vsc_snapshot_extract_dir(case_id, snapshot_id) / "appcompat"
    output_root = paths.vsc_work_dir(case_id) / "outputs" / snapshot_id
    amcache_hive = _copy_optional(mount_path, "Windows/AppCompat/Programs/Amcache.hve", extract_dir / "Amcache.hve")
    for suffix in (".LOG1", ".LOG2"):
        _copy_optional(mount_path, f"Windows/AppCompat/Programs/Amcache.hve{suffix}", extract_dir / f"Amcache.hve{suffix}")
    system_hive = _copy_optional(mount_path, "Windows/System32/config/SYSTEM", extract_dir / "SYSTEM")
    for suffix in (".LOG1", ".LOG2"):
        _copy_optional(mount_path, f"Windows/System32/config/SYSTEM{suffix}", extract_dir / f"SYSTEM{suffix}")

    amcache_rows: list[dict[str, Any]] = []
    shimcache_rows: list[dict[str, Any]] = []
    if amcache_hive:
        amcache_rows = _run_amcache_parser(
            registry=registry,
            case_id=case_id,
            computer_id=computer_id,
            image_id=image_id,
            snapshot=snapshot,
            snapshot_id=snapshot_id,
            hive=amcache_hive,
            output=output_root / "AmcacheParser",
        )
    if system_hive:
        shimcache_rows = _run_shimcache_parser(
            registry=registry,
            case_id=case_id,
            computer_id=computer_id,
            image_id=image_id,
            snapshot=snapshot,
            snapshot_id=snapshot_id,
            hive=system_hive,
            output=output_root / "AppCompatCacheParser",
        )
    return {"amcache": amcache_rows, "shimcache": shimcache_rows}


def compare_appcompat_snapshots(*, live_signatures: set[str], snapshot_rows: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    by_snapshot: dict[str, dict[str, Any]] = {}
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
            findings.append({"artifact_type": artifact_type, **row})
    unique: dict[str, dict[str, Any]] = {}
    for finding in findings:
        unique.setdefault(finding["record_signature"], finding)
    unique_findings = sorted(
        unique.values(),
        key=lambda item: (item["artifact_type"], item.get("modified_utc") or item.get("last_modified_utc") or "", item.get("path") or ""),
    )
    type_counts = Counter(finding["artifact_type"] for finding in unique_findings)
    return {
        "summary": {
            "vsc_appcompat_rows": sum(len(rows) for rows in snapshot_rows.values()),
            "unique_vsc_records_not_live": len(unique_findings),
            "artifact_type_count": len(type_counts),
            "artifact_counts": dict(sorted(type_counts.items())),
        },
        "snapshots": sorted(by_snapshot.values(), key=lambda item: int(item["snapshot_index"])),
        "findings": unique_findings,
    }


def amcache_signature(row: dict[str, Any]) -> str:
    path = _normalize_windows_path(row.get("path"))
    sha1 = _text(row.get("sha1")).casefold()
    modified = _text(row.get("modified_utc"))
    name = _text(row.get("name")).casefold()
    if not path and not sha1 and not name:
        return ""
    return "|".join(("amcache", _text(row.get("entry_type")).casefold(), path, sha1, modified, name))


def shimcache_signature(row: dict[str, Any]) -> str:
    path = _normalize_windows_path(row.get("path"))
    modified = _text(row.get("last_modified_utc"))
    if not path and not modified:
        return ""
    return "|".join(("shimcache", path, modified, _text(row.get("executed")).casefold()))


def _run_amcache_parser(
    *,
    registry: ToolRegistry,
    case_id: str,
    computer_id: str,
    image_id: str,
    snapshot: VscSnapshot,
    snapshot_id: str,
    hive: Path,
    output: Path,
) -> list[dict[str, Any]]:
    tool = registry.get_tool("AmcacheParser")
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)
    prepare_registry_transaction_logs({"amcache_hive": hive})
    command = build_tool_command(tool, mount=Path("/unused"), output=output, artifacts={"amcache_hive": hive})
    _run_command(command, output)
    rows: list[dict[str, Any]] = []
    for csv_path in sorted(output.glob("*.csv")):
        for row_number, row in enumerate(_read_csv(csv_path), start=1):
            normalized = normalized_amcache_row(
                case_id=case_id,
                computer_id=computer_id,
                image_id=image_id,
                tool_output_id=f"{snapshot_id}-AmcacheParser",
                tool_name="AmcacheParser",
                source_csv=csv_path,
                row_number=row_number,
                row=row,
            )
            if _has_control_characters(normalized.get("path")):
                continue
            _add_snapshot_fields(normalized, snapshot=snapshot, snapshot_id=snapshot_id)
            normalized["record_signature"] = amcache_signature(normalized)
            rows.append(normalized)
    return rows


def _run_shimcache_parser(
    *,
    registry: ToolRegistry,
    case_id: str,
    computer_id: str,
    image_id: str,
    snapshot: VscSnapshot,
    snapshot_id: str,
    hive: Path,
    output: Path,
) -> list[dict[str, Any]]:
    tool = registry.get_tool("AppCompatCacheParser")
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)
    prepare_registry_transaction_logs({"registry_system": hive})
    command = build_tool_command(tool, mount=Path("/unused"), output=output, artifacts={"registry_system": hive})
    _run_command(command, output)
    rows: list[dict[str, Any]] = []
    for csv_path in sorted(output.glob("*.csv")):
        for row_number, row in enumerate(_read_csv(csv_path), start=1):
            normalized = normalized_shimcache_row(
                case_id=case_id,
                computer_id=computer_id,
                image_id=image_id,
                tool_output_id=f"{snapshot_id}-AppCompatCacheParser",
                tool_name="AppCompatCacheParser",
                source_csv=csv_path,
                row_number=row_number,
                row=row,
            )
            _add_snapshot_fields(normalized, snapshot=snapshot, snapshot_id=snapshot_id)
            normalized["record_signature"] = shimcache_signature(normalized)
            rows.append(normalized)
    return rows


def _live_signatures(db: Database, *, case_id: str) -> set[str]:
    case = db.get_case(case_id)
    duckdb_path = case.root / "analytics" / "events.duckdb"
    signatures: set[str] = set()
    if not duckdb_path.exists():
        return signatures
    conn = duckdb.connect(str(duckdb_path), read_only=True)
    try:
        for row in conn.execute(
            """
            SELECT entry_type, path, name, sha1, modified_utc
            FROM amcache_entries
            WHERE case_id = ?
            """,
            [case_id],
        ).fetchall():
            signatures.add(amcache_signature({"entry_type": row[0], "path": row[1], "name": row[2], "sha1": row[3], "modified_utc": row[4]}))
        for row in conn.execute(
            """
            SELECT path, last_modified_utc, executed
            FROM shimcache_entries
            WHERE case_id = ?
            """,
            [case_id],
        ).fetchall():
            signatures.add(shimcache_signature({"path": row[0], "last_modified_utc": row[1], "executed": row[2]}))
    finally:
        conn.close()
    signatures.discard("")
    return signatures


def _ensure_tables(conn: duckdb.DuckDBPyConnection) -> None:
    _ensure_table(conn, "vsc_amcache_entries", AMCACHE_COLUMNS)
    _ensure_table(conn, "vsc_shimcache_entries", SHIMCACHE_COLUMNS)


def _ensure_table(conn: duckdb.DuckDBPyConnection, table: str, columns: list[str]) -> None:
    column_defs = ", ".join(f"{column} VARCHAR" for column in columns)
    conn.execute(f"CREATE TABLE IF NOT EXISTS {table} ({column_defs})")
    existing = {row[1] for row in conn.execute(f"PRAGMA table_info('{table}')").fetchall()}
    for column in columns:
        if column not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} VARCHAR")


def _clear_snapshot_rows(conn: duckdb.DuckDBPyConnection, *, case_id: str, image_id: str, snapshot_ids: list[str]) -> None:
    if not snapshot_ids:
        return
    placeholders = ", ".join("?" for _ in snapshot_ids)
    params = [case_id, image_id, *snapshot_ids]
    for table in ("vsc_amcache_entries", "vsc_shimcache_entries"):
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
    for artifact_type, table in (("amcache", "vsc_amcache_entries"), ("shimcache", "vsc_shimcache_entries")):
        rows = conn.execute(f"SELECT * FROM {table} WHERE case_id = ? AND image_id = ?", [case_id, image_id]).fetchall()
        columns = [desc[0] for desc in conn.description]
        results[artifact_type] = [dict(zip(columns, row, strict=False)) for row in rows]
    return results


def _comparison_markdown(
    comparison: dict[str, Any],
    snapshot_results: list[dict[str, Any]],
    failures: list[dict[str, Any]],
    *,
    started_at: str,
    ended_at: str,
) -> str:
    summary = comparison["summary"]
    lines = [
        "# VSC Amcache and ShimCache Comparison",
        "",
        "## Summary",
        "",
        f"- Started: {started_at}",
        f"- Ended: {ended_at}",
        f"- VSC Amcache/ShimCache rows parsed: {summary['vsc_appcompat_rows']}",
        f"- Unique VSC records not present live: {summary['unique_vsc_records_not_live']}",
        f"- Artifact types with VSC-only records: {summary['artifact_type_count']}",
        "- Amcache and ShimCache are presence/cache indicators, not standalone execution proof.",
        "",
        "## Artifact Counts",
        "",
        "| Artifact | Unique not live |",
        "| --- | ---: |",
    ]
    for artifact_type, count in summary["artifact_counts"].items():
        lines.append(f"| `{artifact_type}` | {count} |")
    lines.extend(["", "## Snapshot Counts", "", "| Snapshot | Created | Rows | Unique not live |", "| --- | --- | ---: | ---: |"])
    unique_by_snapshot = {row["snapshot_id"]: row["unique_not_live_count"] for row in comparison["snapshots"]}
    for result in snapshot_results:
        row_count = result["amcache_rows"] + result["shimcache_rows"]
        lines.append(f"| {result['snapshot_id']} | {result['snapshot_created_utc']} | {row_count} | {unique_by_snapshot.get(result['snapshot_id'], 0)} |")
    lines.extend(["", "## Examples", "", "| Type | Snapshot | Time | Path | Name / Hash |", "| --- | --- | --- | --- | --- |"])
    for finding in comparison["findings"][:50]:
        time_value = finding.get("modified_utc") or finding.get("last_modified_utc") or finding.get("created_utc") or ""
        name_hash = finding.get("name") or finding.get("sha1") or finding.get("executed") or ""
        lines.append(
            f"| `{finding['artifact_type']}` | {finding['snapshot_id']} | {time_value} | `{_md(finding.get('path'))}` | `{_md(name_hash)}` |"
        )
    if failures:
        lines.extend(["", "## Failures", "", "| Snapshot | Error |", "| --- | --- |"])
        for failure in failures:
            lines.append(f"| {failure['snapshot_id']} | `{_md(failure['error'])}` |")
    lines.extend(["", "## Processing", ""])
    for result in snapshot_results:
        lines.append(
            f"- `{result['snapshot_id']}` parsed {result['amcache_rows']} Amcache rows and "
            f"{result['shimcache_rows']} ShimCache rows from {result['started_at']} to {result['ended_at']}"
        )
    return "\n".join(lines) + "\n"


def _copy_optional(mount_path: Path, relative_path: str, destination: Path) -> Path | None:
    source = _find_case_insensitive(mount_path, relative_path)
    try:
        if source is None or not source.is_file():
            return None
    except OSError:
        return None
    destination.parent.mkdir(parents=True, exist_ok=True)

    try:
        shutil.copy2(source, destination)
    except OSError:
        return None
    return destination


def _find_case_insensitive(root: Path, relative_path: str) -> Path | None:
    current = root
    for part in Path(relative_path).parts:
        candidate = current / part
        if candidate.exists():
            current = candidate
            continue
        lowered = part.casefold()
        try:
            matches = [child for child in current.iterdir() if child.name.casefold() == lowered]
        except OSError:
            return None
        if not matches:
            return None
        current = matches[0]
    return current


def _run_command(command: list[str], output: Path) -> None:
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    (output / "_stdout.txt").write_text(result.stdout or "", encoding="utf-8")
    (output / "_stderr.txt").write_text(result.stderr or "", encoding="utf-8")
    if result.returncode != 0:
        raise RuntimeError(f"{command[0]} failed with exit code {result.returncode}: {(result.stderr or '').strip()}")


def _read_csv(path: Path) -> list[dict[str, Any]]:
    with path.open("r", newline="", encoding="utf-8-sig", errors="replace") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def _add_snapshot_fields(row: dict[str, Any], *, snapshot: VscSnapshot, snapshot_id: str) -> None:
    row["snapshot_id"] = snapshot_id
    row["snapshot_index"] = str(snapshot.index)
    row["snapshot_created_utc"] = snapshot.created_utc
    row["parsed_at"] = utc_now()


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
    return str(value).strip()


def _md(value: object, limit: int = 120) -> str:
    text = _text(value).replace("|", "\\|").replace("\n", " ")
    if len(text) > limit:
        return text[: limit - 1] + "..."
    return text


def _has_control_characters(value: object) -> bool:
    text = _text(value)
    return any(ord(char) < 32 for char in text)
