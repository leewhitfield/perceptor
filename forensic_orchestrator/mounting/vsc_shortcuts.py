from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import duckdb

from forensic_orchestrator.db import Database, utc_now
from forensic_orchestrator.paths import WorkspacePaths
from forensic_orchestrator.safety import MountError, require_dependency
from forensic_orchestrator.tools.shortcuts import normalized_shortcut_rows
from .vsc_promote import add_vsc_provenance, clear_vsc_rows, promote_deduped_rows


VSC_SHORTCUT_COLUMNS = [
    "case_id",
    "image_id",
    "snapshot_id",
    "snapshot_index",
    "snapshot_created_utc",
    "source_vsc_path",
    "artifact_type",
    "artifact_name",
    "artifact_path",
    "file_name",
    "file_location",
    "target_created",
    "target_modified",
    "target_accessed",
    "device_type",
    "volume_serial_number",
    "volume_name",
    "command_line_arguments",
    "working_directory",
    "network_path",
    "machine_name",
    "app_id",
    "app_id_description",
    "entry_id",
    "destlist_version",
    "lnk_created",
    "lnk_modified",
    "lnk_accessed",
    "jumplist_item_number",
    "record_signature",
    "parsed_at",
]


def run_vsc_shortcut_scan(
    *,
    db: Database | None = None,
    paths: WorkspacePaths,
    case_id: str,
    image_id: str,
    computer_id: str | None = None,
    snapshot_indexes: list[int] | None = None,
    eztools_root: Path | None = None,
) -> dict[str, Any]:
    inventory_path = paths.vsc_work_dir(case_id) / "inventory.json"
    if not inventory_path.exists():
        raise MountError(f"VSC inventory not found: {inventory_path}")
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    snapshots = inventory.get("snapshots") or []
    if snapshot_indexes:
        wanted = set(snapshot_indexes)
        snapshots = [snapshot for snapshot in snapshots if int(snapshot["index"]) in wanted]
    if not snapshots:
        raise MountError("No VSC snapshots selected for shortcut scan")

    require_dependency("fls")
    require_dependency("icat")
    dotnet = _dotnet_executable()
    eztools_root = eztools_root or _resolve_eztools_root()
    lecmd = eztools_root / "LECmd" / "LECmd.dll"
    jlecmd = eztools_root / "JLECmd" / "JLECmd.dll"
    if not lecmd.is_file() or not jlecmd.is_file():
        raise MountError(f"LECmd/JLECmd not found under {eztools_root}")

    started_at = utc_now()
    db_path = paths.vsc_parsed_db_path(case_id)
    conn = duckdb.connect(str(db_path))
    try:
        _ensure_shortcut_table(conn)
        snapshot_ids = [f"vss{int(snapshot['index'])}" for snapshot in snapshots]
        _clear_snapshot_rows(conn, case_id=case_id, image_id=image_id, snapshot_ids=snapshot_ids)
        if db is not None:
            clear_vsc_rows(db, table="shortcut_items", case_id=case_id, image_id=image_id, snapshot_ids=snapshot_ids)
        snapshot_results: list[dict[str, Any]] = []
        failures: list[dict[str, Any]] = []
        all_rows: list[dict[str, Any]] = []
        for snapshot in snapshots:
            snapshot_index = int(snapshot["index"])
            snapshot_id = f"vss{snapshot_index}"
            step_started_at = utc_now()
            try:
                vss_path = paths.vshadow_mount_dir(case_id) / snapshot_id
                if not vss_path.exists():
                    raise MountError(f"VSC path not exposed: {vss_path}")
                extracted = extract_vsc_shortcut_artifacts(
                    paths=paths,
                    case_id=case_id,
                    snapshot_id=snapshot_id,
                    vss_path=vss_path,
                )
                rows = parse_vsc_shortcuts(
                    paths=paths,
                    case_id=case_id,
                    image_id=image_id,
                    computer_id=computer_id or "vsc",
                    snapshot_id=snapshot_id,
                    snapshot_index=snapshot_index,
                    snapshot_created_utc=str(snapshot.get("created_utc") or ""),
                    extracted_dir=extracted["destination"],
                    output_dir=paths.vsc_work_dir(case_id) / "outputs" / snapshot_id / "shortcuts",
                    lecmd=lecmd,
                    jlecmd=jlecmd,
                    dotnet=dotnet,
                )
                _insert_shortcut_rows(conn, rows)
                all_rows.extend(rows)
                snapshot_results.append(
                    {
                        "snapshot_id": snapshot_id,
                        "snapshot_index": snapshot_index,
                        "snapshot_created_utc": snapshot.get("created_utc") or "",
                        "extracted_lnk_count": extracted["lnk_count"],
                        "extracted_jumplist_count": extracted["jumplist_count"],
                        "parsed_rows": len(rows),
                        "started_at": step_started_at,
                        "ended_at": utc_now(),
                    }
                )
            except Exception as exc:
                failures.append(
                    {
                        "snapshot_id": snapshot_id,
                        "snapshot_index": snapshot_index,
                        "snapshot_created_utc": snapshot.get("created_utc") or "",
                        "error": str(exc),
                        "started_at": step_started_at,
                        "ended_at": utc_now(),
                    }
                )

        if db is not None:
            promote_deduped_rows(
                db,
                table="shortcut_items",
                rows=[add_vsc_provenance(row, source_csv=f"vsc://{row.get('snapshot_id')}/{row.get('tool_name') or 'Shortcuts'}") for row in all_rows],
                key_func=shortcut_record_signature,
            )
        live_signatures = _live_shortcut_signatures(paths=paths, case_id=case_id)
        snapshot_rows = _snapshot_rows(conn, case_id=case_id, image_id=image_id)
        comparison = compare_shortcut_snapshots(live_signatures=live_signatures, snapshot_rows=snapshot_rows)
        ended_at = utc_now()
        report_path = paths.vsc_reports_dir(case_id) / "shortcuts-vsc-comparison.md"
        report_path.write_text(
            _shortcut_comparison_markdown(
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
            "image_id": image_id,
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
        _write_json(paths.vsc_work_dir(case_id) / "shortcuts-scan.json", payload)
        return payload
    finally:
        conn.close()


def extract_vsc_shortcut_artifacts(
    *,
    paths: WorkspacePaths,
    case_id: str,
    snapshot_id: str,
    vss_path: Path,
) -> dict[str, Any]:
    destination = paths.vsc_snapshot_extract_dir(case_id, snapshot_id) / "Shortcuts"
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True, exist_ok=True)
    result = _run_command(
        ["fls", "-r", "-p", str(vss_path)],
        paths.vsc_work_dir(case_id) / "jobs" / f"shortcut-fls-{snapshot_id}",
    )
    if result["exit_code"] != 0:
        raise MountError(f"VSC shortcut fls failed; see {result['stderr_path']}")
    lnk_count = 0
    jumplist_count = 0
    manifest_files: list[dict[str, str]] = []
    stdout = Path(result["stdout_path"]).read_text(encoding="utf-8", errors="replace")
    for entry in _parse_fls_entries(stdout):
        artifact_type = _shortcut_artifact_type(entry["path"])
        if artifact_type is None:
            continue
        target = destination / entry["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        icat = _run_command(
            ["icat", str(vss_path), entry["inode"]],
            paths.vsc_work_dir(case_id) / "jobs" / f"shortcut-icat-{snapshot_id}-{hashlib.md5(entry['path'].encode()).hexdigest()[:12]}",
        )
        if icat["exit_code"] != 0:
            continue
        shutil.copy2(icat["stdout_path"], target)
        manifest_files.append({"source_path": entry["path"], "inode": entry["inode"], "artifact_type": artifact_type})
        if artifact_type == "lnk":
            lnk_count += 1
        else:
            jumplist_count += 1
    manifest = {
        "snapshot_id": snapshot_id,
        "lnk_count": lnk_count,
        "jumplist_count": jumplist_count,
        "files": manifest_files,
        "created_at": utc_now(),
    }
    _write_json(destination / "manifest.json", manifest)
    return {"destination": destination, **manifest}


def parse_vsc_shortcuts(
    *,
    paths: WorkspacePaths,
    case_id: str,
    image_id: str,
    computer_id: str,
    snapshot_id: str,
    snapshot_index: int,
    snapshot_created_utc: str,
    extracted_dir: Path,
    output_dir: Path,
    lecmd: Path,
    jlecmd: Path,
    dotnet: Path,
) -> list[dict[str, Any]]:
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    lnk_dir = extracted_dir
    if any(lnk_dir.rglob("*.lnk")):
        lecmd_out = output_dir / "LECmd"
        lecmd_out.mkdir(parents=True, exist_ok=True)
        _run_command([str(dotnet), str(lecmd), "-d", str(lnk_dir), "--csv", str(lecmd_out)], output_dir / "jobs" / "LECmd")
        rows.extend(
            _normalized_rows_from_csvs(
                paths=paths,
                case_id=case_id,
                image_id=image_id,
                computer_id=computer_id,
                snapshot_id=snapshot_id,
                snapshot_index=snapshot_index,
                snapshot_created_utc=snapshot_created_utc,
                tool_name="LECmd",
                csv_paths=sorted(lecmd_out.glob("*.csv")),
            )
        )
    if any(extracted_dir.rglob("*.automaticDestinations-ms")) or any(extracted_dir.rglob("*.customDestinations-ms")):
        jlecmd_out = output_dir / "JLECmd"
        jlecmd_out.mkdir(parents=True, exist_ok=True)
        _run_command([str(dotnet), str(jlecmd), "-d", str(extracted_dir), "--csv", str(jlecmd_out)], output_dir / "jobs" / "JLECmd")
        rows.extend(
            _normalized_rows_from_csvs(
                paths=paths,
                case_id=case_id,
                image_id=image_id,
                computer_id=computer_id,
                snapshot_id=snapshot_id,
                snapshot_index=snapshot_index,
                snapshot_created_utc=snapshot_created_utc,
                tool_name="JLECmd",
                csv_paths=sorted(jlecmd_out.glob("*.csv")),
            )
        )
    return rows


def compare_shortcut_snapshots(*, live_signatures: set[str], snapshot_rows: list[dict[str, Any]]) -> dict[str, Any]:
    unique: dict[str, dict[str, Any]] = {}
    by_snapshot: dict[str, dict[str, Any]] = {}
    for row in snapshot_rows:
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
        signature = shortcut_record_signature(row)
        if signature and not _shortcut_comparison_candidate(row):
            signature = ""
        if signature and signature not in live_signatures:
            summary["unique_not_live_count"] += 1
            unique.setdefault(signature, row)
    artifact_counts: dict[str, int] = {}
    for row in unique.values():
        artifact = row.get("artifact_type") or "unknown"
        artifact_counts[artifact] = artifact_counts.get(artifact, 0) + 1
    return {
        "summary": {
            "vsc_shortcut_rows": len(snapshot_rows),
            "unique_vsc_shortcut_records_not_live": len(unique),
            "artifact_count": len(artifact_counts),
        },
        "snapshots": sorted(by_snapshot.values(), key=lambda item: int(item["snapshot_index"])),
        "artifact_counts": dict(sorted(artifact_counts.items(), key=lambda item: (-item[1], item[0]))),
        "examples": _balanced_examples(unique.values(), per_artifact=25, total=100),
    }


def shortcut_record_signature(row: dict[str, Any]) -> str:
    artifact_type = _comparison_text(row.get("artifact_type"), case_insensitive=True)
    parts = [
        artifact_type,
        _comparison_text(row.get("file_location"), path_aware=True, case_insensitive=True),
        _comparison_text(row.get("file_name"), path_aware=True, case_insensitive=True),
        _comparison_text(row.get("target_created")),
        _comparison_text(row.get("target_modified")),
        _comparison_text(row.get("target_accessed")),
        _comparison_text(row.get("app_id"), case_insensitive=True),
        _comparison_text(row.get("command_line_arguments"), path_aware=True, case_insensitive=True),
    ]
    return "\x1f".join(value or "" for value in parts)


def _shortcut_comparison_candidate(row: dict[str, Any]) -> bool:
    target = _comparison_text(row.get("file_location"), path_aware=True, case_insensitive=True)
    command = _comparison_text(row.get("command_line_arguments"), path_aware=True, case_insensitive=True)
    if not target and not command:
        return False
    target_text = target or command
    if target_text.startswith("::{"):
        return False
    if "controlpanelhome" in target_text:
        return False
    return True


def _normalized_rows_from_csvs(
    *,
    paths: WorkspacePaths,
    case_id: str,
    image_id: str,
    computer_id: str,
    snapshot_id: str,
    snapshot_index: int,
    snapshot_created_utc: str,
    tool_name: str,
    csv_paths: list[Path],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for csv_path in csv_paths:
        with csv_path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
            reader = csv.DictReader(line for line in handle if not line.startswith("#"))
            for row_number, row in enumerate(reader, start=1):
                for normalized in normalized_shortcut_rows(
                    case_id=case_id,
                    computer_id=computer_id,
                    image_id=image_id,
                    tool_output_id=f"{snapshot_id}-{tool_name}",
                    tool_name=tool_name,
                    source_csv=csv_path,
                    row_number=row_number,
                    row=dict(row),
                ):
                    normalized["case_id"] = case_id
                    normalized["image_id"] = image_id
                    normalized["snapshot_id"] = snapshot_id
                    normalized["snapshot_index"] = snapshot_index
                    normalized["snapshot_created_utc"] = snapshot_created_utc
                    normalized["source_vsc_path"] = _source_vsc_path(normalized.get("artifact_path"))
                    normalized["artifact_path"] = _relative_to_work(paths.vsc_work_dir(case_id), Path(str(normalized.get("artifact_path") or "")))
                    normalized["record_signature"] = shortcut_record_signature(normalized)
                    normalized["parsed_at"] = utc_now()
                    rows.append(normalized)
    return rows


def _live_shortcut_signatures(*, paths: WorkspacePaths, case_id: str) -> set[str]:
    db_path = paths.analytics_db_path(case_id)
    if not db_path.exists():
        return set()
    conn = duckdb.connect(str(db_path), read_only=True)
    try:
        if "shortcut_items" not in {row[0] for row in conn.execute("SHOW TABLES").fetchall()}:
            return set()
        rows = conn.execute("SELECT * FROM shortcut_items WHERE case_id = ?", [case_id]).fetchall()
        columns = [item[0] for item in conn.description]
        return {shortcut_record_signature(dict(zip(columns, row))) for row in rows}
    finally:
        conn.close()


def _parse_fls_entries(text: str) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    for line in text.splitlines():
        match = re.match(r"^[^:]+?\s+([^:\s]+):\s+(.+)$", line)
        if not match:
            continue
        inode = match.group(1).split("-", 1)[0]
        path = match.group(2).strip()
        entries.append({"inode": inode, "path": path})
    return entries


def _dotnet_executable() -> Path:
    found = shutil.which("dotnet")
    if found:
        return Path(found)
    fallback = Path.home() / ".dotnet" / "dotnet"
    if fallback.is_file():
        return fallback
    require_dependency("dotnet")
    return Path("dotnet")


def _resolve_eztools_root() -> Path:
    candidates = [
        Path(os.environ["EZTOOLS_ROOT"]).expanduser() if os.environ.get("EZTOOLS_ROOT") else None,
        Path(os.environ["FORENSIC_ORCHESTRATOR_TOOLS_ROOT"]).expanduser() / "eztools"
        if os.environ.get("FORENSIC_ORCHESTRATOR_TOOLS_ROOT")
        else None,
        Path("/opt/relic-tools/eztools"),
        Path("/opt/eztools"),
        Path.home() / "tools" / "eztools",
    ]
    for candidate in candidates:
        if candidate and candidate.exists():
            return candidate
    return Path("/opt/relic-tools/eztools")


def _shortcut_artifact_type(path: str) -> str | None:
    lowered = path.casefold()
    if not lowered.startswith("users/"):
        return None
    if lowered.endswith(".lnk"):
        if "/start menu/" in lowered:
            return None
        return "lnk"
    if lowered.endswith(".automaticdestinations-ms") or lowered.endswith(".customdestinations-ms"):
        return "jumplist"
    return None


def _source_vsc_path(value: object) -> str:
    text = str(value or "").replace("\\", "/")
    marker = "/Shortcuts/"
    if marker in text:
        return text.split(marker, 1)[1]
    marker = "Shortcuts/"
    if marker in text:
        return text.split(marker, 1)[1]
    return text


def _ensure_shortcut_table(conn: duckdb.DuckDBPyConnection) -> None:
    column_defs = ", ".join(f"{column} VARCHAR" for column in VSC_SHORTCUT_COLUMNS)
    conn.execute(f"CREATE TABLE IF NOT EXISTS vsc_shortcut_items ({column_defs})")
    columns = {str(row[1]) for row in conn.execute("PRAGMA table_info('vsc_shortcut_items')").fetchall()}
    for column in VSC_SHORTCUT_COLUMNS:
        if column not in columns:
            conn.execute(f"ALTER TABLE vsc_shortcut_items ADD COLUMN {column} VARCHAR")


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
    conn.execute(
        f"DELETE FROM vsc_shortcut_items WHERE case_id = ? AND image_id = ? AND snapshot_id IN ({placeholders})",
        [case_id, image_id, *snapshot_ids],
    )


def _insert_shortcut_rows(conn: duckdb.DuckDBPyConnection, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    placeholders = ", ".join("?" for _ in VSC_SHORTCUT_COLUMNS)
    conn.executemany(
        f"INSERT INTO vsc_shortcut_items ({', '.join(VSC_SHORTCUT_COLUMNS)}) VALUES ({placeholders})",
        [[row.get(column) for column in VSC_SHORTCUT_COLUMNS] for row in rows],
    )


def _snapshot_rows(conn: duckdb.DuckDBPyConnection, *, case_id: str, image_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT * FROM vsc_shortcut_items
        WHERE case_id = ? AND image_id = ?
        ORDER BY snapshot_index, artifact_type, file_location, target_accessed
        """,
        [case_id, image_id],
    ).fetchall()
    columns = [item[0] for item in conn.description]
    return [dict(zip(columns, row)) for row in rows]


def _shortcut_comparison_markdown(
    comparison: dict[str, Any],
    snapshot_results: list[dict[str, Any]],
    failures: list[dict[str, Any]],
    *,
    started_at: str,
    ended_at: str,
) -> str:
    summary = comparison["summary"]
    lines = [
        "# VSC Shortcut and Jump List Comparison",
        "",
        "## Summary",
        "",
        f"- Started: {started_at}",
        f"- Ended: {ended_at}",
        f"- VSC shortcut/jump list rows parsed: {summary['vsc_shortcut_rows']}",
        f"- Unique VSC records not present live: {summary['unique_vsc_shortcut_records_not_live']}",
        f"- Artifact types with VSC-only records: {summary['artifact_count']}",
        "",
        "## Snapshot Counts",
        "",
        "| Snapshot | Created | Rows | Unique not live |",
        "| --- | --- | ---: | ---: |",
    ]
    for item in comparison["snapshots"]:
        lines.append(
            f"| {item['snapshot_id']} | {item.get('snapshot_created_utc') or ''} | "
            f"{item['row_count']} | {item['unique_not_live_count']} |"
        )
    if failures:
        lines.extend(["", "## Failures", ""])
        for failure in failures:
            lines.append(f"- `{failure['snapshot_id']}`: {failure['error']}")
    lines.extend(["", "## Artifact Counts", "", "| Artifact | Unique not live |", "| --- | ---: |"])
    for artifact, count in comparison["artifact_counts"].items():
        lines.append(f"| `{artifact}` | {count} |")
    lines.extend(
        [
            "",
            "## Examples",
            "",
            "| Artifact | Snapshot | Target | Command / URL | Created | Modified | Accessed | App | Source |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for row in comparison["examples"]:
        lines.append(
            f"| `{row.get('artifact_type') or ''}` | {row.get('snapshot_id') or ''} | "
            f"`{_md_escape(_truncate(row.get('file_location') or row.get('file_name') or '', 120))}` | "
            f"`{_md_escape(_truncate(row.get('command_line_arguments') or '', 120))}` | "
            f"{row.get('target_created') or ''} | {row.get('target_modified') or ''} | {row.get('target_accessed') or ''} | "
            f"`{_md_escape(_truncate(row.get('app_id_description') or row.get('app_id') or '', 80))}` | "
            f"`{_md_escape(_truncate(row.get('source_vsc_path') or '', 100))}` |"
        )
    lines.extend(["", "## Processing", ""])
    for result in snapshot_results:
        lines.append(
            f"- `{result['snapshot_id']}` extracted {result['extracted_lnk_count']} LNK files and "
            f"{result['extracted_jumplist_count']} Jump Lists, parsed {result['parsed_rows']} rows "
            f"from {result.get('started_at') or ''} to {result.get('ended_at') or ''}"
        )
    return "\n".join(lines) + "\n"


def _balanced_examples(rows: Any, *, per_artifact: int, total: int) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(row.get("artifact_type") or "unknown", []).append(row)
    examples: list[dict[str, Any]] = []
    for artifact in sorted(grouped):
        examples.extend(
            sorted(
                grouped[artifact],
                key=lambda row: (
                    row.get("file_location") or "",
                    row.get("target_accessed") or row.get("target_modified") or row.get("target_created") or "",
                    row.get("snapshot_index") or "",
                ),
            )[:per_artifact]
        )
    return examples[:total]


def _comparison_text(
    value: object,
    *,
    path_aware: bool = False,
    case_insensitive: bool = False,
) -> str:
    text = str(value or "").replace("\x00", "").strip()
    if not text:
        return ""
    if path_aware and _looks_path_like(text):
        text = text.replace("\\", "/")
        text = re.sub(r"/+", "/", text).rstrip("/")
        if re.match(r"^[a-z]:/", text, flags=re.IGNORECASE):
            text = text[2:]
        return text.casefold()
    return text.casefold() if case_insensitive else text


def _looks_path_like(value: str) -> bool:
    return "\\" in value or "/" in value or bool(re.match(r"^[a-z]:", value, flags=re.IGNORECASE))


def _relative_to_work(work_dir: Path, path: Path) -> str:
    try:
        return str(path.relative_to(work_dir)).replace("\\", "/")
    except ValueError:
        return str(path)


def _run_command(command: list[str], job_dir: Path) -> dict[str, Any]:
    job_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = job_dir / "stdout.bin"
    stderr_path = job_dir / "stderr.txt"
    started_at = utc_now()
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        completed = subprocess.run(command, stdout=stdout, stderr=stderr, check=False)
    return {
        "command": command,
        "started_at": started_at,
        "ended_at": utc_now(),
        "exit_code": completed.returncode,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
    }


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


def _truncate(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[: limit - 3] + "..."


def _md_escape(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")
