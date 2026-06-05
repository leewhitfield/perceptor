from __future__ import annotations

import csv
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Callable


VOLATILITY_PLUGINS: tuple[str, ...] = (
    "windows.info.Info",
    "windows.pslist.PsList",
    "windows.pstree.PsTree",
    "windows.cmdline.CmdLine",
    "windows.netscan.NetScan",
    "windows.dlllist.DllList",
    "windows.handles.Handles",
    "windows.filescan.FileScan",
    "windows.malfind.Malfind",
)


CSV_COLUMNS = [
    "source_artifact_type",
    "source_path",
    "analysis_engine",
    "plugin",
    "category",
    "record_type",
    "pid",
    "ppid",
    "process_name",
    "command_line",
    "local_address",
    "local_port",
    "foreign_address",
    "foreign_port",
    "protocol",
    "state",
    "object_type",
    "object_name",
    "path",
    "module_base",
    "module_size",
    "offset",
    "virtual_address",
    "created_utc",
    "exited_utc",
    "suspicious",
    "summary",
    "raw_record_json",
]


def run_structured_memory_analysis(
    source: Path,
    output_dir: Path,
    *,
    source_artifact_type: str = "full_memory_dump",
    include_volatility: bool = True,
    include_memprocfs: bool = True,
    volatility_plugins: tuple[str, ...] = VOLATILITY_PLUGINS,
    timeout_seconds: int = 1800,
    progress: Callable[[str], None] | None = None,
) -> tuple[Path, dict[str, Any]]:
    output_dir.mkdir(parents=True, exist_ok=True)
    source = source.resolve()
    rows: list[dict[str, str]] = []
    runs: list[dict[str, Any]] = []
    if include_volatility:
        vol = _volatility_command()
        if vol:
            for plugin in volatility_plugins:
                _emit_progress(progress, f"Volatility starting {plugin}")
                run = _run_volatility_plugin(
                    vol,
                    source,
                    output_dir,
                    plugin,
                    source_artifact_type=source_artifact_type,
                    timeout_seconds=timeout_seconds,
                )
                runs.append(run["metadata"])
                rows.extend(run["rows"])
                _emit_progress(
                    progress,
                    f"Volatility finished {plugin}: {run['metadata'].get('status')} rows={run['metadata'].get('record_count', 0)}",
                )
        else:
            runs.append({"engine": "volatility3", "status": "missing", "reason": "vol launcher not found"})
    if include_memprocfs:
        memprocfs = _memprocfs_command()
        if memprocfs:
            _emit_progress(progress, "MemProcFS starting bounded inventory mount")
            run = _run_memprocfs_inventory(
                memprocfs,
                source,
                output_dir,
                source_artifact_type=source_artifact_type,
                timeout_seconds=timeout_seconds,
            )
            runs.append(run["metadata"])
            rows.extend(run["rows"])
            _emit_progress(progress, f"MemProcFS finished: {run['metadata'].get('status')} rows={run['metadata'].get('record_count', 0)}")
        else:
            runs.append({"engine": "memprocfs", "status": "missing", "reason": "memprocfs binary not found"})
    csv_path = output_dir / "StructuredMemoryAnalyzer.csv"
    _write_rows(csv_path, rows)
    return csv_path, {
        "source_path": str(source),
        "source_artifact_type": source_artifact_type,
        "source_size_bytes": str(_path_size(source)),
        "row_count": len(rows),
        "runs": runs,
    }


def _emit_progress(progress: Callable[[str], None] | None, message: str) -> None:
    if progress:
        progress(message)


def _run_volatility_plugin(
    vol: list[str],
    source: Path,
    output_dir: Path,
    plugin: str,
    *,
    source_artifact_type: str,
    timeout_seconds: int,
) -> dict[str, Any]:
    safe_plugin = plugin.replace(".", "_")
    raw_path = output_dir / f"volatility3-{safe_plugin}.json"
    stderr_path = output_dir / f"volatility3-{safe_plugin}.stderr.txt"
    command = [*vol]
    symbol_dirs = _volatility_symbol_dirs()
    if symbol_dirs:
        command.extend(["--symbol-dirs", symbol_dirs])
    command.extend(["-f", str(source), "-r", "json", plugin])
    started = time.monotonic()
    try:
        completed = subprocess.run(command, capture_output=True, text=True, errors="replace", timeout=timeout_seconds, check=False)
    except subprocess.TimeoutExpired as exc:
        stderr_path.write_text(str(exc), encoding="utf-8", errors="replace")
        return {
            "metadata": {
                "engine": "volatility3",
                "plugin": plugin,
                "status": "timeout",
                "command": command,
                "duration_seconds": round(time.monotonic() - started, 3),
                "stderr_path": str(stderr_path),
            },
            "rows": [],
        }
    raw_path.write_text(completed.stdout or "", encoding="utf-8", errors="replace")
    stderr_path.write_text(completed.stderr or "", encoding="utf-8", errors="replace")
    parsed = _load_json(completed.stdout)
    records = _volatility_records(parsed)
    rows = [
        _normalize_volatility_record(
            record,
            plugin=plugin,
            source=source,
            source_artifact_type=source_artifact_type,
        )
        for record in records
    ]
    return {
        "metadata": {
            "engine": "volatility3",
            "plugin": plugin,
            "status": "completed" if completed.returncode == 0 else "failed",
            "returncode": completed.returncode,
            "command": command,
            "raw_output_path": str(raw_path),
            "stderr_path": str(stderr_path),
            "record_count": len(rows),
            "duration_seconds": round(time.monotonic() - started, 3),
        },
        "rows": rows,
    }


def _run_memprocfs_inventory(
    memprocfs: list[str],
    source: Path,
    output_dir: Path,
    *,
    source_artifact_type: str,
    timeout_seconds: int,
) -> dict[str, Any]:
    mount_dir = output_dir / "memprocfs-mount"
    mount_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = output_dir / "memprocfs.stdout.txt"
    stderr_path = output_dir / "memprocfs.stderr.txt"
    command = [*memprocfs, "-device", str(source), "-mount", str(mount_dir), "-forensic", "1"]
    started = time.monotonic()
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace")
    except OSError as exc:
        stderr_path.write_text(str(exc), encoding="utf-8", errors="replace")
        return {
            "metadata": {"engine": "memprocfs", "status": "failed", "command": command, "stderr_path": str(stderr_path), "error": str(exc)},
            "rows": [],
        }
    rows: list[dict[str, str]] = []
    status = "started"
    error = ""
    try:
        status = _wait_for_memprocfs_views(process, mount_dir, wait_seconds=min(timeout_seconds, 120))
        if status == "mounted":
            rows.extend(_memprocfs_rows(source, mount_dir, source_artifact_type=source_artifact_type))
    except OSError as exc:
        status = "failed"
        error = str(exc)
    finally:
        try:
            process.terminate()
            stdout, stderr = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=10)
        stdout = stdout or ""
        stdout_path.write_text(stdout, encoding="utf-8", errors="replace")
        stderr_text = stderr or ""
        if error:
            stderr_text = f"{stderr_text}\n{error}".strip()
        stderr_path.write_text(stderr_text, encoding="utf-8", errors="replace")
        _best_effort_unmount(mount_dir)
    return {
        "metadata": {
            "engine": "memprocfs",
            "status": status if rows else ("completed_no_rows" if status == "mounted" else "failed"),
            "command": command,
            "mount_dir": str(mount_dir),
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
            "record_count": len(rows),
            "duration_seconds": round(time.monotonic() - started, 3),
            "timeout_seconds": timeout_seconds,
            "error": error,
            "detected_os": _memprocfs_detected_os(stdout),
            "detected_architecture": _memprocfs_detected_architecture(stdout),
            "limitation": _memprocfs_architecture_limitation(stdout),
        },
        "rows": rows,
    }


def _memprocfs_rows(source: Path, mount_dir: Path, *, source_artifact_type: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for candidate in _memprocfs_candidate_files(mount_dir):
        rel = str(candidate.relative_to(mount_dir))
        try:
            if candidate.suffix.lower() == ".csv":
                with candidate.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
                    for index, record in enumerate(csv.DictReader(handle), start=1):
                        if index > 5000:
                            break
                        rows.append(_normalize_memprocfs_record(record, source, source_artifact_type, rel))
            elif candidate.is_file():
                text = candidate.read_text(encoding="utf-8", errors="replace")[:2000]
                if text.strip():
                    rows.append(_base_row("memprocfs", "memprocfs", "inventory", source, source_artifact_type, summary=f"{rel}: {text[:200]}"))
        except OSError:
            continue
    return rows


def _memprocfs_candidate_files(mount_dir: Path) -> list[Path]:
    relative_candidates = (
        "forensic/csv/process.csv",
        "forensic/csv/processes.csv",
        "forensic/csv/net.csv",
        "forensic/csv/network.csv",
        "forensic/csv/handles.csv",
        "forensic/csv/modules.csv",
        "forensic/csv/files.csv",
        "forensic/csv/timeline.csv",
        "forensic/process.csv",
        "forensic/net.csv",
        "forensic/handles.csv",
        "forensic/modules.csv",
        "forensic/files.csv",
        "process.csv",
        "processes.csv",
        "net.csv",
        "network.csv",
        "handles.csv",
        "modules.csv",
        "files.csv",
        "timeline.csv",
    )
    output: list[Path] = []
    seen: set[Path] = set()
    for relative in relative_candidates:
        path = mount_dir / relative
        if _safe_is_file(path) and path not in seen:
            seen.add(path)
            output.append(path)
    # MemProcFS is a virtual filesystem; deep recursive walks can be very slow.
    # Only inspect one shallow level for CSVs whose names match high-value views.
    names = ("process", "net", "network", "handles", "modules", "files", "timeline")
    for directory in (mount_dir, mount_dir / "forensic", mount_dir / "forensic" / "csv"):
        if not _safe_is_dir(directory):
            continue
        try:
            for child in directory.iterdir():
                if len(output) >= 50:
                    return output
                if not _safe_is_file(child) or child.suffix.lower() != ".csv":
                    continue
                if any(name in child.name.lower() for name in names) and child not in seen:
                    seen.add(child)
                    output.append(child)
        except OSError:
            continue
    return output


def _mount_has_entries(mount_dir: Path) -> bool:
    try:
        next(mount_dir.iterdir())
        return True
    except (OSError, StopIteration):
        return False


def _wait_for_memprocfs_views(process: subprocess.Popen[str], mount_dir: Path, *, wait_seconds: int) -> str:
    deadline = time.monotonic() + max(5, wait_seconds)
    saw_mount = False
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return "started" if not saw_mount else "mounted"
        if _mount_has_entries(mount_dir):
            saw_mount = True
            if _memprocfs_candidate_files(mount_dir):
                return "mounted"
        time.sleep(2)
    return "mounted" if saw_mount else "started"


def _safe_is_file(path: Path) -> bool:
    try:
        return path.exists() and path.is_file()
    except OSError:
        return False


def _safe_is_dir(path: Path) -> bool:
    try:
        return path.exists() and path.is_dir()
    except OSError:
        return False


def _normalize_volatility_record(record: dict[str, Any], *, plugin: str, source: Path, source_artifact_type: str) -> dict[str, str]:
    category = _plugin_category(plugin)
    pid = _first(record, "PID", "Pid", "pid")
    process_name = _first(record, "ImageFileName", "Process", "Owner", "process_name", "Name")
    path = _first(record, "Path", "Name", "File output")
    command_line = _first(record, "Args", "CommandLine", "CommandLineProcess")
    local = _split_host_port(_first(record, "LocalAddr", "Local Address", "Local"))
    foreign = _split_host_port(_first(record, "ForeignAddr", "Foreign Address", "Foreign"))
    summary = _summary_for(category, process_name, command_line, path, record)
    row = _base_row("volatility3", plugin, category, source, source_artifact_type, summary=summary)
    row.update(
        {
            "record_type": category,
            "pid": str(pid or ""),
            "ppid": str(_first(record, "PPID", "InheritedFromUniqueProcessId") or ""),
            "process_name": str(process_name or ""),
            "command_line": str(command_line or ""),
            "local_address": local[0] or str(_first(record, "LocalAddr") or ""),
            "local_port": local[1] or str(_first(record, "LocalPort") or ""),
            "foreign_address": foreign[0] or str(_first(record, "ForeignAddr") or ""),
            "foreign_port": foreign[1] or str(_first(record, "ForeignPort") or ""),
            "protocol": str(_first(record, "Proto", "Protocol") or ""),
            "state": str(_first(record, "State") or ""),
            "object_type": str(_first(record, "Type", "Tag") or ""),
            "object_name": str(_first(record, "Name", "HandleName") or ""),
            "path": str(path or ""),
            "module_base": str(_first(record, "Base", "Start VPN", "Start") or ""),
            "module_size": str(_first(record, "Size") or ""),
            "offset": str(_first(record, "Offset(V)", "Offset", "Physical Offset") or ""),
            "virtual_address": str(_first(record, "Start VPN", "Address") or ""),
            "created_utc": str(_first(record, "CreateTime", "Created") or ""),
            "exited_utc": str(_first(record, "ExitTime") or ""),
            "suspicious": "true" if "malfind" in plugin.lower() else "",
            "raw_record_json": json.dumps(record, ensure_ascii=False, default=str),
        }
    )
    return row


def _normalize_memprocfs_record(record: dict[str, Any], source: Path, source_artifact_type: str, rel_path: str) -> dict[str, str]:
    category = _memprocfs_category(rel_path)
    pid = _first(record, "PID", "pid", "ProcessID")
    name = _first(record, "Name", "Process", "ImageFileName")
    path = _first(record, "Path", "FileName", "Name")
    row = _base_row("memprocfs", rel_path, category, source, source_artifact_type, summary=_summary_for(category, name, "", path, record))
    row.update(
        {
            "record_type": category,
            "pid": str(pid or ""),
            "ppid": str(_first(record, "PPID", "ppid") or ""),
            "process_name": str(name or ""),
            "command_line": str(_first(record, "CommandLine", "CmdLine", "Args") or ""),
            "path": str(path or ""),
            "object_type": str(_first(record, "Type", "ObjectType") or ""),
            "object_name": str(_first(record, "Object", "Name") or ""),
            "created_utc": str(_first(record, "CreateTime", "Created", "Time") or ""),
            "raw_record_json": json.dumps(record, ensure_ascii=False, default=str),
        }
    )
    return row


def _base_row(engine: str, plugin: str, category: str, source: Path, source_artifact_type: str, *, summary: str) -> dict[str, str]:
    return {column: "" for column in CSV_COLUMNS} | {
        "source_artifact_type": source_artifact_type,
        "source_path": str(source),
        "analysis_engine": engine,
        "plugin": plugin,
        "category": category,
        "summary": summary,
    }


def _write_rows(path: Path, rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow({column: row.get(column, "") for column in CSV_COLUMNS})


def _volatility_records(parsed: Any) -> list[dict[str, Any]]:
    if isinstance(parsed, list):
        return [row for row in parsed if isinstance(row, dict)]
    if isinstance(parsed, dict):
        for key in ("rows", "data", "treegrid"):
            value = parsed.get(key)
            if isinstance(value, list):
                return [row for row in value if isinstance(row, dict)]
        if "columns" in parsed and "rows" in parsed:
            return []
        return [parsed]
    return []


def _load_json(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _volatility_command() -> list[str] | None:
    explicit = os.environ.get("VOLATILITY3_BIN")
    candidates = [explicit] if explicit else []
    for name in ("vol", "vol.py", "volatility3"):
        found = shutil.which(name)
        if found:
            candidates.append(found)
    for candidate in candidates:
        if candidate:
            return [candidate]
    return None


def _volatility_symbol_dirs() -> str:
    candidates: list[Path] = []
    explicit = os.environ.get("VOLATILITY3_SYMBOL_DIR")
    if explicit:
        candidates.append(Path(explicit).expanduser())
    for root in (os.environ.get("FORENSIC_ORCHESTRATOR_TOOLS_ROOT"), "/opt/relic-tools", str(Path.home() / "tools")):
        if not root:
            continue
        candidates.append(Path(root) / "volatility3-symbols")
    usable = [str(path) for path in candidates if (path / "windows.zip").exists()]
    return ";".join(dict.fromkeys(usable))


def _memprocfs_command() -> list[str] | None:
    explicit = os.environ.get("MEMPROCFS_BIN")
    candidates = [explicit] if explicit else []
    for name in ("memprocfs", "MemProcFS"):
        found = shutil.which(name)
        if found:
            candidates.append(found)
    for root in (os.environ.get("FORENSIC_ORCHESTRATOR_TOOLS_ROOT"), "/opt/relic-tools", str(Path.home() / "tools")):
        if not root:
            continue
        for relative in ("MemProcFS/memprocfs", "memprocfs/memprocfs"):
            candidate = Path(root) / relative
            if candidate.exists():
                candidates.append(str(candidate))
    for candidate in candidates:
        if candidate:
            return [candidate]
    return None


def _first(record: dict[str, Any], *names: str) -> Any:
    lowered = {key.lower(): value for key, value in record.items()}
    for name in names:
        if name in record:
            return record[name]
        if name.lower() in lowered:
            return lowered[name.lower()]
    return ""


def _split_host_port(value: Any) -> tuple[str, str]:
    text = str(value or "")
    match = re.match(r"^\[?([^\]]+)\]?:(\d+)$", text)
    if match:
        return match.group(1), match.group(2)
    return text, ""


def _plugin_category(plugin: str) -> str:
    lowered = plugin.lower()
    if "pslist" in lowered or "pstree" in lowered:
        return "process"
    if "cmdline" in lowered:
        return "command_line"
    if "netscan" in lowered:
        return "network_connection"
    if "dlllist" in lowered:
        return "module"
    if "handles" in lowered:
        return "handle"
    if "filescan" in lowered:
        return "file_object"
    if "malfind" in lowered:
        return "suspicious_memory_region"
    if "info" in lowered:
        return "memory_image_info"
    return "memory_record"


def _memprocfs_category(path: str) -> str:
    lowered = path.lower()
    if "process" in lowered:
        return "process"
    if "net" in lowered:
        return "network_connection"
    if "handle" in lowered:
        return "handle"
    if "module" in lowered or "dll" in lowered:
        return "module"
    if "file" in lowered:
        return "file_object"
    if "timeline" in lowered:
        return "timeline"
    return "memprocfs_inventory"


def _summary_for(category: str, process_name: Any, command_line: Any, path: Any, record: dict[str, Any]) -> str:
    if command_line:
        return str(command_line)
    if path:
        return str(path)
    if process_name:
        return str(process_name)
    for key in ("Kernel Base", "DTB", "NtBuildLab", "Layer Name"):
        if record.get(key):
            return f"{key}: {record.get(key)}"
    return category


def _path_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _best_effort_unmount(mount_dir: Path) -> None:
    for command in (["fusermount3", "-u", str(mount_dir)], ["fusermount", "-u", str(mount_dir)], ["umount", str(mount_dir)]):
        if shutil.which(command[0]):
            subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
            break


def _memprocfs_detected_os(stdout: str) -> str:
    match = re.search(r"Operating System:\s*(.+)", stdout)
    return match.group(1).strip() if match else ""


def _memprocfs_detected_architecture(stdout: str) -> str:
    match = re.search(r"Operating System:.*\(([^)]+)\)", stdout)
    return match.group(1).strip() if match else ""


def _memprocfs_architecture_limitation(stdout: str) -> str:
    arch = _memprocfs_detected_architecture(stdout).lower()
    if "arm64" in arch:
        return "Windows ARM64 memory image detected; current Volatility Windows plugins may not construct a supported kernel layer even with symbol packs."
    return ""
