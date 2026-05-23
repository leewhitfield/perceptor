from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from forensic_orchestrator.db import Database, utc_now
from forensic_orchestrator.models import EvidenceImage, Partition
from forensic_orchestrator.paths import WorkspacePaths
from forensic_orchestrator.safety import MountError, require_dependency

from .volume_mount import build_ntfs_mount_command, build_umount_command, validate_mount_available


@dataclass(frozen=True)
class VscSnapshot:
    index: int
    snapshot_id: str
    identifier: str = ""
    shadow_copy_set_id: str = ""
    created_utc: str = ""


def build_vshadowinfo_command(raw_image: Path, *, offset_bytes: int = 0) -> list[str]:
    command = ["vshadowinfo"]
    if offset_bytes:
        command.extend(["-o", str(offset_bytes)])
    command.append(str(raw_image))
    return command


def build_vshadowmount_command(raw_image: Path, mount_dir: Path, *, offset_bytes: int = 0, allow_other: bool = True) -> list[str]:
    command = ["vshadowmount"]
    if offset_bytes:
        command.extend(["-o", str(offset_bytes)])
    if allow_other:
        command.extend(["-X", "allow_other"])
    command.extend([str(raw_image), str(mount_dir)])
    return command


def parse_vshadowinfo_output(text: str) -> list[VscSnapshot]:
    snapshots: list[VscSnapshot] = []
    current: dict[str, str] | None = None
    for line in text.splitlines():
        stripped = line.strip()
        store = re.match(r"(?i)^(?:Store|Shadow copy)\s*:?\s*(\d+)", stripped)
        if store:
            if current:
                snapshots.append(_snapshot_from_mapping(current))
            current = {"index": store.group(1)}
            continue
        if current is None:
            continue
        key_value = re.match(r"^([^:]+):\s*(.*)$", stripped)
        if not key_value:
            continue
        key = key_value.group(1).strip().lower()
        value = key_value.group(2).strip()
        if key in {"identifier", "shadow copy identifier", "shadow copy id"}:
            current["identifier"] = value
        elif key in {"shadow copy set id", "set id"}:
            current["shadow_copy_set_id"] = value
        elif key in {"creation time", "created", "creation date and time"}:
            current["created_utc"] = value
    if current:
        snapshots.append(_snapshot_from_mapping(current))
    return snapshots


def discover_vsc_snapshots(
    *,
    db: Database,
    paths: WorkspacePaths,
    case_id: str,
    image: EvidenceImage,
) -> dict[str, Any]:
    source = _latest_source_context(db, case_id=case_id, image=image)
    require_dependency("vshadowinfo")
    work_dir = paths.vsc_work_dir(case_id)
    result = _run_sidecar_command(
        build_vshadowinfo_command(source["raw_path"], offset_bytes=source["offset_bytes"]),
        work_dir / "jobs" / "vshadowinfo",
    )
    if result["exit_code"] != 0:
        raise MountError(f"vshadowinfo failed; see {result['stderr_path']}")
    snapshots = parse_vshadowinfo_output(Path(result["stdout_path"]).read_text(encoding="utf-8", errors="replace"))
    payload = {
        "case_id": case_id,
        "image_id": image.id,
        "source": _jsonable_source(source),
        "snapshot_count": len(snapshots),
        "snapshots": [asdict(snapshot) for snapshot in snapshots],
        "created_at": utc_now(),
        "job": result,
    }
    _write_json(work_dir / "inventory.json", payload)
    return payload


def mount_vsc_snapshot(
    *,
    db: Database,
    paths: WorkspacePaths,
    case_id: str,
    image: EvidenceImage,
    snapshot_index: int,
    use_sudo_mount: bool = False,
) -> dict[str, Any]:
    source = _latest_source_context(db, case_id=case_id, image=image)
    require_dependency("vshadowmount")
    validate_mount_available()
    if use_sudo_mount:
        require_dependency("sudo")
    work_dir = paths.vsc_work_dir(case_id)
    vshadow_dir = paths.vshadow_mount_dir(case_id)
    vshadow_dir.mkdir(parents=True, exist_ok=True)
    if not _is_mount(vshadow_dir):
        result = _run_sidecar_command(
            build_vshadowmount_command(source["raw_path"], vshadow_dir, offset_bytes=source["offset_bytes"]),
            work_dir / "jobs" / "vshadowmount",
        )
        if result["exit_code"] != 0:
            raise MountError(f"vshadowmount failed; see {result['stderr_path']}")
    vss_path = vshadow_dir / f"vss{snapshot_index}"
    if not vss_path.exists():
        raise MountError(f"vshadowmount did not expose expected snapshot path: {vss_path}")
    snapshot_id = f"vss{snapshot_index}"
    mount_dir = paths.vsc_snapshot_mount_dir(case_id, snapshot_id)
    mount_dir.mkdir(parents=True, exist_ok=True)
    if not _is_mount(mount_dir):
        command = build_ntfs_mount_command(
            vss_path,
            mount_dir,
            Partition(
                id=snapshot_id,
                slot=snapshot_id,
                start_sector=0,
                end_sector=0,
                length=0,
                description="Volume Shadow Copy exposed NTFS volume",
            ),
            use_sudo=use_sudo_mount,
            norecover=True,
        )
        result = _run_sidecar_command(command, work_dir / "jobs" / f"ntfs-mount-{snapshot_id}")
        if result["exit_code"] != 0:
            raise MountError(f"VSC NTFS mount failed; see {result['stderr_path']}")
    payload = {
        "case_id": case_id,
        "image_id": image.id,
        "snapshot_index": snapshot_index,
        "snapshot_id": snapshot_id,
        "vshadow_mount_path": str(vshadow_dir),
        "vss_path": str(vss_path),
        "volume_mount_path": str(mount_dir),
        "source": _jsonable_source(source),
        "mounted_at": utc_now(),
    }
    _write_json(work_dir / "snapshots" / snapshot_id / "mount.json", payload)
    return payload


def extract_vsc_artifact(
    *,
    paths: WorkspacePaths,
    case_id: str,
    snapshot_id: str,
    relative_path: str,
) -> dict[str, Any]:
    clean_relative = relative_path.replace("\\", "/").strip("/")
    if not clean_relative or ".." in Path(clean_relative).parts:
        raise MountError(f"Unsafe VSC artifact path: {relative_path}")
    mount_dir = paths.vsc_snapshot_mount_dir(case_id, snapshot_id)
    source = mount_dir / clean_relative
    vss_path = paths.vshadow_mount_dir(case_id) / snapshot_id
    if ":" in clean_relative and vss_path.exists():
        return _extract_vsc_artifact_tsk(
            paths=paths,
            case_id=case_id,
            snapshot_id=snapshot_id,
            vss_path=vss_path,
            relative_path=clean_relative,
        )
    if not source.exists() and vss_path.exists():
        return _extract_vsc_artifact_tsk(
            paths=paths,
            case_id=case_id,
            snapshot_id=snapshot_id,
            vss_path=vss_path,
            relative_path=clean_relative,
        )
    if not source.exists():
        raise MountError(f"VSC artifact path not found: {source}")
    destination = paths.vsc_snapshot_extract_dir(case_id, snapshot_id) / clean_relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    if source.is_dir():
        if destination.exists():
            shutil.rmtree(destination)
        shutil.copytree(source, destination, symlinks=False)
    else:
        shutil.copy2(source, destination)
    manifest = _artifact_manifest(source, destination, clean_relative)
    _write_json(destination.parent / f"{destination.name}.manifest.json", manifest)
    return manifest


def _extract_vsc_artifact_tsk(
    *,
    paths: WorkspacePaths,
    case_id: str,
    snapshot_id: str,
    vss_path: Path,
    relative_path: str,
) -> dict[str, Any]:
    resolved = _resolve_tsk_path(vss_path, relative_path)
    destination = paths.vsc_snapshot_extract_dir(case_id, f"{snapshot_id}-tsk") / relative_path
    if destination.exists():
        if destination.is_dir():
            shutil.rmtree(destination)
        else:
            destination.unlink()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if resolved["kind"] == "directory":
        destination.mkdir(parents=True, exist_ok=True)
        result = _run_sidecar_command(
            ["tsk_recover", "-a", "-d", resolved["inode"], str(vss_path), str(destination)],
            paths.vsc_work_dir(case_id) / "jobs" / f"tsk-recover-{snapshot_id}-{_safe_job_name(relative_path)}",
        )
        if result["exit_code"] != 0:
            raise MountError(f"VSC TSK directory extraction failed; see {result['stderr_path']}")
    else:
        result = _run_sidecar_binary_stdout_command(
            ["icat", str(vss_path), resolved["inode"]],
            paths.vsc_work_dir(case_id) / "jobs" / f"icat-{snapshot_id}-{_safe_job_name(relative_path)}",
        )
        if result["exit_code"] != 0:
            raise MountError(f"VSC TSK file extraction failed; see {result['stderr_path']}")
        Path(result["stdout_path"]).replace(destination)
    manifest = _artifact_manifest(destination, destination, relative_path)
    manifest.update(
        {
            "source_path": str(vss_path),
            "source_method": "tsk",
            "source_inode": resolved["inode"],
            "snapshot_id": snapshot_id,
        }
    )
    _write_json(destination.parent / f"{destination.name}.manifest.json", manifest)
    return manifest


def unmount_vsc(
    *,
    paths: WorkspacePaths,
    case_id: str,
    snapshot_id: str | None = None,
    use_sudo_mount: bool = False,
) -> dict[str, Any]:
    work_dir = paths.vsc_work_dir(case_id)
    unmounted: list[dict[str, Any]] = []
    snapshot_root = work_dir / "snapshots"
    mount_dirs: list[Path] = []
    if snapshot_id:
        mount_dirs.append(paths.vsc_snapshot_mount_dir(case_id, snapshot_id))
    elif snapshot_root.exists():
        mount_dirs.extend(sorted(path / "volume" for path in snapshot_root.iterdir() if path.is_dir()))
    for mount_dir in mount_dirs:
        if _is_mount(mount_dir):
            result = _run_sidecar_command(
                build_umount_command(mount_dir, use_sudo=use_sudo_mount),
                work_dir / "jobs" / f"umount-{mount_dir.parent.name}",
            )
            unmounted.append({"mount_path": str(mount_dir), **result})
    vshadow_dir = paths.vshadow_mount_dir(case_id)
    if _is_mount(vshadow_dir):
        result = _run_sidecar_command(
            build_umount_command(vshadow_dir, use_sudo=False),
            work_dir / "jobs" / "umount-vshadow",
        )
        unmounted.append({"mount_path": str(vshadow_dir), **result})
    payload = {"case_id": case_id, "snapshot_id": snapshot_id, "unmounted": unmounted, "created_at": utc_now()}
    _write_json(work_dir / "unmount.json", payload)
    return payload


def _latest_source_context(db: Database, *, case_id: str, image: EvidenceImage) -> dict[str, Any]:
    mount_row = db.latest_mount(case_id, image.id)
    if mount_row is None:
        raise MountError(f"No prepared image recorded for case={case_id} image={image.id}; run image mount first")
    raw_path = Path(mount_row["raw_path"])
    if not raw_path.exists():
        raise MountError(f"Prepared raw image path does not exist: {raw_path}")
    return {
        "raw_path": raw_path,
        "offset_bytes": int(mount_row["offset_bytes"] or 0),
        "partition_id": mount_row["partition_id"],
        "source_type": mount_row["source_type"],
        "volume_mount_path": mount_row["volume_mount_path"],
    }


def _resolve_tsk_path(vss_path: Path, relative_path: str) -> dict[str, str]:
    inode = ""
    kind = "directory"
    for component in Path(relative_path).parts:
        entries = _fls_entries(vss_path, inode)
        match = next((entry for entry in entries if entry["name"].casefold() == component.casefold()), None)
        if match is None:
            raise MountError(f"Could not resolve VSC path component with Sleuth Kit: {component} in {relative_path}")
        inode = match["inode"]
        kind = match["kind"]
    if not inode:
        raise MountError(f"Could not resolve VSC path with Sleuth Kit: {relative_path}")
    return {"inode": inode, "kind": kind}


def _fls_entries(vss_path: Path, inode: str = "") -> list[dict[str, str]]:
    command = ["fls", str(vss_path)]
    if inode:
        command.append(inode)
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise MountError(result.stderr.strip() or f"fls failed for {vss_path} inode={inode}")
    entries: list[dict[str, str]] = []
    for line in result.stdout.splitlines():
        match = re.match(r"^([dr-])/[dr-]\s+\*?\s*([0-9]+(?:-[^:]+)?):\s+(.+)$", line.strip())
        if not match:
            continue
        type_char, entry_inode, name = match.groups()
        entries.append(
            {
                "kind": "directory" if type_char == "d" else "file",
                "inode": entry_inode.split("-", 1)[0] if type_char == "d" else entry_inode,
                "name": name,
            }
        )
    return entries


def _safe_job_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip("/\\"))[:80] or "artifact"


def _snapshot_from_mapping(values: dict[str, str]) -> VscSnapshot:
    index = int(values.get("index") or "0")
    identifier = values.get("identifier", "")
    snapshot_id = identifier.strip("{}") or f"vss{index}"
    return VscSnapshot(
        index=index,
        snapshot_id=snapshot_id,
        identifier=identifier,
        shadow_copy_set_id=values.get("shadow_copy_set_id", ""),
        created_utc=values.get("created_utc", ""),
    )


def _run_sidecar_command(command: list[str], output_dir: Path) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    started_at = utc_now()
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    ended_at = utc_now()
    stdout_path = output_dir / "stdout.txt"
    stderr_path = output_dir / "stderr.txt"
    stdout_path.write_text(result.stdout, encoding="utf-8", errors="replace")
    stderr_path.write_text(result.stderr, encoding="utf-8", errors="replace")
    payload = {
        "command": command,
        "started_at": started_at,
        "ended_at": ended_at,
        "exit_code": result.returncode,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
    }
    _write_json(output_dir / "command.json", payload)
    return payload


def _run_sidecar_binary_stdout_command(command: list[str], output_dir: Path) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    started_at = utc_now()
    stdout_path = output_dir / "stdout.bin"
    stderr_path = output_dir / "stderr.txt"
    with stdout_path.open("wb") as stdout_handle:
        result = subprocess.run(command, stdout=stdout_handle, stderr=subprocess.PIPE, check=False)
    ended_at = utc_now()
    stderr_text = (result.stderr or b"").decode("utf-8", errors="replace")
    stderr_path.write_text(stderr_text, encoding="utf-8", errors="replace")
    payload = {
        "command": command,
        "started_at": started_at,
        "ended_at": ended_at,
        "exit_code": result.returncode,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
    }
    _write_json(output_dir / "command.json", payload)
    return payload


def _artifact_manifest(source: Path, destination: Path, relative_path: str) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    roots = [source] if source.is_file() else sorted(path for path in source.rglob("*") if path.is_file())
    for path in roots:
        stat = path.stat()
        relative = path.relative_to(source.parent if source.is_file() else source)
        files.append(
            {
                "relative_path": str(relative).replace("\\", "/"),
                "size": stat.st_size,
                "modified_time_ns": stat.st_mtime_ns,
                "md5": _md5(path),
            }
        )
    return {
        "relative_path": relative_path,
        "source_path": str(source),
        "destination_path": str(destination),
        "file_count": len(files),
        "byte_count": sum(int(item["size"]) for item in files),
        "files": files,
        "created_at": utc_now(),
    }


def _md5(path: Path) -> str:
    digest = hashlib.md5(usedforsecurity=False)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


def _jsonable_source(source: dict[str, Any]) -> dict[str, Any]:
    return {key: str(value) if isinstance(value, Path) else value for key, value in source.items()}


def _is_mount(path: Path) -> bool:
    try:
        return path.exists() and path.is_mount()
    except OSError:
        return False
