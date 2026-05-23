from __future__ import annotations

import json
from typing import Any, Callable

from forensic_orchestrator.db import Database, utc_now
from forensic_orchestrator.models import EvidenceImage
from forensic_orchestrator.paths import WorkspacePaths
from forensic_orchestrator.safety import MountError

from .vsc_appcompat import run_vsc_appcompat_scan
from .vsc_browser import run_vsc_browser_scan
from .vsc_evtx import run_vsc_evtx_triage_scan
from .vsc_ntfs import run_vsc_ntfs_delta_scan
from .vsc_prefetch import run_vsc_prefetch_scan
from .vsc_recycle import run_vsc_recycle_scan
from .vsc_registry import run_vsc_registry_scan
from .vsc_search import run_vsc_windows_search_scan
from .vsc_shortcuts import run_vsc_shortcut_scan
from .vsc_srum import run_vsc_srum_scan


VSC_PROFILES: dict[str, list[str]] = {
    "history": [
        "prefetch",
        "registry",
        "shortcuts",
        "browser",
        "appcompat",
        "srum",
        "evtx",
        "recycle",
        "windows-search",
    ],
    "ntfs": ["ntfs"],
    "all": [
        "prefetch",
        "registry",
        "shortcuts",
        "browser",
        "appcompat",
        "srum",
        "evtx",
        "recycle",
        "windows-search",
        "ntfs",
    ],
}

SCAN_FUNCTIONS: dict[str, Callable[..., dict[str, Any]]] = {
    "prefetch": run_vsc_prefetch_scan,
    "registry": run_vsc_registry_scan,
    "shortcuts": run_vsc_shortcut_scan,
    "browser": run_vsc_browser_scan,
    "appcompat": run_vsc_appcompat_scan,
    "srum": run_vsc_srum_scan,
    "evtx": run_vsc_evtx_triage_scan,
    "recycle": run_vsc_recycle_scan,
    "windows-search": run_vsc_windows_search_scan,
    "ntfs": run_vsc_ntfs_delta_scan,
}


def run_vsc_profile_scan(
    *,
    db: Database,
    paths: WorkspacePaths,
    case_id: str,
    image: EvidenceImage,
    profile: str,
    snapshot_indexes: list[int] | None = None,
    use_sudo_mount: bool = False,
    continue_on_error: bool = True,
) -> dict[str, Any]:
    if profile not in VSC_PROFILES:
        raise MountError(f"Unknown VSC profile: {profile}")
    paths.ensure_case_tree(case_id)
    started_at = utc_now()
    results: dict[str, Any] = {}
    failures: list[dict[str, str]] = []
    for scan_name in VSC_PROFILES[profile]:
        step_started_at = utc_now()
        try:
            if scan_name == "shortcuts":
                results[scan_name] = run_vsc_shortcut_scan(
                    db=db,
                    paths=paths,
                    case_id=case_id,
                    image_id=image.id,
                    computer_id=image.computer_id,
                    snapshot_indexes=snapshot_indexes,
                )
            else:
                results[scan_name] = SCAN_FUNCTIONS[scan_name](
                    db=db,
                    paths=paths,
                    case_id=case_id,
                    image=image,
                    snapshot_indexes=snapshot_indexes,
                    use_sudo_mount=use_sudo_mount,
                )
        except Exception as exc:
            failure = {
                "scan": scan_name,
                "started_at": step_started_at,
                "ended_at": utc_now(),
                "error": str(exc),
            }
            failures.append(failure)
            if not continue_on_error:
                break
    ended_at = utc_now()
    payload = {
        "case_id": case_id,
        "image_id": image.id,
        "profile": profile,
        "scans": VSC_PROFILES[profile],
        "started_at": started_at,
        "ended_at": ended_at,
        "successful_scans": len(results),
        "failed_scans": len(failures),
        "results": results,
        "failures": failures,
    }
    path = paths.vsc_work_dir(case_id) / f"profile-{profile}-scan.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    payload["profile_path"] = str(path)
    return payload
