from __future__ import annotations

import zipfile
from dataclasses import dataclass
from pathlib import Path

from .db import Database
from .jobs import JobRunner
from .models import EvidenceImage
from .paths import WorkspacePaths
from .safety import MountError, require_dependency


EWF_EXTENSIONS = {".e01", ".ex01", ".l01", ".lx01"}
RAW_EXTENSIONS = {".dd", ".raw", ".img", ".001"}
VIRTUAL_DISK_EXTENSIONS = {".vhd", ".vhdx", ".vmdk"}
ZIP_EXTENSIONS = {".zip"}
REPORT_EXTENSIONS = {".csv", ".json", ".xml", ".html", ".htm", ".xlsx", ".tsv", ".txt"}


@dataclass(frozen=True)
class EvidenceCandidate:
    path: Path
    kind: str
    score: int


@dataclass(frozen=True)
class PreparedSource:
    path: Path
    source_type: str
    original_kind: str


def classify_evidence_path(path: Path) -> str:
    suffix = path.suffix.lower()
    name = path.name.lower()
    if suffix in EWF_EXTENSIONS or _looks_like_ewf_segment(name):
        return "ewf"
    if suffix in VIRTUAL_DISK_EXTENSIONS:
        return suffix.lstrip(".")
    if suffix in RAW_EXTENSIONS:
        return "raw"
    if suffix in ZIP_EXTENSIONS:
        return "zip"
    if suffix in REPORT_EXTENSIONS:
        return "report"
    if path.is_dir():
        return "directory"
    return "unknown"


def evidence_metadata_rows(path: Path) -> list[dict[str, object]]:
    kind = classify_evidence_path(path)
    rows: list[dict[str, object]] = [
        {"source": "evidence", "key": "kind", "value": kind},
        {"source": "evidence", "key": "mountable", "value": str(kind in {"ewf", "raw", "vhd", "vhdx", "vmdk", "zip"})},
    ]
    if kind in {"vhd", "vhdx", "vmdk"}:
        rows.append({"source": "evidence", "key": "preparation", "value": "qemu-img-convert-to-raw"})
    elif kind == "zip":
        rows.append({"source": "evidence", "key": "preparation", "value": "extract-and-identify"})
    elif kind == "report":
        rows.append({"source": "evidence", "key": "preparation", "value": "report-import-candidate"})
    return rows


def prepare_mount_source(
    *,
    db: Database,
    paths: WorkspacePaths,
    case_id: str,
    image: EvidenceImage,
    dry_run: bool,
) -> PreparedSource:
    kind = classify_evidence_path(image.path)
    if kind == "zip":
        candidate = _extract_zip_and_select_candidate(
            db=db,
            paths=paths,
            case_id=case_id,
            image=image,
            dry_run=dry_run,
        )
        return _prepare_candidate(
            db=db,
            paths=paths,
            case_id=case_id,
            image=image,
            candidate=candidate,
            dry_run=dry_run,
            source_prefix="zip",
        )
    return _prepare_candidate(
        db=db,
        paths=paths,
        case_id=case_id,
        image=image,
        candidate=EvidenceCandidate(image.path, kind, 0),
        dry_run=dry_run,
        source_prefix="direct",
    )


def _prepare_candidate(
    *,
    db: Database,
    paths: WorkspacePaths,
    case_id: str,
    image: EvidenceImage,
    candidate: EvidenceCandidate,
    dry_run: bool,
    source_prefix: str,
) -> PreparedSource:
    kind = candidate.kind
    if kind in {"ewf", "raw"}:
        source_type = "direct-e01" if kind == "ewf" else "direct-raw"
        if source_prefix != "direct":
            source_type = f"{source_prefix}-{source_type}"
        return PreparedSource(candidate.path, source_type, kind)
    if kind in {"vhd", "vhdx", "vmdk"}:
        raw_path = _convert_virtual_disk_to_raw(
            db=db,
            paths=paths,
            case_id=case_id,
            image=image,
            source=candidate.path,
            source_kind=kind,
            dry_run=dry_run,
        )
        return PreparedSource(raw_path, f"{source_prefix}-{kind}-qemu-raw", kind)
    if kind == "report":
        raise MountError(
            f"Evidence appears to be pre-generated report content, not a mountable disk image: {candidate.path}"
        )
    raise MountError(f"Unsupported or unrecognized mountable evidence format: {candidate.path}")


def _convert_virtual_disk_to_raw(
    *,
    db: Database,
    paths: WorkspacePaths,
    case_id: str,
    image: EvidenceImage,
    source: Path,
    source_kind: str,
    dry_run: bool,
) -> Path:
    if not dry_run:
        require_dependency("qemu-img")
    output_dir = paths.images_dir(case_id) / image.id / "prepared"
    output_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / f"{source.stem}.raw"
    if output.exists() and output.stat().st_size > 0:
        db.log_activity(
            case_id=case_id,
            image_id=image.id,
            computer_id=image.computer_id,
            event="evidence.prepared_source_reused",
            message="Using existing qemu-img raw conversion output",
            details={"source": str(source), "raw_path": str(output), "source_kind": source_kind},
        )
        return output
    command = ["qemu-img", "convert", "-O", "raw", str(source), str(output)]
    JobRunner(db).run(
        case_id=case_id,
        image_id=image.id,
        computer_id=image.computer_id,
        tool_name="qemu-img",
        command=command,
        output_folder=paths.jobs_dir(case_id) / "evidence" / "qemu-img-convert",
        dry_run=dry_run,
    )
    return output


def _extract_zip_and_select_candidate(
    *,
    db: Database,
    paths: WorkspacePaths,
    case_id: str,
    image: EvidenceImage,
    dry_run: bool,
) -> EvidenceCandidate:
    extract_dir = paths.images_dir(case_id) / image.id / "extracted"
    if dry_run:
        candidates = _discover_zip_member_candidates(image.path, extract_dir)
    else:
        extract_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(image.path) as archive:
            members = archive.infolist()
            for member in members:
                _validate_zip_member(member.filename)
                archive.extract(member, extract_dir)
        db.log_activity(
            case_id=case_id,
            image_id=image.id,
            computer_id=image.computer_id,
            event="evidence.zip_extracted",
            message="Extracted ZIP evidence into case storage",
            details={"source": str(image.path), "extract_dir": str(extract_dir), "member_count": len(members)},
        )
        candidates = _discover_candidates(extract_dir)
    if not candidates:
        raise MountError(f"ZIP evidence did not contain a recognized disk image or report candidate: {image.path}")
    best = sorted(candidates, key=lambda item: (-item.score, str(item.path).lower()))[0]
    db.log_activity(
        case_id=case_id,
        image_id=image.id,
        computer_id=image.computer_id,
        event="evidence.zip_candidate_selected",
        message=f"Selected {best.kind} candidate from ZIP evidence",
        details={"candidate": str(best.path), "kind": best.kind, "score": best.score},
    )
    return best


def _discover_zip_member_candidates(zip_path: Path, extract_dir: Path) -> list[EvidenceCandidate]:
    candidates: list[EvidenceCandidate] = []
    with zipfile.ZipFile(zip_path) as archive:
        for member in archive.infolist():
            _validate_zip_member(member.filename)
            if member.is_dir():
                continue
            candidate_path = extract_dir / member.filename
            kind = classify_evidence_path(candidate_path)
            score = _candidate_score(kind)
            if score <= 0:
                continue
            if kind == "ewf" and not _is_first_ewf_segment(candidate_path):
                continue
            candidates.append(EvidenceCandidate(candidate_path, kind, score))
    return candidates


def _discover_candidates(root: Path) -> list[EvidenceCandidate]:
    if root.is_file():
        kind = classify_evidence_path(root)
        return [EvidenceCandidate(root, kind, _candidate_score(kind))] if _candidate_score(kind) > 0 else []
    candidates = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        kind = classify_evidence_path(path)
        score = _candidate_score(kind)
        if score > 0:
            if kind == "ewf" and not _is_first_ewf_segment(path):
                continue
            candidates.append(EvidenceCandidate(path, kind, score))
    return candidates


def _candidate_score(kind: str) -> int:
    return {
        "ewf": 100,
        "vhdx": 90,
        "vhd": 89,
        "vmdk": 88,
        "raw": 80,
        "report": 10,
    }.get(kind, 0)


def _validate_zip_member(name: str) -> None:
    path = Path(name)
    if path.is_absolute() or ".." in path.parts:
        raise MountError(f"Unsafe ZIP member path: {name}")


def _looks_like_ewf_segment(name: str) -> bool:
    return len(name) > 4 and name[-4:-2] == ".e" and name[-2:].isdigit()


def _is_first_ewf_segment(path: Path) -> bool:
    name = path.name.lower()
    return not _looks_like_ewf_segment(name) or name.endswith(".e01")
