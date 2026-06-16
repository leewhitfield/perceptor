from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path
from shutil import which
from typing import Any

from .db import Database, utc_now

DEFAULT_IMAGE_HASH_ALGORITHMS = ("md5", "sha1", "sha256")


def compute_file_hashes(
    path: Path,
    *,
    algorithms: tuple[str, ...] = DEFAULT_IMAGE_HASH_ALGORITHMS,
    chunk_size: int = 8 * 1024 * 1024,
) -> dict[str, Any]:
    resolved = path.resolve()
    hashers = {algorithm.lower(): hashlib.new(algorithm.lower()) for algorithm in algorithms}
    size = 0
    with resolved.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            size += len(chunk)
            for hasher in hashers.values():
                hasher.update(chunk)
    return {
        "source_path": str(resolved),
        "size_bytes": size,
        "hashes": {algorithm: hasher.hexdigest() for algorithm, hasher in hashers.items()},
    }


def image_hash_rows(path: Path, *, algorithms: tuple[str, ...] = DEFAULT_IMAGE_HASH_ALGORITHMS) -> list[dict[str, Any]]:
    computed_at = utc_now()
    try:
        result = compute_file_hashes(path, algorithms=algorithms)
    except Exception as exc:
        return [
            {
                "algorithm": algorithm,
                "digest": None,
                "size_bytes": None,
                "source_path": str(path),
                "status": "error",
                "error": str(exc),
                "computed_at": computed_at,
            }
            for algorithm in algorithms
        ]
    return [
        {
            "algorithm": algorithm,
            "digest": digest,
            "size_bytes": result["size_bytes"],
            "source_path": result["source_path"],
            "status": "computed",
            "error": None,
            "computed_at": computed_at,
        }
        for algorithm, digest in result["hashes"].items()
    ]


def record_initial_image_verification(
    db: Database,
    *,
    case_id: str,
    image_id: str,
    metadata_rows: list[dict[str, Any]],
    hash_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    image = db.get_image(image_id, case_id)
    suffix = image.path.suffix.lower()
    if suffix.startswith(".e") and suffix[2:].isdigit():
        return _record_ewf_verification(db, case_id=case_id, image_id=image_id, image_path=image.path, metadata_rows=metadata_rows)
    if suffix == ".aff4":
        return _record_aff4_verification(db, case_id=case_id, image_id=image_id, image_path=image.path)
    verification_rows = []
    verified_at = utc_now()
    for row in hash_rows:
        status = "verified" if row.get("digest") else "error"
        verification = {
            "case_id": case_id,
            "image_id": image_id,
            "algorithm": row["algorithm"],
            "expected_digest": row.get("digest"),
            "actual_digest": row.get("digest"),
            "source_path": row.get("source_path") or str(image.path),
            "size_bytes": row.get("size_bytes"),
            "status": status,
            "error": row.get("error"),
            "verified_at": verified_at,
        }
        db.record_image_verification(verification)
        verification_rows.append(verification)
    overall = "verified" if verification_rows and all(row["status"] == "verified" for row in verification_rows) else "error"
    if not verification_rows:
        overall = "missing_expected_hash"
    return {"case_id": case_id, "image_id": image_id, "status": overall, "verifications": verification_rows}


def _record_ewf_verification(
    db: Database,
    *,
    case_id: str,
    image_id: str,
    image_path: Path,
    metadata_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    verified_at = utc_now()
    internal_hashes = {
        str(row.get("key") or "").rsplit(".", 1)[-1].lower(): str(row.get("value") or "")
        for row in metadata_rows
        if str(row.get("source") or "") == "ewfinfo"
        and str(row.get("key") or "").startswith("digest_hash_information.")
        and row.get("value")
    }
    if which("ewfverify") is None:
        row = {
            "case_id": case_id,
            "image_id": image_id,
            "algorithm": "ewf",
            "expected_digest": None,
            "actual_digest": None,
            "source_path": str(image_path),
            "size_bytes": image_path.stat().st_size if image_path.exists() else None,
            "status": "unsupported",
            "error": "ewfverify is not installed.",
            "verified_at": verified_at,
        }
        db.record_image_verification(row)
        return {"case_id": case_id, "image_id": image_id, "status": "unsupported", "verifications": [row]}
    try:
        completed = subprocess.run(
            ["ewfverify", "-q", str(image_path)],
            check=False,
            capture_output=True,
            text=True,
            timeout=None,
        )
    except OSError as exc:
        completed = None
        error = str(exc)
    else:
        error = (completed.stderr or completed.stdout or "").strip()[:1000] or None
    status = "verified" if completed is not None and completed.returncode == 0 else "mismatch"
    if not internal_hashes:
        internal_hashes = {"ewf": ""}
    verification_rows = []
    for algorithm, expected_digest in internal_hashes.items():
        row = {
            "case_id": case_id,
            "image_id": image_id,
            "algorithm": algorithm,
            "expected_digest": expected_digest or None,
            "actual_digest": expected_digest if status == "verified" and expected_digest else None,
            "source_path": str(image_path),
            "size_bytes": image_path.stat().st_size if image_path.exists() else None,
            "status": status,
            "error": None if status == "verified" else error,
            "verified_at": verified_at,
        }
        db.record_image_verification(row)
        verification_rows.append(row)
    return {"case_id": case_id, "image_id": image_id, "status": status, "verifications": verification_rows}


def _record_aff4_verification(db: Database, *, case_id: str, image_id: str, image_path: Path) -> dict[str, Any]:
    verified_at = utc_now()
    tool = which("affverify")
    if tool is None:
        row = {
            "case_id": case_id,
            "image_id": image_id,
            "algorithm": "aff4",
            "expected_digest": None,
            "actual_digest": None,
            "source_path": str(image_path),
            "size_bytes": image_path.stat().st_size if image_path.exists() else None,
            "status": "unsupported",
            "error": "AFF4 verification requires affverify-compatible tooling, which is not installed.",
            "verified_at": verified_at,
        }
        db.record_image_verification(row)
        return {"case_id": case_id, "image_id": image_id, "status": "unsupported", "verifications": [row]}
    try:
        completed = subprocess.run([tool, str(image_path)], check=False, capture_output=True, text=True, timeout=None)
        status = "verified" if completed.returncode == 0 else "mismatch"
        error = None if status == "verified" else (completed.stderr or completed.stdout or "").strip()[:1000]
    except OSError as exc:
        status = "error"
        error = str(exc)
    row = {
        "case_id": case_id,
        "image_id": image_id,
        "algorithm": "aff4",
        "expected_digest": None,
        "actual_digest": None,
        "source_path": str(image_path),
        "size_bytes": image_path.stat().st_size if image_path.exists() else None,
        "status": status,
        "error": error,
        "verified_at": verified_at,
    }
    db.record_image_verification(row)
    return {"case_id": case_id, "image_id": image_id, "status": status, "verifications": [row]}


def verify_image_hashes(db: Database, *, case_id: str, image_id: str) -> dict[str, Any]:
    image = db.get_image(image_id, case_id)
    expected_rows = db.image_hashes(case_id=case_id, image_id=image_id)
    algorithms = tuple(str(row["algorithm"]) for row in expected_rows if row.get("digest"))
    verified_at = utc_now()
    verification_rows: list[dict[str, Any]] = []
    if not expected_rows:
        row = {
            "case_id": case_id,
            "image_id": image_id,
            "algorithm": "sha256",
            "expected_digest": None,
            "actual_digest": None,
            "source_path": str(image.path),
            "size_bytes": None,
            "status": "missing_expected_hash",
            "error": "No stored image hashes are available for this image.",
            "verified_at": verified_at,
        }
        db.record_image_verification(row)
        return {"case_id": case_id, "image_id": image_id, "status": row["status"], "verifications": [row]}
    if not algorithms:
        for expected in expected_rows:
            row = {
                "case_id": case_id,
                "image_id": image_id,
                "algorithm": expected["algorithm"],
                "expected_digest": expected.get("digest"),
                "actual_digest": None,
                "source_path": str(image.path),
                "size_bytes": expected.get("size_bytes"),
                "status": "missing_expected_hash",
                "error": expected.get("error") or "Stored hash row has no digest.",
                "verified_at": verified_at,
            }
            db.record_image_verification(row)
            verification_rows.append(row)
        return {"case_id": case_id, "image_id": image_id, "status": "missing_expected_hash", "verifications": verification_rows}
    try:
        actual = compute_file_hashes(image.path, algorithms=algorithms)
    except Exception as exc:
        for expected in expected_rows:
            row = {
                "case_id": case_id,
                "image_id": image_id,
                "algorithm": expected["algorithm"],
                "expected_digest": expected.get("digest"),
                "actual_digest": None,
                "source_path": str(image.path),
                "size_bytes": expected.get("size_bytes"),
                "status": "error",
                "error": str(exc),
                "verified_at": verified_at,
            }
            db.record_image_verification(row)
            verification_rows.append(row)
        return {"case_id": case_id, "image_id": image_id, "status": "error", "verifications": verification_rows}
    overall = "verified"
    for expected in expected_rows:
        algorithm = str(expected["algorithm"])
        expected_digest = str(expected.get("digest") or "")
        actual_digest = str(actual["hashes"].get(algorithm) or "")
        status = "verified" if expected_digest and actual_digest.lower() == expected_digest.lower() else "mismatch"
        if status != "verified":
            overall = status
        row = {
            "case_id": case_id,
            "image_id": image_id,
            "algorithm": algorithm,
            "expected_digest": expected_digest,
            "actual_digest": actual_digest,
            "source_path": actual["source_path"],
            "size_bytes": actual["size_bytes"],
            "status": status,
            "error": None if status == "verified" else "Stored image hash does not match current image bytes.",
            "verified_at": verified_at,
        }
        db.record_image_verification(row)
        verification_rows.append(row)
    return {"case_id": case_id, "image_id": image_id, "status": overall, "verifications": verification_rows}
