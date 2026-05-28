from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any

from forensic_orchestrator.db import Database
from forensic_orchestrator.models import EvidenceImage, Partition
from forensic_orchestrator.safety import EncryptedImageError


ENCRYPTED_FILESYSTEM_PATTERNS = (
    ("BitLocker", re.compile(r"\b(bitlocker|bit\s*locker|fvevol|fve-fs|full volume encryption)\b", re.IGNORECASE)),
    ("VeraCrypt", re.compile(r"\bveracrypt\b", re.IGNORECASE)),
    ("TrueCrypt", re.compile(r"\btruecrypt\b", re.IGNORECASE)),
    ("Sophos SafeGuard", re.compile(r"\b(sophos\s+(safeguard|encryption)|safeguard\s+enterprise|safe\s*guard|sgn|sgm)\b", re.IGNORECASE)),
    ("LUKS", re.compile(r"\b(luks|cryptsetup)\b", re.IGNORECASE)),
    ("APFS/FileVault", re.compile(r"\b(filevault|encrypted apfs)\b", re.IGNORECASE)),
)


def build_fsstat_command(source: Path, *, offset_sectors: int | None = None) -> list[str]:
    if offset_sectors is None:
        return ["fsstat", str(source)]
    return ["fsstat", "-o", str(offset_sectors), str(source)]


def encrypted_filesystem_evidence(
    *,
    stdout: str = "",
    stderr: str = "",
    partition_description: str = "",
) -> dict[str, str] | None:
    text_parts = [
        ("fsstat_stdout", stdout or ""),
        ("fsstat_stderr", stderr or ""),
        ("partition_description", partition_description or ""),
    ]
    for source, text in text_parts:
        for encryption_type, pattern in ENCRYPTED_FILESYSTEM_PATTERNS:
            match = pattern.search(text)
            if match:
                return {
                    "encryption_type": encryption_type,
                    "match_source": source,
                    "matched_text": _snippet(text, match.start(), match.end()),
                }
    return None


def is_bitlocker_evidence(evidence: dict[str, str] | None) -> bool:
    return bool(evidence and evidence.get("encryption_type") == "BitLocker")


def assert_not_encrypted(
    *,
    db: Database,
    case_id: str,
    image: EvidenceImage,
    source_path: Path,
    source_type: str,
    partition: Partition | None = None,
    fsstat_result: subprocess.CompletedProcess[str] | None = None,
    context: str,
) -> None:
    evidence = encrypted_filesystem_evidence(
        stdout=fsstat_result.stdout if fsstat_result else "",
        stderr=fsstat_result.stderr if fsstat_result else "",
        partition_description=partition.description if partition else "",
    )
    if evidence is None:
        return
    details: dict[str, Any] = {
        **evidence,
        "source": str(source_path),
        "source_type": source_type,
        "context": context,
    }
    if partition is not None:
        details.update(
            {
                "partition_id": partition.id,
                "partition_description": partition.description,
                "offset_sectors": partition.start_sector,
                "offset_bytes": partition.offset_bytes,
            }
        )
    db.log_activity(
        case_id=case_id,
        image_id=image.id,
        computer_id=image.computer_id,
        event="image.encryption_detected",
        level="error",
        message=f"Encrypted filesystem detected ({evidence['encryption_type']}); processing stopped",
        details=details,
    )
    raise EncryptedImageError(
        f"Encrypted filesystem detected ({evidence['encryption_type']}) for image {image.id}; "
        "processing requires an unlock workflow"
    )


def log_encryption_preflight_inconclusive(
    *,
    db: Database,
    case_id: str,
    image: EvidenceImage,
    source_path: Path,
    source_type: str,
    partition: Partition,
    fsstat_result: subprocess.CompletedProcess[str],
) -> None:
    db.log_activity(
        case_id=case_id,
        image_id=image.id,
        computer_id=image.computer_id,
        event="image.encryption_preflight_inconclusive",
        level="warning",
        message="Could not confirm filesystem encryption state from fsstat; continuing with normal processing",
        details={
            "source": str(source_path),
            "source_type": source_type,
            "partition_id": partition.id,
            "partition_description": partition.description,
            "offset_sectors": partition.start_sector,
            "offset_bytes": partition.offset_bytes,
            "exit_code": fsstat_result.returncode,
            "stdout_snippet": fsstat_result.stdout[:500],
            "stderr_snippet": fsstat_result.stderr[:500],
        },
    )


def assert_image_not_previously_marked_encrypted(db: Database, *, case_id: str, image_id: str) -> None:
    row = db.conn.execute(
        """
        SELECT message, details_json
        FROM activity_log
        WHERE case_id = ? AND image_id = ? AND event = 'image.encryption_detected'
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (case_id, image_id),
    ).fetchone()
    if row is None:
        return
    unlocked = db.conn.execute(
        """
        SELECT 1
        FROM activity_log
        WHERE case_id = ? AND image_id = ? AND event = 'image.encryption_unlocked'
          AND created_at >= (
            SELECT created_at
            FROM activity_log
            WHERE case_id = ? AND image_id = ? AND event = 'image.encryption_detected'
            ORDER BY created_at DESC
            LIMIT 1
          )
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (case_id, image_id, case_id, image_id),
    ).fetchone()
    if unlocked is not None:
        return
    details = _json_dict(row["details_json"])
    encryption_type = details.get("encryption_type") or "encrypted filesystem"
    raise EncryptedImageError(
        f"Encrypted filesystem previously detected ({encryption_type}) for image {image_id}; "
        "processing requires an unlock workflow"
    )


def _json_dict(value: str) -> dict[str, Any]:
    try:
        loaded = json.loads(value or "{}")
    except (TypeError, ValueError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _snippet(text: str, start: int, end: int) -> str:
    left = max(start - 80, 0)
    right = min(end + 80, len(text))
    return re.sub(r"\s+", " ", text[left:right]).strip()
