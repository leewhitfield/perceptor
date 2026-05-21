from __future__ import annotations

import uuid
from pathlib import Path

from .db import Database
from .models import Computer, EvidenceImage
from .paths import WorkspacePaths
from .safety import require_file


def create_case(db: Database, paths: WorkspacePaths) -> str:
    case_id = str(uuid.uuid4())
    paths.ensure_case_tree(case_id)
    db.create_case(case_id, paths.case_dir(case_id))
    return case_id


def create_computer(
    db: Database,
    paths: WorkspacePaths,
    case_id: str,
    label: str,
    hostname: str | None = None,
    notes: str | None = None,
) -> Computer:
    paths.ensure_case_tree(case_id)
    return db.create_computer(
        computer_id=str(uuid.uuid4()),
        case_id=case_id,
        label=label,
        hostname=hostname,
        notes=notes,
    )


def add_image(
    db: Database,
    paths: WorkspacePaths,
    case_id: str,
    image_path: Path,
    computer_id: str | None = None,
) -> EvidenceImage:
    db.get_case(case_id)
    require_file(image_path, "E01 image")
    image_id = str(uuid.uuid4())
    paths.ensure_case_tree(case_id)
    return db.add_image(image_id, case_id, image_path.resolve(), computer_id=computer_id)
