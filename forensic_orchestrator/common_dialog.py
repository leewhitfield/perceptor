from __future__ import annotations

import json
import uuid
from typing import Any

from forensic_orchestrator.db import Database
from forensic_orchestrator.pidl import parse_pidl_items


def rebuild_common_dialog_items(db: Database, *, case_id: str, image_id: str | None = None) -> int:
    where = ["case_id = ?", "artifact = 'common_dialog'", "value_type = 'REG_BINARY'", "value_name != 'MRUListEx'"]
    params: list[Any] = [case_id]
    if image_id is not None:
        where.append("image_id = ?")
        params.append(image_id)
    rows = []
    source_rows = db.conn.execute(
        f"SELECT * FROM registry_artifacts WHERE {' AND '.join(where)} ORDER BY row_number",
        params,
    ).fetchall()
    for source in source_rows:
        raw = _raw_bytes(source["value_data_hex"])
        if not raw:
            continue
        key_path = str(source["key_path"] or "")
        artifact_type = "lastvisitedpidlmru" if "lastvisitedpidlmru" in key_path.lower() else "opensavepidlmru"
        for item in parse_pidl_items(raw):
            rows.append(
                {
                    "id": str(uuid.uuid4()),
                    "case_id": source["case_id"],
                    "computer_id": source["computer_id"],
                    "image_id": source["image_id"],
                    "tool_output_id": source["tool_output_id"],
                    "source_registry_artifact_id": source["id"],
                    "source_csv": source["source_csv"],
                    "source_path": source["source_path"],
                    "hive_type": source["hive_type"],
                    "user_profile": source["user_profile"],
                    "artifact": artifact_type,
                    "key_path": source["key_path"],
                    "key_last_write_utc": source["key_last_write_utc"],
                    "mru_position": source["mru_position"],
                    "value_name": source["value_name"],
                    "item_index": item.item_index,
                    "shell_item_name": item.name,
                    "shell_created": item.created_time,
                    "shell_modified": item.modified_time,
                    "shell_accessed": item.accessed_time,
                    "raw_fat_times_json": json.dumps(item.raw_fat_times),
                }
            )
    db.replace_common_dialog_items(case_id=case_id, image_id=image_id, rows=rows)
    return len(rows)


def _raw_bytes(value: str | None) -> bytes:
    if not value:
        return b""
    try:
        return bytes.fromhex(value)
    except ValueError:
        return b""
