from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any


def normalize_timestamp(value: Any) -> str | None:
    parsed = parse_timestamp(value)
    if parsed is None:
        return None
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_timestamp(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    normalized = value.strip()
    if not normalized:
        return None
    normalized = normalized.replace(" (UTC)", "")
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    if "." in normalized:
        normalized = re.sub(r"\.(\d{6})\d+($|[+-])", r".\1\2", normalized)
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
            try:
                parsed = datetime.strptime(normalized, fmt)
                break
            except ValueError:
                continue
        else:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
