from __future__ import annotations

import base64
import csv
import hashlib
import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .rdp_cache import RDP_VISUAL_OBSERVATION_FIELDS


OPENAI_VISION_MODEL = "gpt-5.4-mini"
OPENAI_RESPONSES_URL = "https://api.openai.com/v1/responses"
OBSERVED_TEXT_LIMIT = 1000
DETAIL_TEXT_LIMIT = 500
DETAIL_LIST_LIMIT = 10
OPENAI_PRICE_USD_PER_1M = {
    "gpt-5.4-mini": {"input": 0.75, "cached_input": 0.075, "output": 4.50},
    "gpt-5-mini": {"input": 0.25, "cached_input": 0.025, "output": 2.00},
    "gpt-5-nano": {"input": 0.05, "cached_input": 0.005, "output": 0.40},
    "gpt-4.1-mini": {"input": 0.40, "cached_input": 0.10, "output": 1.60},
    "gpt-4o-mini": {"input": 0.15, "cached_input": 0.075, "output": 0.60},
}


def parse_rdp_vision_review_to_csv(_source: Path, output: Path) -> list[Path]:
    output.mkdir(parents=True, exist_ok=True)
    rdp_output = output.parent / "RdpCacheParser"
    cache_rows = _read_rows(rdp_output / "RdpCacheItems.csv")
    existing_visual_rows = _read_rows(rdp_output / "RdpVisualObservations.csv")
    tesseract_rows = _tesseract_rows_by_contact_sheet(existing_visual_rows)
    rows: list[dict[str, object]] = []
    for contact in _contact_sheet_rows(cache_rows):
        contact_sheet = Path(str(contact.get("contact_sheet_path") or ""))
        if not contact_sheet.exists():
            rows.append(_status_row(contact, "openai_vision_missing_contact_sheet", "Contact sheet file is missing."))
            continue
        api_key = os.environ.get("OPENAI_API_KEY", "").strip()
        external_ai_allowed = _truthy(os.environ.get("FORENSIC_ALLOW_EXTERNAL_AI"))
        if api_key and external_ai_allowed:
            result = _openai_contact_sheet_review(contact_sheet, api_key=api_key)
            if result.get("status") == "ok":
                rows.append(_openai_observation_row(contact, contact_sheet, result))
                continue
            rows.append(_status_row(contact, "openai_vision_error", str(result.get("error") or "OpenAI vision review failed."), result))
        fallback_reason = (
            "OPENAI_API_KEY configured but FORENSIC_ALLOW_EXTERNAL_AI is not enabled"
            if api_key and not external_ai_allowed
            else "OPENAI_API_KEY not configured"
        )
        rows.append(_tesseract_fallback_row(contact, contact_sheet, tesseract_rows.get(str(contact_sheet)), fallback_reason=fallback_reason))
    csv_path = output / "RdpVisualObservations.csv"
    _write_csv(csv_path, rows)
    return [csv_path]


def _contact_sheet_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    return [
        row for row in rows
        if row.get("record_type") == "contact_sheet" and row.get("contact_sheet_path")
    ]


def _tesseract_rows_by_contact_sheet(rows: list[dict[str, str]]) -> dict[str, dict[str, str]]:
    return {
        row["contact_sheet_path"]: row
        for row in rows
        if row.get("contact_sheet_path") and row.get("observation_type") == "contact_sheet_ocr_text"
    }


def _openai_contact_sheet_review(contact_sheet: Path, *, api_key: str) -> dict[str, Any]:
    model = os.environ.get("FORENSIC_OPENAI_VISION_MODEL", OPENAI_VISION_MODEL)
    endpoint = os.environ.get("FORENSIC_OPENAI_RESPONSES_URL", OPENAI_RESPONSES_URL)
    prompt = (
        "Review this RDP bitmap-cache contact sheet as forensic visual evidence. "
        "Return strict JSON only with keys: summary, visible_applications, visible_text, "
        "visible_paths, notable_items, confidence, caveat. Be conservative. If text or UI "
        "is fragmented, say so. Do not infer user intent beyond what is visible."
    )
    payload = {
        "model": model,
        "input": [
            {
                "role": "user",
                "content": [
                    {"type": "input_text", "text": prompt},
                    {
                        "type": "input_image",
                        "image_url": f"data:image/jpeg;base64,{_base64_file(contact_sheet)}",
                        "detail": "high",
                    },
                ],
            }
        ],
        "max_output_tokens": 1200,
    }
    request = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=int(os.environ.get("FORENSIC_OPENAI_TIMEOUT", "120"))) as response:
            body = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        return {"status": "error", "provider": "openai_api", "model": model, "error": str(exc)}
    text = _response_text(body)
    try:
        parsed = json.loads(_strip_json_fence(text))
    except json.JSONDecodeError as exc:
        return {
            "status": "error",
            "provider": "openai_api",
            "model": model,
            "response_id": body.get("id", ""),
            "usage": _openai_usage(body, model),
            "error": f"Model did not return valid JSON: {exc}",
            "raw_text": _truncate(text, OBSERVED_TEXT_LIMIT),
        }
    return {
        "status": "ok",
        "provider": "openai_api",
        "model": model,
        "response_id": body.get("id", ""),
        "usage": _openai_usage(body, model),
        "review": parsed,
    }


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().casefold() in {"1", "true", "yes", "y", "on"}


def _openai_observation_row(contact: dict[str, str], contact_sheet: Path, result: dict[str, Any]) -> dict[str, object]:
    review = result.get("review") if isinstance(result.get("review"), dict) else {}
    applications = _join_values(review.get("visible_applications"))
    visible_text = _join_values(review.get("visible_text"))
    visible_paths = _join_values(review.get("visible_paths"))
    summary = str(review.get("summary") or "")
    observed_text = _truncate(" | ".join(part for part in [summary, visible_text] if part), OBSERVED_TEXT_LIMIT)
    details = {
        "provider": result.get("provider"),
        "model": result.get("model"),
        "response_id": result.get("response_id"),
        "openai_usage": result.get("usage") if isinstance(result.get("usage"), dict) else {},
        "source_contact_sheet_sha256": _file_sha256(contact_sheet),
        "summary": _truncate(summary, DETAIL_TEXT_LIMIT),
        "notable_items": _bounded_list(review.get("notable_items")),
    }
    return {
        "user_profile": contact.get("user_profile", ""),
        "source_cache_path": contact.get("source_cache_path", ""),
        "contact_sheet_path": str(contact_sheet),
        "observation_time_utc": _mtime_or_empty(contact.get("source_cache_path", "")),
        "time_basis": "source_cache_file_mtime",
        "observation_type": "openai_vision_contact_sheet_review",
        "observed_application": applications,
        "observed_text": observed_text,
        "observed_path": visible_paths,
        "certainty": str(review.get("confidence") or "requires_review"),
        "caveat": str(review.get("caveat") or "Vision-model review of fragmented RDP bitmap-cache contact sheet; verify manually."),
        "details_json": json.dumps(details, default=str),
    }


def _tesseract_fallback_row(
    contact: dict[str, str],
    contact_sheet: Path,
    ocr_row: dict[str, str] | None,
    *,
    fallback_reason: str = "OPENAI_API_KEY not configured",
) -> dict[str, object]:
    observed_text = _truncate(str((ocr_row or {}).get("observed_text") or ""), OBSERVED_TEXT_LIMIT)
    observation_type = "tesseract_fallback_contact_sheet_ocr" if observed_text else "tesseract_fallback_no_text"
    certainty = "ocr_text_requires_review" if observed_text else "no_openai_vision_and_no_ocr_text"
    return {
        "user_profile": contact.get("user_profile", ""),
        "source_cache_path": contact.get("source_cache_path", ""),
        "contact_sheet_path": str(contact_sheet),
        "observation_time_utc": _mtime_or_empty(contact.get("source_cache_path", "")),
        "time_basis": "source_cache_file_mtime",
        "observation_type": observation_type,
        "observed_application": "",
        "observed_text": observed_text,
        "observed_path": "",
        "certainty": certainty,
        "caveat": "External AI vision was not enabled; this row falls back to Tesseract OCR and is not semantic visual interpretation.",
        "details_json": json.dumps(
            {
                "provider": "tesseract_fallback",
                "source_contact_sheet_sha256": _file_sha256(contact_sheet),
                "fallback_reason": fallback_reason,
            }
        ),
    }


def _status_row(
    contact: dict[str, str],
    status: str,
    message: str,
    details: dict[str, Any] | None = None,
) -> dict[str, object]:
    return {
        "user_profile": contact.get("user_profile", ""),
        "source_cache_path": contact.get("source_cache_path", ""),
        "contact_sheet_path": contact.get("contact_sheet_path", ""),
        "observation_time_utc": _mtime_or_empty(contact.get("source_cache_path", "")),
        "time_basis": "source_cache_file_mtime",
        "observation_type": status,
        "observed_application": "",
        "observed_text": "",
        "observed_path": "",
        "certainty": "not_reviewed",
        "caveat": message,
        "details_json": json.dumps(details or {}),
    }


def _response_text(body: dict[str, Any]) -> str:
    if isinstance(body.get("output_text"), str):
        return str(body["output_text"])
    parts: list[str] = []
    for item in body.get("output", []):
        if not isinstance(item, dict):
            continue
        for content in item.get("content", []):
            if isinstance(content, dict) and content.get("type") in {"output_text", "text"}:
                parts.append(str(content.get("text") or ""))
    return "\n".join(part for part in parts if part)


def _openai_usage(body: dict[str, Any], model: str) -> dict[str, object]:
    usage = body.get("usage") if isinstance(body.get("usage"), dict) else {}
    input_tokens = _int_value(usage.get("input_tokens") or usage.get("prompt_tokens"))
    output_tokens = _int_value(usage.get("output_tokens") or usage.get("completion_tokens"))
    total_tokens = _int_value(usage.get("total_tokens")) or input_tokens + output_tokens
    details = usage.get("input_tokens_details") if isinstance(usage.get("input_tokens_details"), dict) else {}
    cached_input_tokens = _int_value(details.get("cached_tokens") or details.get("cached_input_tokens"))
    estimated_cost = _estimate_openai_cost_usd(
        model,
        input_tokens=input_tokens,
        cached_input_tokens=cached_input_tokens,
        output_tokens=output_tokens,
    )
    return {
        "input_tokens": input_tokens,
        "cached_input_tokens": cached_input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens,
        "estimated_cost_usd": estimated_cost,
        "cost_basis": "configured_or_builtin_usd_per_1m_tokens",
    }


def _estimate_openai_cost_usd(
    model: str,
    *,
    input_tokens: int,
    cached_input_tokens: int,
    output_tokens: int,
) -> float:
    rates = _openai_rates(model)
    uncached_input_tokens = max(0, input_tokens - cached_input_tokens)
    cost = (
        (uncached_input_tokens / 1_000_000) * rates["input"]
        + (cached_input_tokens / 1_000_000) * rates["cached_input"]
        + (output_tokens / 1_000_000) * rates["output"]
    )
    return round(cost, 8)


def _openai_rates(model: str) -> dict[str, float]:
    default = OPENAI_PRICE_USD_PER_1M.get(model, {})
    return {
        "input": _float_env("FORENSIC_OPENAI_INPUT_USD_PER_1M", default.get("input", 0.0)),
        "cached_input": _float_env("FORENSIC_OPENAI_CACHED_INPUT_USD_PER_1M", default.get("cached_input", 0.0)),
        "output": _float_env("FORENSIC_OPENAI_OUTPUT_USD_PER_1M", default.get("output", 0.0)),
    }


def _int_value(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _float_env(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return float(default)


def _strip_json_fence(value: str) -> str:
    text = value.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else text
        if text.endswith("```"):
            text = text[:-3]
    return text.strip()


def _join_values(value: Any) -> str:
    if isinstance(value, list):
        return "; ".join(str(item) for item in value if str(item).strip())
    return str(value or "")


def _bounded_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [_truncate(str(item), DETAIL_TEXT_LIMIT) for item in value[:DETAIL_LIST_LIMIT] if str(item).strip()]


def _truncate(value: str, limit: int) -> str:
    text = " ".join(value.split())
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def _mtime_or_empty(value: str) -> str:
    if not value:
        return ""
    path = Path(value)
    if not path.exists():
        return ""
    from datetime import datetime, timezone

    return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).replace(tzinfo=None).isoformat(sep=" ")


def _base64_file(path: Path) -> str:
    return base64.b64encode(path.read_bytes()).decode("ascii")


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=RDP_VISUAL_OBSERVATION_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
