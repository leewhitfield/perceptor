from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class WindowsVersionFacts:
    generation: str
    edition: str
    display_version: str
    normalized_name: str
    confidence: str
    reason: str


def normalize_windows_version(
    *,
    product_name: str | None = None,
    edition_id: str | None = None,
    display_version: str | None = None,
    current_build: str | None = None,
    current_build_number: str | None = None,
) -> WindowsVersionFacts:
    build = _numeric(current_build_number or current_build)
    generation = windows_generation_from_build(build)
    edition = windows_edition_from_values(product_name=product_name, edition_id=edition_id)
    display = (display_version or "").strip()
    name_parts = [part for part in (generation, edition, display) if part]
    normalized = " ".join(name_parts) if name_parts else (product_name or "Windows legacy/unknown")
    product = product_name or ""
    confidence = "derived"
    reason = f"Derived from build {build}" if build else "Derived from registry product/display values"
    if build >= 22000 and "windows 10" in product.lower():
        reason += "; ProductName is a stale Windows 10 string seen on Windows 11 systems"
    return WindowsVersionFacts(
        generation=generation,
        edition=edition,
        display_version=display,
        normalized_name=normalized,
        confidence=confidence,
        reason=reason,
    )


def windows_generation_from_build(build: int | str | None) -> str:
    number = _numeric(build)
    if number >= 22000:
        return "Windows 11"
    if number >= 10240:
        return "Windows 10"
    if number >= 9600:
        return "Windows 8.1"
    if number >= 9200:
        return "Windows 8"
    if number >= 7600:
        return "Windows 7"
    return "Windows legacy/unknown"


def windows_edition_from_values(*, product_name: str | None = None, edition_id: str | None = None) -> str:
    edition = (edition_id or "").strip().lower()
    if edition in {"core", "corecountryspecific", "coresinglelanguage"}:
        return "Home"
    if edition == "professional":
        return "Pro"
    if edition:
        return _title_compact(edition_id or "")
    product = product_name or ""
    for candidate in ("Enterprise", "Education", "Pro", "Home"):
        if re.search(rf"\b{candidate}\b", product, flags=re.IGNORECASE):
            return candidate
    return ""


def _numeric(value: int | str | None) -> int:
    if isinstance(value, int):
        return value
    match = re.search(r"\d+", str(value or ""))
    return int(match.group(0)) if match else 0


def _title_compact(value: str) -> str:
    return re.sub(r"(?<!^)([A-Z])", r" \1", value).strip().title()
