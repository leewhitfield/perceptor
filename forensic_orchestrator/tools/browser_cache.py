from __future__ import annotations

import csv
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse


BROWSER_CACHE_FIELDS = [
    "browser",
    "source_path",
    "profile_path",
    "cache_type",
    "url",
    "host",
    "cache_file",
    "cache_file_size",
    "cache_file_modified_utc",
]

URL_BYTES_RE = re.compile(rb"https?://[A-Za-z0-9][^\x00-\x20\"'<>\\]{2,2048}", re.IGNORECASE)


def parse_browser_cache_artifacts_to_csv(source: Path, output: Path) -> list[Path]:
    output.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, object]] = []
    if source.exists():
        for cache_file in _candidate_cache_files(source):
            rows.extend(_cache_rows(cache_file, source))
    csv_path = output / "BrowserCacheEntries.csv"
    _write_csv(csv_path, BROWSER_CACHE_FIELDS, rows)
    return [csv_path]


def _candidate_cache_files(source: Path) -> Iterable[Path]:
    for root, dirnames, filenames in os.walk(source, onerror=lambda _exc: None):
        root_path = Path(root)
        root_lower = root_path.as_posix().lower()
        dirnames[:] = [
            name
            for name in dirnames
            if name.lower() not in {"packages", "windowsapps"}
        ]
        if not (_is_chromium_cache_path(root_lower + "/placeholder") or _is_firefox_cache_path(root_lower + "/placeholder")):
            continue
        for filename in sorted(filenames):
            path = root_path / filename
            try:
                if path.is_file():
                    yield path
            except OSError:
                continue


def _is_chromium_cache_path(path: str) -> bool:
    return any(
        token in path
        for token in (
            "/cache/",
            "/code cache/",
            "/gpucache/",
            "/media cache/",
            "/service worker/cache",
        )
    ) and any(token in path for token in ("/google/chrome/", "/microsoft/edge/", "/user data/"))


def _is_firefox_cache_path(path: str) -> bool:
    return "/mozilla/firefox/profiles/" in path and (
        "/cache2/entries/" in path or path.endswith("/cache2/index") or "/startupcache/" in path
    )


def _cache_rows(path: Path, source_root: Path) -> list[dict[str, object]]:
    urls = _urls_from_file(path)
    if not urls:
        return []
    try:
        stat = path.stat()
    except OSError:
        return []
    browser = _browser_from_path(path)
    profile = _profile_path(path, source_root, browser)
    cache_type = _cache_type_from_path(path)
    modified = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    rows = []
    for url in urls:
        host = _safe_host(url)
        if not host:
            continue
        rows.append(
            {
                "browser": browser,
                "source_path": str(path),
                "profile_path": profile,
                "cache_type": cache_type,
                "url": url,
                "host": host,
                "cache_file": path.name,
                "cache_file_size": stat.st_size,
                "cache_file_modified_utc": modified,
            }
        )
    return rows


def _urls_from_file(path: Path) -> list[str]:
    try:
        data = path.read_bytes()
    except OSError:
        return []
    urls: list[str] = []
    seen: set[str] = set()
    for match in URL_BYTES_RE.finditer(data):
        url = match.group(0).decode("utf-8", errors="replace")
        url = _clean_url(url)
        if not url or url in seen:
            continue
        seen.add(url)
        urls.append(url)
        if len(urls) >= 100:
            break
    return urls


def _clean_url(url: str) -> str | None:
    url = url.strip().strip("\x00")
    url = re.split(r"[\x00\r\n\t]", url, maxsplit=1)[0]
    url = url.rstrip("),.;]")
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return None
    return url


def _safe_host(url: str) -> str:
    try:
        return urlparse(url).netloc
    except ValueError:
        return ""


def _browser_from_path(path: Path) -> str:
    text = path.as_posix().lower()
    if "/microsoft/edge/" in text:
        return "edge"
    if "/google/chrome/" in text:
        return "chrome"
    if "/mozilla/firefox/" in text:
        return "firefox"
    return "chromium"


def _cache_type_from_path(path: Path) -> str:
    text = path.as_posix().lower()
    for name in ("code cache", "gpucache", "media cache", "service worker/cache", "cache2/entries", "startupcache"):
        if f"/{name}/" in text or text.endswith(f"/{name}"):
            return name
    if "/cache/" in text:
        return "cache"
    if text.endswith("/cache2/index"):
        return "cache2/index"
    return "cache"


def _profile_path(path: Path, source_root: Path, browser: str) -> str:
    try:
        rel = path.parent.relative_to(source_root).as_posix()
    except ValueError:
        rel = path.parent.as_posix()
    lower = rel.lower()
    if browser in {"chrome", "edge", "chromium"}:
        for marker in ("/user data/",):
            if marker in lower:
                prefix_len = lower.index(marker) + len(marker)
                remainder = rel[prefix_len:]
                return remainder.split("/", 1)[0]
    if browser == "firefox":
        marker = "/profiles/"
        if marker in lower:
            prefix_len = lower.index(marker) + len(marker)
            return rel[prefix_len:].split("/", 1)[0]
    return rel


def _write_csv(path: Path, fieldnames: list[str], rows: Iterable[dict[str, object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
