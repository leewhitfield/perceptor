from __future__ import annotations

import csv
import json
import struct
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .xpress_huffman import XpressHuffmanError, decompress_xpress_huffman


PREFETCH_VERSION_NAMES = {
    17: "Windows XP/2003",
    23: "Windows Vista/7",
    26: "Windows 8/8.1",
    30: "Windows 10/11",
    31: "Windows 11",
}
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
RUN_COUNT_OFFSETS = {
    17: 0x90,
    23: 0x98,
    26: 0xD0,
    30: 0xD0,
    31: 0xD0,
}
LAST_RUN_OFFSETS = {
    17: [0x78],
    23: [0x80],
    26: [0x80, 0x88, 0x90, 0x98, 0xA0, 0xA8, 0xB0, 0xB8],
    30: [0x80, 0x88, 0x90, 0x98, 0xA0, 0xA8, 0xB0, 0xB8],
    31: [0x80, 0x88, 0x90, 0x98, 0xA0, 0xA8, 0xB0, 0xB8],
}
PREFETCH_CSV_FIELDS = [
    "source_path",
    "prefetch_name",
    "executable_name",
    "signature",
    "compression",
    "prefetch_version",
    "prefetch_version_label",
    "prefetch_hash",
    "declared_file_size",
    "file_size",
    "compressed_size",
    "decompressed_size",
    "run_count",
    "last_run_time_utc",
    "last_run_times_utc",
    "referenced_string_count",
    "referenced_strings",
    "parser_note",
]


@dataclass(frozen=True)
class PrefetchInventory:
    total: int
    mam_compressed: int
    scca_uncompressed: int
    unknown: int
    versions: dict[str, int]

    @property
    def modern_compressed(self) -> bool:
        return self.mam_compressed > 0

    def as_dict(self) -> dict[str, object]:
        return {
            "total": self.total,
            "mam_compressed": self.mam_compressed,
            "scca_uncompressed": self.scca_uncompressed,
            "unknown": self.unknown,
            "versions": self.versions,
            "modern_compressed": self.modern_compressed,
        }


def prefetch_signature(path: Path) -> tuple[str, str | None]:
    try:
        header = path.read_bytes()[:8]
    except OSError:
        return ("unknown", None)
    if header.startswith(b"MAM"):
        return ("mam_compressed", "Windows 10/11 compressed")
    if len(header) >= 8 and header[4:8] == b"SCCA":
        version = int.from_bytes(header[:4], byteorder="little", signed=False)
        return ("scca_uncompressed", PREFETCH_VERSION_NAMES.get(version, f"version {version}"))
    return ("unknown", None)


def executable_name_from_prefetch(name: str) -> str:
    stem = Path(name).stem
    if "-" in stem:
        return stem.rsplit("-", 1)[0]
    return stem


def decompress_mam(data: bytes) -> bytes | None:
    if not data.startswith(b"MAM") or len(data) < 8:
        return None
    expected_size = struct.unpack_from("<I", data, 4)[0]
    if expected_size <= 0:
        return None
    try:
        return decompress_xpress_huffman(data[8:], expected_size)
    except XpressHuffmanError:
        return None


def parse_prefetch_file(path: Path) -> dict[str, object]:
    data = path.read_bytes()
    file_size = len(data)
    if data.startswith(b"MAM"):
        decompressed = decompress_mam(data)
        if decompressed is None:
            return {
                "source_path": str(path),
                "prefetch_name": path.name,
                "executable_name": executable_name_from_prefetch(path.name),
                "file_size": file_size,
                "compression": "MAM",
                "parser_note": "MAM-compressed Prefetch detected, but XPRESS-Huffman decompression failed.",
            }
        parsed = _parse_scca_bytes(decompressed, path)
        parsed.update(
            {
                "compression": "MAM",
                "compressed_size": file_size,
                "decompressed_size": len(decompressed),
                "parser_note": "Decompressed MAM Prefetch and parsed SCCA data.",
            }
        )
        return parsed
    parsed = _parse_scca_bytes(data, path)
    parsed["compression"] = "none"
    return parsed


def parse_prefetch_directory_to_csv(source: Path, output: Path) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    csv_path = output / "PrefetchParser.csv"
    rows = [parse_prefetch_file(path) for path in sorted(source.rglob("*.pf")) if path.is_file()]
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=PREFETCH_CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            serializable = {
                key: json.dumps(value) if isinstance(value, list) else value
                for key, value in row.items()
            }
            writer.writerow(serializable)
    return csv_path


def inventory_prefetch_directory(path: Path) -> PrefetchInventory:
    counts: Counter[str] = Counter()
    versions: Counter[str] = Counter()
    for pf_file in sorted(candidate for candidate in path.rglob("*.pf") if candidate.is_file()):
        kind, version = prefetch_signature(pf_file)
        counts[kind] += 1
        if version:
            versions[version] += 1
    total = sum(counts.values())
    return PrefetchInventory(
        total=total,
        mam_compressed=counts["mam_compressed"],
        scca_uncompressed=counts["scca_uncompressed"],
        unknown=counts["unknown"],
        versions=dict(sorted(versions.items())),
    )


def _parse_scca_bytes(data: bytes, path: Path) -> dict[str, object]:
    if len(data) < 0x80 or data[4:8] != b"SCCA":
        return {
            "source_path": str(path),
            "prefetch_name": path.name,
            "executable_name": executable_name_from_prefetch(path.name),
            "signature": data[4:8].decode("ascii", errors="replace") if len(data) >= 8 else None,
            "file_size": len(data),
            "parser_note": "File does not look like an uncompressed SCCA Prefetch file; filename metadata only.",
        }

    version = _u32(data, 0)
    executable_name = _utf16_string(data[16:76]) or executable_name_from_prefetch(path.name)
    prefetch_hash = _u32(data, 76)
    declared_file_size = _u32(data, 12)
    last_run_times = [_filetime_to_iso(_u64(data, offset)) for offset in LAST_RUN_OFFSETS.get(version, [])]
    last_run_times = [value for value in last_run_times if value]
    run_count_offset = RUN_COUNT_OFFSETS.get(version)
    run_count = _u32(data, run_count_offset) if run_count_offset is not None else None
    referenced_strings = _extract_utf16_strings(data)

    return {
        "source_path": str(path),
        "prefetch_name": path.name,
        "executable_name": executable_name,
        "signature": "SCCA",
        "prefetch_version": version,
        "prefetch_version_label": PREFETCH_VERSION_NAMES.get(version, f"unknown_{version}"),
        "prefetch_hash": f"{prefetch_hash:08X}" if prefetch_hash is not None else None,
        "declared_file_size": declared_file_size,
        "file_size": len(data),
        "run_count": run_count,
        "last_run_time_utc": last_run_times[0] if last_run_times else None,
        "last_run_times_utc": last_run_times,
        "referenced_strings": referenced_strings[:200],
        "referenced_string_count": len(referenced_strings),
        "parser_note": "Parsed SCCA Prefetch header and best-effort UTF-16 referenced strings.",
    }


def _u32(data: bytes, offset: int | None) -> int | None:
    if offset is None or offset < 0 or offset + 4 > len(data):
        return None
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data: bytes, offset: int) -> int | None:
    if offset < 0 or offset + 8 > len(data):
        return None
    return struct.unpack_from("<Q", data, offset)[0]


def _filetime_to_iso(value: int | None) -> str | None:
    if not value:
        return None
    try:
        seconds, remainder = divmod(value, 10_000_000)
        dt = FILETIME_EPOCH + timedelta(seconds=seconds, microseconds=remainder // 10)
        if dt.year < 1990 or dt.year > 2100:
            return None
        return dt.isoformat().replace("+00:00", "Z")
    except (OverflowError, ValueError):
        return None


def _utf16_string(data: bytes) -> str:
    return data.decode("utf-16le", errors="ignore").split("\x00", 1)[0].strip()


def _extract_utf16_strings(data: bytes, min_chars: int = 4) -> list[str]:
    strings: list[str] = []
    current = bytearray()
    for index in range(0, len(data) - 1, 2):
        pair = data[index : index + 2]
        codepoint = int.from_bytes(pair, "little")
        if codepoint in {9, 10, 13} or 32 <= codepoint <= 0xD7FF:
            current.extend(pair)
            continue
        _append_utf16_candidate(strings, current, min_chars)
        current = bytearray()
    _append_utf16_candidate(strings, current, min_chars)
    deduped: list[str] = []
    seen: set[str] = set()
    for value in strings:
        if value not in seen:
            seen.add(value)
            deduped.append(value)
    return deduped


def _append_utf16_candidate(strings: list[str], current: bytearray, min_chars: int) -> None:
    if len(current) < min_chars * 2:
        return
    text = bytes(current).decode("utf-16le", errors="ignore").strip("\x00").strip()
    if len(text) >= min_chars and _looks_interesting(text):
        strings.append(text)


def _looks_interesting(value: str) -> bool:
    lowered = value.lower()
    return "\\" in value or "/" in value or lowered.endswith((".exe", ".dll", ".sys", ".pf"))
