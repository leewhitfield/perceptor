from __future__ import annotations

import csv
import hashlib
import json
import shutil
import struct
import subprocess
from pathlib import Path


IMAGE_ANALYSIS_FIELDS = [
    "source_artifact_type",
    "source_artifact_id",
    "source_path",
    "output_path",
    "file_name",
    "file_extension",
    "sha256",
    "file_size",
    "width",
    "height",
    "image_format",
    "analysis_type",
    "ocr_status",
    "ocr_engine",
    "ocr_text",
    "classifier_status",
    "classifier_label",
    "details_json",
]


def analyze_image_file(
    path: Path,
    *,
    source_artifact_type: str,
    source_artifact_id: str = "",
    source_path: str = "",
    analysis_type: str = "metadata",
    ocr: bool = False,
) -> dict[str, object]:
    info = image_metadata(path)
    row: dict[str, object] = {
        "source_artifact_type": source_artifact_type,
        "source_artifact_id": source_artifact_id,
        "source_path": source_path or str(path),
        "output_path": str(path),
        "file_name": path.name,
        "file_extension": path.suffix.lower(),
        "sha256": file_sha256(path) if path.exists() and path.is_file() else "",
        "file_size": path.stat().st_size if path.exists() and path.is_file() else "",
        "width": info.get("width", ""),
        "height": info.get("height", ""),
        "image_format": info.get("format", ""),
        "analysis_type": analysis_type,
        "ocr_status": "not_requested",
        "ocr_engine": "",
        "ocr_text": "",
        "classifier_status": "not_requested",
        "classifier_label": "",
        "details_json": json.dumps({"metadata_parser": info.get("parser", ""), "error": info.get("error", "")}),
    }
    if ocr:
        row.update(_run_tesseract(path))
    return row


def image_metadata(path: Path) -> dict[str, object]:
    try:
        with path.open("rb") as handle:
            head = handle.read(64)
    except OSError as exc:
        return {"error": str(exc)}
    if head.startswith(b"\x89PNG\r\n\x1a\n") and len(head) >= 24:
        width, height = struct.unpack(">II", head[16:24])
        return {"format": "png", "width": width, "height": height, "parser": "signature"}
    if head.startswith(b"BM") and len(head) >= 26:
        width = struct.unpack("<i", head[18:22])[0]
        height = abs(struct.unpack("<i", head[22:26])[0])
        return {"format": "bmp", "width": width, "height": height, "parser": "signature"}
    if head.startswith(b"\xff\xd8\xff"):
        return _jpeg_dimensions(path)
    return {"format": _image_format_from_signature(head), "parser": "signature"}


def build_contact_sheet(
    images: list[Path],
    output_path: Path,
    *,
    columns: int = 8,
    thumb_size: tuple[int, int] = (160, 120),
) -> dict[str, object]:
    if not images:
        return {"status": "skipped", "reason": "no_images"}
    try:
        from PIL import Image, ImageDraw
    except Exception:
        return {"status": "skipped", "reason": "pillow_missing"}
    output_path.parent.mkdir(parents=True, exist_ok=True)
    rows = (len(images) + columns - 1) // columns
    cell_w, cell_h = thumb_size[0], thumb_size[1] + 22
    sheet = Image.new("RGB", (columns * cell_w, rows * cell_h), "white")
    draw = ImageDraw.Draw(sheet)
    for index, image_path in enumerate(images):
        x = (index % columns) * cell_w
        y = (index // columns) * cell_h
        try:
            with Image.open(image_path) as img:
                img.thumbnail(thumb_size)
                sheet.paste(img.convert("RGB"), (x, y))
        except Exception:
            draw.text((x + 4, y + 4), "unreadable", fill="red")
        draw.text((x + 4, y + thumb_size[1] + 4), image_path.name[:24], fill="black")
    sheet.save(output_path)
    return {"status": "created", "path": str(output_path), "image_count": len(images)}


def write_image_analysis_csv(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=IMAGE_ANALYSIS_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _image_format_from_signature(head: bytes) -> str:
    if head.startswith(b"GIF87a") or head.startswith(b"GIF89a"):
        return "gif"
    if head.startswith(b"RIFF") and head[8:12] == b"WEBP":
        return "webp"
    return ""


def _jpeg_dimensions(path: Path) -> dict[str, object]:
    try:
        data = path.read_bytes()
    except OSError as exc:
        return {"format": "jpg", "error": str(exc), "parser": "signature"}
    i = 2
    while i + 9 < len(data):
        if data[i] != 0xFF:
            i += 1
            continue
        marker = data[i + 1]
        i += 2
        if marker in {0xD8, 0xD9}:
            continue
        if i + 2 > len(data):
            break
        length = struct.unpack(">H", data[i : i + 2])[0]
        if marker in {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}:
            height, width = struct.unpack(">HH", data[i + 3 : i + 7])
            return {"format": "jpg", "width": width, "height": height, "parser": "signature"}
        i += max(length, 2)
    return {"format": "jpg", "parser": "signature"}


def _run_tesseract(path: Path) -> dict[str, object]:
    executable = shutil.which("tesseract")
    if executable is None:
        return {"ocr_status": "missing_dependency", "ocr_engine": "tesseract", "ocr_text": ""}
    result = subprocess.run(
        [executable, str(path), "stdout", "--psm", "6"],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    return {
        "ocr_status": "ok" if result.returncode == 0 else "error",
        "ocr_engine": "tesseract",
        "ocr_text": result.stdout.strip() if result.returncode == 0 else "",
    }
