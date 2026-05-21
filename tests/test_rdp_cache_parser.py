import csv
import os
import struct

from forensic_orchestrator.tools.image_analysis import image_metadata
from forensic_orchestrator.tools.rdp_cache import parse_rdp_cache_to_csv


def _bmp_bytes(width: int = 2, height: int = 1) -> bytes:
    row_size = ((24 * width + 31) // 32) * 4
    pixel_data_size = row_size * height
    file_size = 54 + pixel_data_size
    header = bytearray()
    header.extend(b"BM")
    header.extend(struct.pack("<IHHI", file_size, 0, 0, 54))
    header.extend(struct.pack("<IiiHHIIiiII", 40, width, height, 1, 24, 0, pixel_data_size, 0, 0, 0, 0))
    return bytes(header) + (b"\x00\x00\xff" + b"\x00" * (row_size - 3)) * height


def _rows(path):
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def test_image_metadata_reads_bmp_dimensions(tmp_path):
    image = tmp_path / "tile.bmp"
    image.write_bytes(_bmp_bytes(3, 2))

    assert image_metadata(image) == {"format": "bmp", "width": 3, "height": 2, "parser": "signature"}


def test_rdp_cache_parser_records_missing_extractor(tmp_path, monkeypatch):
    cache_dir = tmp_path / "Users" / "Devon" / "AppData" / "Local" / "Microsoft" / "Terminal Server Client" / "Cache"
    cache_dir.mkdir(parents=True)
    (cache_dir / "cache000.bin").write_bytes(b"rdp-cache")
    monkeypatch.delenv("BMC_TOOLS", raising=False)
    monkeypatch.setenv("FORENSIC_DISABLE_BMC_TOOLS_DISCOVERY", "1")
    monkeypatch.setenv("PATH", "")

    outputs = parse_rdp_cache_to_csv(tmp_path / "Users", tmp_path / "out")

    assert {path.name for path in outputs} == {"RdpCacheItems.csv", "ImageAnalysisItems.csv", "RdpVisualObservations.csv"}
    rows = _rows(tmp_path / "out" / "RdpCacheItems.csv")
    assert [row["record_type"] for row in rows] == ["cache_file", "extraction_status"]
    assert rows[0]["user_profile"] == "Devon"
    assert rows[1]["parser_status"] == "bmc_tools_missing"


def test_rdp_cache_parser_uses_bmc_tools_and_writes_image_analysis(tmp_path, monkeypatch):
    cache_dir = tmp_path / "Users" / "Jean" / "AppData" / "Local" / "Microsoft" / "Terminal Server Client" / "Cache"
    cache_dir.mkdir(parents=True)
    (cache_dir / "cache000.bin").write_bytes(b"rdp-cache")
    fake_bmc = tmp_path / "fake_bmc_tools.py"
    fake_bmc.write_text(
        "import sys\n"
        "from pathlib import Path\n"
        "args=sys.argv\n"
        f"Path({str(tmp_path / 'bmc-src.txt')!r}).write_text(args[args.index('-s')+1], encoding='utf-8')\n"
        "out=Path(args[args.index('-d')+1])\n"
        "out.mkdir(parents=True, exist_ok=True)\n"
        f"(out/'tile001.bmp').write_bytes({repr(_bmp_bytes(2, 1))})\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("BMC_TOOLS", os.fspath(fake_bmc))
    monkeypatch.setenv("PATH", os.fspath(tmp_path / "no-tesseract"))

    parse_rdp_cache_to_csv(tmp_path / "Users", tmp_path / "out")

    rdp_rows = _rows(tmp_path / "out" / "RdpCacheItems.csv")
    image_rows = _rows(tmp_path / "out" / "ImageAnalysisItems.csv")
    visual_rows = _rows(tmp_path / "out" / "RdpVisualObservations.csv")
    assert any(row["record_type"] == "fragment" and row["width"] == "2" for row in rdp_rows)
    assert (tmp_path / "bmc-src.txt").read_text(encoding="utf-8") == str(cache_dir / "cache000.bin")
    assert image_rows[0]["source_artifact_type"] == "rdp_bitmap_cache"
    assert image_rows[0]["analysis_type"] == "rdp_fragment_metadata"
    assert image_rows[0]["image_format"] == "bmp"
    assert [row["observation_type"] for row in visual_rows] == [
        "contact_sheet_available",
        "contact_sheet_ocr_missing_dependency",
    ]
    assert visual_rows[0]["certainty"] == "visual_material_available_not_semantic_interpretation"
    assert visual_rows[0]["contact_sheet_path"].endswith("Jean_cache000.jpg")
    assert visual_rows[1]["certainty"] == "ocr_not_performed"


def test_rdp_cache_parser_skips_zero_byte_cache_files(tmp_path, monkeypatch):
    cache_dir = tmp_path / "Users" / "Jean" / "AppData" / "Local" / "Microsoft" / "Terminal Server Client" / "Cache"
    cache_dir.mkdir(parents=True)
    (cache_dir / "bcache24.bmc").write_bytes(b"")
    fake_bmc = tmp_path / "fake_bmc_tools.py"
    fake_bmc.write_text(
        "raise SystemExit('bmc-tools should not be called for empty cache files')\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("BMC_TOOLS", os.fspath(fake_bmc))

    parse_rdp_cache_to_csv(tmp_path / "Users", tmp_path / "out")

    rdp_rows = _rows(tmp_path / "out" / "RdpCacheItems.csv")
    visual_rows = _rows(tmp_path / "out" / "RdpVisualObservations.csv")
    assert [row["record_type"] for row in rdp_rows] == ["cache_file", "extraction_status"]
    assert rdp_rows[0]["file_name"] == "bcache24.bmc"
    assert rdp_rows[0]["file_size"] == "0"
    assert rdp_rows[1]["parser_status"] == "empty_cache_file"
    assert visual_rows == []


def test_rdp_cache_parser_records_contact_sheet_ocr_text(tmp_path, monkeypatch):
    cache_dir = tmp_path / "Users" / "Jean" / "AppData" / "Local" / "Microsoft" / "Terminal Server Client" / "Cache"
    cache_dir.mkdir(parents=True)
    (cache_dir / "cache000.bin").write_bytes(b"rdp-cache")
    fake_bmc = tmp_path / "fake_bmc_tools.py"
    fake_bmc.write_text(
        "import sys\n"
        "from pathlib import Path\n"
        "args=sys.argv\n"
        "out=Path(args[args.index('-d')+1])\n"
        "out.mkdir(parents=True, exist_ok=True)\n"
        f"(out/'tile001.bmp').write_bytes({repr(_bmp_bytes(2, 1))})\n",
        encoding="utf-8",
    )
    fake_tesseract = tmp_path / "tesseract"
    fake_tesseract.write_text("#!/bin/sh\nprintf 'File Explorer\\nC:\\\\Users\\\\Jean\\\\Documents\\n'\n", encoding="utf-8")
    fake_tesseract.chmod(0o755)
    monkeypatch.setenv("BMC_TOOLS", os.fspath(fake_bmc))
    monkeypatch.setenv("PATH", os.fspath(tmp_path))

    parse_rdp_cache_to_csv(tmp_path / "Users", tmp_path / "out")

    visual_rows = _rows(tmp_path / "out" / "RdpVisualObservations.csv")
    ocr_row = next(row for row in visual_rows if row["observation_type"] == "contact_sheet_ocr_text")
    assert ocr_row["observed_text"] == "File Explorer C:\\Users\\Jean\\Documents"
    assert ocr_row["certainty"] == "ocr_text_from_contact_sheet_requires_review"
