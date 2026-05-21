import struct
from datetime import datetime, timezone

from forensic_orchestrator.tools.prefetch import (
    FILETIME_EPOCH,
    decompress_mam,
    inventory_prefetch_directory,
    parse_prefetch_directory_to_csv,
    parse_prefetch_file,
    prefetch_signature,
)
from forensic_orchestrator.tools.prefetch_hash_lookup import (
    load_prefetch_hash_references,
    resolve_prefetch_hash,
)
from forensic_orchestrator.tools.prefetch_items import normalized_prefetch_row


def test_prefetch_signature_detects_mam_compressed(tmp_path):
    pf_file = tmp_path / "APP.EXE-12345678.pf"
    pf_file.write_bytes(b"MAM\x04payload")

    assert prefetch_signature(pf_file) == ("mam_compressed", "Windows 10/11 compressed")


def test_prefetch_signature_detects_uncompressed_scca_version(tmp_path):
    pf_file = tmp_path / "APP.EXE-12345678.pf"
    pf_file.write_bytes((30).to_bytes(4, "little") + b"SCCA" + b"payload")

    assert prefetch_signature(pf_file) == ("scca_uncompressed", "Windows 10/11")


def test_prefetch_inventory_counts_modern_compressed_files(tmp_path):
    (tmp_path / "modern.pf").write_bytes(b"MAM\x04payload")
    (tmp_path / "old.pf").write_bytes((23).to_bytes(4, "little") + b"SCCA")
    (tmp_path / "unknown.pf").write_bytes(b"????")
    (tmp_path / "_extract_jobs" / "modern.pf").mkdir(parents=True)

    inventory = inventory_prefetch_directory(tmp_path)

    assert inventory.total == 3
    assert inventory.mam_compressed == 1
    assert inventory.scca_uncompressed == 1
    assert inventory.unknown == 1
    assert inventory.modern_compressed is True
    assert inventory.versions == {
        "Windows 10/11 compressed": 1,
        "Windows Vista/7": 1,
    }


def test_mam_compressed_prefetch_decompresses_portably(tmp_path):
    path = tmp_path / "COMPRESSED.EXE-11111111.pf"
    uncompressed = create_scca_prefetch_bytes("COMPRESSED.EXE", 0x11111111, 4)
    mam_bytes = b"MAM\x04" + struct.pack("<I", len(uncompressed)) + literal_xpress_huffman(uncompressed)
    path.write_bytes(mam_bytes)

    details = parse_prefetch_file(path)

    assert decompress_mam(mam_bytes) == uncompressed
    assert details["compression"] == "MAM"
    assert details["signature"] == "SCCA"
    assert details["executable_name"] == "COMPRESSED.EXE"
    assert details["run_count"] == 4
    assert details["prefetch_version_label"] == "Windows 10/11"


def test_prefetch_parser_writes_csv(tmp_path):
    prefetch_dir = tmp_path / "Prefetch"
    output_dir = tmp_path / "out"
    prefetch_dir.mkdir()
    (prefetch_dir / "POWERSHELL.EXE-1234ABCD.pf").write_bytes(
        create_scca_prefetch_bytes("POWERSHELL.EXE", 0x1234ABCD, 7)
    )

    csv_path = parse_prefetch_directory_to_csv(prefetch_dir, output_dir)
    text = csv_path.read_text()

    assert "POWERSHELL.EXE" in text
    assert "1234ABCD" in text
    assert "2026-05-12T13:14:15Z" in text


def test_prefetch_hash_lookup_resolves_local_reference_file(tmp_path, monkeypatch):
    lookup = tmp_path / "prefetch_lookup.txt"
    lookup.write_text(
        "W7    (64-bit)Mouse Properties\t"
        "RUNDLL32.EXE-BE9C36BF.pf\t"
        "C:\\WINDOWS\\system32\\rundll32.exe\t"
        "shell32.dll,Control_RunDLL main.cpl @0\t"
        "\\DEVICE\\HARDDISKVOLUME2\\WINDOWS\\SYSTEM32\\RUNDLL32.EXE\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("FORENSIC_PREFETCH_HASH_LOOKUP_PATHS", str(lookup))
    load_prefetch_hash_references.cache_clear()

    resolved = resolve_prefetch_hash(
        prefetch_name="RUNDLL32.EXE-BE9C36BF.pf",
        executable_name="rundll32.exe",
        prefetch_hash="BE9C36BF",
    )

    assert resolved["reference_path"] == r"C:\WINDOWS\system32\rundll32.exe"
    assert resolved["reference_device_path"] == r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\RUNDLL32.EXE"
    assert resolved["reference_command_line"] == "shell32.dll,Control_RunDLL main.cpl @0"
    assert resolved["reference_os"] == "W7 (64-bit)"
    assert resolved["reference_description"] == "Mouse Properties"
    assert resolved["reference_match_count"] == "1"


def test_normalized_prefetch_row_adds_reference_enrichment(tmp_path, monkeypatch):
    lookup = tmp_path / "prefetch_lookup.txt"
    lookup.write_text(
        "Vista (32-bit)\tWRITE.EXE-A9A22051.pf\tD:\\windows\\write.exe\t\t"
        "\\DEVICE\\HARDDISKVOLUME2\\WINDOWS\\WRITE.EXE\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("FORENSIC_PREFETCH_HASH_LOOKUP_PATHS", str(lookup))
    load_prefetch_hash_references.cache_clear()

    row = normalized_prefetch_row(
        case_id="case-1",
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-1",
        tool_name="PrefetchParser",
        source_csv=tmp_path / "PrefetchParser.csv",
        row_number=1,
        row={
            "source_path": str(tmp_path / "WRITE.EXE-A9A22051.pf"),
            "prefetch_name": "WRITE.EXE-A9A22051.pf",
            "executable_name": "WRITE.EXE",
            "prefetch_hash": "A9A22051",
        },
    )

    assert row["resolved_reference_path"] == r"D:\windows\write.exe"
    assert row["resolved_reference_device_path"] == r"\DEVICE\HARDDISKVOLUME2\WINDOWS\WRITE.EXE"
    assert row["resolved_reference_match_count"] == "1"


def create_scca_prefetch_bytes(exe_name: str, prefetch_hash: int, run_count: int) -> bytes:
    data = bytearray(0x300)
    struct.pack_into("<I", data, 0, 30)
    data[4:8] = b"SCCA"
    struct.pack_into("<I", data, 12, len(data))
    data[16:76] = exe_name.encode("utf-16le").ljust(60, b"\x00")[:60]
    struct.pack_into("<I", data, 76, prefetch_hash)
    struct.pack_into("<Q", data, 0x80, filetime(datetime(2026, 5, 12, 13, 14, 15, tzinfo=timezone.utc)))
    struct.pack_into("<Q", data, 0x88, filetime(datetime(2026, 5, 12, 12, 14, 15, tzinfo=timezone.utc)))
    struct.pack_into("<I", data, 0xD0, run_count)
    path_string = (r"\\DEVICE\\HARDDISKVOLUME3\\WINDOWS\\SYSTEM32\\" + exe_name).encode("utf-16le")
    data[0x180 : 0x180 + len(path_string)] = path_string
    return bytes(data)


def filetime(dt: datetime) -> int:
    return int((dt - FILETIME_EPOCH).total_seconds() * 10_000_000)


def literal_xpress_huffman(payload: bytes) -> bytes:
    table = bytes([0x99]) * 256
    bits = "".join(f"{byte:09b}" for byte in payload)
    padding = (-len(bits)) % 16
    bits += "0" * padding
    words = bytearray()
    for index in range(0, len(bits), 16):
        words.extend(struct.pack("<H", int(bits[index : index + 16], 2)))
    return table + bytes(words) + b"\x00\x00\x00\x00"
