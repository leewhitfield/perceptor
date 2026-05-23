import struct
from datetime import datetime, timezone

from forensic_orchestrator.tools.recycle import parse_recycle_artifacts_to_csv


def test_recycle_parser_records_modern_deleted_folder_children(tmp_path):
    root = tmp_path / "$Recycle.Bin" / "S-1-5-21"
    deleted_folder = root / "$RABC123"
    deleted_folder.mkdir(parents=True)
    (deleted_folder / "inside.txt").write_text("deleted")
    (root / "$IABC123").write_bytes(modern_i_record("C:\\Users\\Jean\\Desktop\\Folder", 7))

    csv_path = parse_recycle_artifacts_to_csv([tmp_path / "$Recycle.Bin"], tmp_path / "out")
    text = csv_path.read_text()

    assert "item,modern" in text
    assert "child,modern" in text
    assert "inside.txt" in text
    assert "C:\\Users\\Jean\\Desktop\\Folder" in text
    assert "$IABC123" not in text


def test_recycle_parser_reads_windows_10_i_file_path_length(tmp_path):
    root = tmp_path / "$Recycle.Bin" / "S-1-5-21"
    root.mkdir(parents=True)
    (root / "$RABC123.txt").write_text("deleted")
    (root / "$IABC123.txt").write_bytes(modern_i_record_v2("C:\\Users\\Jean\\Desktop\\note.txt", 7))

    csv_path = parse_recycle_artifacts_to_csv([tmp_path / "$Recycle.Bin"], tmp_path / "out")
    text = csv_path.read_text()

    assert "C:\\Users\\Jean\\Desktop\\note.txt" in text
    assert ",C," not in text


def modern_i_record(original_path: str, size: int) -> bytes:
    deleted = int(
        (datetime(2026, 5, 12, 13, 14, 15, tzinfo=timezone.utc) - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds()
        * 10_000_000
    )
    return (
        struct.pack("<Q", 1)
        + struct.pack("<Q", size)
        + struct.pack("<Q", deleted)
        + original_path.encode("utf-16le")
        + b"\x00\x00"
    )


def modern_i_record_v2(original_path: str, size: int) -> bytes:
    deleted = int(
        (datetime(2026, 5, 12, 13, 14, 15, tzinfo=timezone.utc) - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds()
        * 10_000_000
    )
    encoded = original_path.encode("utf-16le") + b"\x00\x00"
    return (
        struct.pack("<Q", 2)
        + struct.pack("<Q", size)
        + struct.pack("<Q", deleted)
        + struct.pack("<I", len(original_path) + 1)
        + encoded
    )
