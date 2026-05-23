import csv
import json

from forensic_orchestrator.tools.windows_search_ese import (
    _filetime_hex_to_iso,
    _write_property_store_csv,
    parse_windows_search_ese_to_csv,
)


def test_windows_search_ese_property_store_csv_extracts_thumbcache_mapping(tmp_path):
    exported = tmp_path / "SystemIndex_PropertyStore.11"
    output = tmp_path / "WindowsSearchESEParser.csv"
    exported.write_text(
        "\t".join(
            [
                "WorkID",
                "4631F-System_Search_GatherTime",
                "15F-System_DateModified",
                "4447-System_ItemPathDisplay",
                "11-System_FileName",
                "4392-System_FileExtension",
                "4678-System_ThumbnailCacheId",
                "4371-System_Document_DateCreated",
            ]
        )
        + "\n"
        + "\t".join(
            [
                "42",
                "0080fd805edbd901",
                "0080fd805edbd901",
                r"C:\\Users\\Devon\\Pictures\\photo.jpg",
                "photo.jpg",
                ".jpg",
                "9084ae42c4588348",
                "0080fd805edbd901",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    _write_property_store_csv(exported, output)

    rows = list(csv.DictReader(output.open(encoding="utf-8")))
    assert len(rows) == 1
    assert rows[0]["WorkId"] == "42"
    assert rows[0]["System_Search_GatherTime"] == "2023-08-30T16:24:52.164608Z"
    assert rows[0]["System_DateModified"] == "2023-08-30T16:24:52.164608Z"
    assert rows[0]["System_ItemPathDisplay"] == r"C:\Users\Devon\Pictures\photo.jpg"
    assert rows[0]["System_FileName"] == "photo.jpg"
    assert rows[0]["System_FileExtension"] == ".jpg"
    assert rows[0]["System_ThumbnailCacheId"] == "9084ae42c4588348"
    assert rows[0]["4631F-System_Search_GatherTime"] == "2023-08-30T16:24:52.164608Z"
    assert rows[0]["4371-System_Document_DateCreated"] == "2023-08-30T16:24:52.164608Z"
    assert rows[0]["4678-System_ThumbnailCacheId"] == "9084ae42c4588348"


def test_windows_search_ese_filetime_handles_empty_and_placeholder_values():
    assert _filetime_hex_to_iso("") == ""
    assert _filetime_hex_to_iso("0000000000000000") == ""
    assert _filetime_hex_to_iso("2a2a2a2a2a2a2a2a") == ""


def test_windows_search_parser_records_encrypted_sqlite_without_failing(tmp_path):
    source = tmp_path / "WindowsSearch" / "Applications" / "Windows"
    source.mkdir(parents=True)
    (source / "Windows.db").write_bytes(b"AesGcm1 SQLite3\x00" + b"\x00" * 64)

    csv_path = parse_windows_search_ese_to_csv(source, tmp_path / "out")

    rows = list(csv.DictReader(csv_path.open(encoding="utf-8")))
    assert rows == []
    inventory = json.loads((tmp_path / "out" / "WindowsSearchParserInventory.json").read_text(encoding="utf-8"))
    assert inventory[0]["detected_format"] == "encrypted_sqlite"
    assert inventory[0]["parser_status"] == "unsupported_encrypted_sqlite"
    assert inventory[0]["source_path"].endswith("Windows.db")


def test_windows_search_parser_records_missing_store_without_failing(tmp_path):
    csv_path = parse_windows_search_ese_to_csv(tmp_path / "missing", tmp_path / "out")

    rows = list(csv.DictReader(csv_path.open(encoding="utf-8")))
    assert rows == []
    inventory = json.loads((tmp_path / "out" / "WindowsSearchParserInventory.json").read_text(encoding="utf-8"))
    assert inventory[0]["detected_format"] == "missing"
    assert inventory[0]["parser_status"] == "not_found"
