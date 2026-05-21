import csv

from forensic_orchestrator.tools.windows_search_ese import _filetime_hex_to_iso, _write_property_store_csv


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
