from __future__ import annotations

import csv
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path


OUTPUT_FIELDS = [
    "WorkId",
    "System_Search_GatherTime",
    "System_Size",
    "System_DateModified",
    "System_DateCreated",
    "System_DateAccessed",
    "System_DateImported",
    "System_ItemPathDisplay",
    "System_ItemPathDisplayNarrow",
    "System_ItemFolderPathDisplay",
    "System_FileName",
    "System_FileExtension",
    "System_ItemType",
    "System_ItemTypeText",
    "System_IsFolder",
    "System_IsDeleted",
    "System_FileOwner",
    "System_ThumbnailCacheId",
    "System_Image_HorizontalSize",
    "System_Image_VerticalSize",
    "System_Image_Dimensions",
]

PROPERTY_COLUMNS = {
    "WorkId": ("WorkID",),
    "System_Search_GatherTime": ("4631F-System_Search_GatherTime",),
    "System_Size": ("13F-System_Size",),
    "System_DateModified": ("15F-System_DateModified",),
    "System_DateCreated": ("16F-System_DateCreated",),
    "System_DateAccessed": ("17F-System_DateAccessed",),
    "System_DateImported": ("4365-System_DateImported",),
    "System_ItemPathDisplay": ("4447-System_ItemPathDisplay",),
    "System_ItemPathDisplayNarrow": ("4448-System_ItemPathDisplayNarrow",),
    "System_ItemFolderPathDisplay": ("4440-System_ItemFolderPathDisplay",),
    "System_FileName": ("11-System_FileName",),
    "System_FileExtension": ("4392-System_FileExtension", "12-System_FileExtension"),
    "System_ItemType": ("4450-System_ItemType",),
    "System_ItemTypeText": ("5-System_ItemTypeText",),
    "System_IsFolder": ("4434-System_IsFolder",),
    "System_IsDeleted": ("4430-System_IsDeleted",),
    "System_FileOwner": ("4396-System_FileOwner",),
    "System_ThumbnailCacheId": ("4678-System_ThumbnailCacheId",),
    "System_Image_HorizontalSize": ("4422-System_Image_HorizontalSize",),
    "System_Image_VerticalSize": ("4424-System_Image_VerticalSize",),
    "System_Image_Dimensions": ("4420-System_Image_Dimensions",),
}

FILETIME_FIELDS = {
    "System_Search_GatherTime",
    "System_DateModified",
    "System_DateCreated",
    "System_DateAccessed",
    "System_DateImported",
}
RAW_FILETIME_FIELDS = {
    "15F-System_DateModified",
    "16F-System_DateCreated",
    "17F-System_DateAccessed",
    "4365-System_DateImported",
    "4371-System_Document_DateCreated",
    "4372-System_Document_DatePrinted",
    "4373-System_Document_DateSaved",
    "4404-System_GPS_Date",
    "4519-System_Message_DateReceived",
    "4520-System_Message_DateSent",
    "4570-System_Photo_DateTaken",
    "4631F-System_Search_GatherTime",
}
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def parse_windows_search_ese_to_csv(source: Path, output: Path) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    edb_path = _resolve_windows_edb(source)
    export_prefix = output / "_ese_export" / "windows_search"
    export_dir = export_prefix.with_suffix(".export")
    if export_dir.exists():
        shutil.rmtree(export_dir)
    export_dir.parent.mkdir(parents=True, exist_ok=True)
    if shutil.which("esedbexport") is None:
        raise FileNotFoundError("Missing dependency: esedbexport")
    subprocess.run(
        ["esedbexport", "-t", str(export_prefix), str(edb_path)],
        capture_output=True,
        text=True,
        check=True,
    )
    property_store = _find_exported_table(export_dir, "SystemIndex_PropertyStore")
    csv_path = output / "WindowsSearchESEParser.csv"
    _write_property_store_csv(property_store, csv_path)
    return csv_path


def _resolve_windows_edb(source: Path) -> Path:
    if source.is_file():
        return source
    candidate = source / "Windows.edb"
    if candidate.exists():
        return candidate
    matches = sorted(source.rglob("Windows.edb")) if source.exists() else []
    if matches:
        return matches[0]
    raise FileNotFoundError(f"Windows.edb not found under {source}")


def _find_exported_table(export_dir: Path, table_name: str) -> Path:
    matches = sorted(export_dir.glob(f"{table_name}.*"))
    if not matches:
        raise FileNotFoundError(f"{table_name} was not exported from Windows.edb")
    return matches[0]


def _write_property_store_csv(source: Path, destination: Path) -> None:
    with source.open("r", encoding="utf-8", errors="replace", newline="") as src, destination.open(
        "w", encoding="utf-8", newline=""
    ) as dst:
        reader = csv.DictReader(src, delimiter="\t")
        raw_fields = [field for field in (reader.fieldnames or []) if field not in OUTPUT_FIELDS]
        writer = csv.DictWriter(dst, fieldnames=[*OUTPUT_FIELDS, *raw_fields], extrasaction="ignore")
        writer.writeheader()
        for row in reader:
            normalized = {
                field: _filetime_hex_to_iso(row.get(field, "")) if field in RAW_FILETIME_FIELDS else row.get(field, "")
                for field in raw_fields
            }
            for output_name, candidates in PROPERTY_COLUMNS.items():
                value = _first(row, *candidates)
                if output_name in FILETIME_FIELDS:
                    value = _filetime_hex_to_iso(value)
                elif output_name in {"System_ItemPathDisplay", "System_ItemPathDisplayNarrow", "System_ItemFolderPathDisplay"}:
                    value = _path_text(value)
                normalized[output_name] = value
            if not normalized.get("System_FileName"):
                normalized["System_FileName"] = _basename(
                    normalized.get("System_ItemPathDisplay") or normalized.get("System_ItemPathDisplayNarrow")
                )
            if not normalized.get("System_FileExtension"):
                normalized["System_FileExtension"] = _extension(normalized.get("System_FileName"))
            writer.writerow(normalized)


def _first(row: dict[str, str], *keys: str) -> str:
    for key in keys:
        value = row.get(key)
        if value not in {None, ""}:
            return value
    return ""


def _path_text(value: str) -> str:
    return (value or "").replace("\\\\", "\\")


def _basename(value: str | None) -> str:
    text = (value or "").replace("/", "\\").rstrip("\\")
    return text.rsplit("\\", 1)[-1] if text else ""


def _extension(value: str | None) -> str:
    name = _basename(value)
    if "." not in name:
        return ""
    return "." + name.rsplit(".", 1)[-1].lower()


def _filetime_hex_to_iso(value: str) -> str:
    text = (value or "").strip()
    if not text or set(text) == {"0"} or set(text) == {"2", "a"}:
        return ""
    try:
        raw = bytes.fromhex(text)
    except ValueError:
        return text
    if len(raw) != 8:
        return text
    filetime = int.from_bytes(raw, "little")
    if filetime <= 0:
        return ""
    try:
        return (FILETIME_EPOCH + timedelta(microseconds=filetime // 10)).isoformat().replace("+00:00", "Z")
    except OverflowError:
        return ""
