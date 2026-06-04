from __future__ import annotations

import json
import hashlib
import re
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from forensic_orchestrator.db import utc_now
from forensic_orchestrator.timestamps import normalize_timestamp


EMAIL_RE = re.compile(
    r"(?i)(?<![A-Z0-9._%+-])"
    r"([A-Z0-9._%+-]+@(?:[A-Z0-9-]+\.)+"
    r"(?:COM|ORG|NET|EDU|GOV|MIL|INT|IO|CO|US|UK|CA|AU|DE|FR|JP|NL|INFO|BIZ|ME|TV|TECH|DEV))"
    r"(?![A-Z0-9.-])"
)


def normalized_sam_account_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "source_path": _text(row.get("source_path")),
        "username": _text(row.get("username")),
        "rid": _text(row.get("rid")),
        "rid_hex": _text(row.get("rid_hex")),
        "account_category": _text(row.get("account_category")),
        "last_login_utc": _timestamp(row.get("last_login_utc")),
        "password_last_set_utc": _timestamp(row.get("password_last_set_utc")),
        "last_bad_password_utc": _timestamp(row.get("last_bad_password_utc")),
        "account_expires_utc": _timestamp(row.get("account_expires_utc")),
        "logon_count": _text(row.get("logon_count")),
        "bad_password_count": _text(row.get("bad_password_count")),
        "account_flags_hex": _text(row.get("account_flags_hex")),
        "account_flags": _text(row.get("account_flags")),
        "account_flags_unknown_hex": _text(row.get("account_flags_unknown_hex")),
        "registry_path": _text(row.get("registry_path")),
        "account_key_last_write_utc": _timestamp(row.get("account_key_last_write_utc")),
    }


def normalized_mft_entry_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "entry_number": _text(row.get("EntryNumber")),
        "sequence_number": _text(row.get("SequenceNumber")),
        "in_use": _text(row.get("InUse")),
        "parent_entry_number": _text(row.get("ParentEntryNumber")),
        "parent_sequence_number": _text(row.get("ParentSequenceNumber")),
        "parent_path": _text(row.get("ParentPath")),
        "file_name": _text(row.get("FileName") or row.get("Name")),
        "extension": _text(row.get("Extension")),
        "file_size": _text(row.get("FileSize")),
        "is_directory": _text(row.get("IsDirectory")),
        "has_ads": _text(row.get("HasAds")),
        "is_ads": _text(row.get("IsAds")),
        "si_flags": _text(row.get("SiFlags")),
        "reparse_target": _text(row.get("ReparseTarget")),
        "object_id": _first_text(row, "ObjectId", "ObjectID", "Object Id", "Object ID"),
        "birth_volume_id": _first_text(row, "BirthVolumeId", "BirthVolumeID", "Birth Volume Id", "Birth Volume ID"),
        "birth_object_id": _first_text(row, "BirthObjectId", "BirthObjectID", "Birth Object Id", "Birth Object ID"),
        "birth_domain_id": _first_text(row, "BirthDomainId", "BirthDomainID", "Birth Domain Id", "Birth Domain ID", "DomainId", "Domain ID"),
        "si_fn_copied": _text(row.get("SI<FN") or row.get("Copied")),
        "created_si": _timestamp(row.get("Created0x10")),
        "created_fn": _timestamp(row.get("Created0x30")),
        "modified_si": _timestamp(row.get("LastModified0x10")),
        "modified_fn": _timestamp(row.get("LastModified0x30")),
        "record_changed_si": _timestamp(row.get("LastRecordChange0x10")),
        "record_changed_fn": _timestamp(row.get("LastRecordChange0x30")),
        "accessed_si": _timestamp(row.get("LastAccess0x10")),
        "accessed_fn": _timestamp(row.get("LastAccess0x30")),
        "source_file": _text(row.get("SourceFile")),
    }


def normalized_usn_journal_entry_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    file_name = _first_text(row, "FileName", "Name")
    parent_path = _first_text(row, "FullPath", "FilePath", "Path", "ParentPath")
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "source_file": _first_text(row, "SourceFile", "Source File"),
        "update_sequence_number": _first_text(row, "UpdateSequenceNumber", "USN", "Usn"),
        "update_timestamp": _first_timestamp(row, "UpdateTimestamp", "Timestamp", "TimeStamp", "TimeCreated"),
        "file_name": file_name,
        "extension": _first_text(row, "Extension"),
        "file_reference_number": _first_text(row, "FileReferenceNumber", "EntryNumber", "FileReference"),
        "file_reference_sequence_number": _first_text(
            row,
            "FileReferenceSequenceNumber",
            "SequenceNumber",
            "FileSequenceNumber",
        ),
        "parent_file_reference_number": _first_text(
            row,
            "ParentFileReferenceNumber",
            "ParentEntryNumber",
            "ParentFileReference",
        ),
        "parent_file_reference_sequence_number": _first_text(
            row,
            "ParentFileReferenceSequenceNumber",
            "ParentSequenceNumber",
            "ParentFileSequenceNumber",
        ),
        "full_path": _join_parent_and_name(parent_path, file_name),
        "reason": _first_text(row, "Reason", "UpdateReasons", "Reasons"),
        "reason_flags": _first_text(row, "ReasonFlags", "UpdateReasonFlags"),
        "file_attributes": _first_text(row, "FileAttributes"),
        "file_attributes_flags": _first_text(row, "FileAttributesFlags"),
        "source_info": _first_text(row, "SourceInfo", "SourceInfoFlags"),
        "security_id": _first_text(row, "SecurityId"),
        "major_version": _first_text(row, "MajorVersion"),
        "minor_version": _first_text(row, "MinorVersion"),
        "record_length": _first_text(row, "RecordLength"),
        "offset": _first_text(row, "Offset"),
    }


def _join_parent_and_name(parent_path: str | None, file_name: str | None) -> str | None:
    if not parent_path:
        return file_name
    if not file_name:
        return parent_path
    clean_parent = parent_path.rstrip("\\/")
    clean_name = file_name.strip("\\/")
    lower_parent = clean_parent.lower().replace("/", "\\")
    lower_name = clean_name.lower().replace("/", "\\")
    if lower_parent.endswith("\\" + lower_name) or lower_parent == lower_name:
        return parent_path
    separator = "\\" if "\\" in clean_parent or clean_parent.startswith(".") else "/"
    return f"{clean_parent}{separator}{clean_name}"


def normalized_zone_identifier_ads_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "source_path": _first_text(row, "source_path", "SourcePath"),
        "file_path": _first_text(row, "file_path", "FilePath"),
        "user_profile": _first_text(row, "user_profile", "UserProfile"),
        "stream_name": _first_text(row, "stream_name", "StreamName"),
        "zone_id": _first_text(row, "zone_id", "ZoneId", "ZoneID"),
        "classification": _first_text(row, "classification", "Classification"),
        "referrer_url": _first_text(row, "referrer_url", "ReferrerUrl"),
        "referrer_host": _first_text(row, "referrer_host", "ReferrerHost"),
        "host_url": _first_text(row, "host_url", "HostUrl"),
        "host": _first_text(row, "host", "Host"),
        "timestamp_utc": _first_timestamp(row, "timestamp_utc", "TimestampUtc"),
        "details_json": _first_text(row, "details_json", "DetailsJson") or "{}",
    }


def normalized_setupapi_device_event_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv,
    row_number: int,
    row: dict[str, object],
) -> dict[str, object]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "source_path": _first_text(row, "source_path", "SourcePath"),
        "line_number": _first_text(row, "line_number", "LineNumber"),
        "section_title": _first_text(row, "section_title", "SectionTitle"),
        "operation": _first_text(row, "operation", "Operation"),
        "device_instance_id": _first_text(row, "device_instance_id", "DeviceInstanceId"),
        "device_class": _first_text(row, "device_class", "DeviceClass"),
        "vendor_id": _first_text(row, "vendor_id", "VendorId"),
        "product_id": _first_text(row, "product_id", "ProductId"),
        "serial": _first_text(row, "serial", "Serial"),
        "service": _first_text(row, "service", "Service"),
        "inf_path": _first_text(row, "inf_path", "InfPath"),
        "driver_package": _first_text(row, "driver_package", "DriverPackage"),
        "start_time_utc": _first_timestamp(row, "start_time_utc", "StartTimeUtc"),
        "end_time_utc": _first_timestamp(row, "end_time_utc", "EndTimeUtc"),
        "event_time_utc": _first_timestamp(row, "event_time_utc", "EventTimeUtc"),
        "status": _first_text(row, "status", "Status"),
        "confidence": _first_text(row, "confidence", "Confidence"),
        "details_json": _first_text(row, "details_json", "DetailsJson") or "{}",
        "error": _first_text(row, "error", "Error"),
        "created_at": utc_now(),
    }


def normalized_thumbcache_entry_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "source_path": _first_text(row, "source_path", "SourcePath"),
        "source_name": _first_text(row, "source_name", "SourceName"),
        "user_profile": _first_text(row, "user_profile", "UserProfile"),
        "cache_file_type": _first_text(row, "cache_file_type", "CacheFileType"),
        "cache_id": _first_text(row, "cache_id", "CacheId", "ThumbnailCacheId"),
        "entry_index": _first_text(row, "entry_index", "EntryIndex"),
        "entry_offset": _first_text(row, "entry_offset", "EntryOffset"),
        "entry_size": _first_text(row, "entry_size", "EntrySize"),
        "thumbnail_offset": _first_text(row, "thumbnail_offset", "ThumbnailOffset"),
        "thumbnail_size": _first_text(row, "thumbnail_size", "ThumbnailSize"),
        "thumbnail_type": _first_text(row, "thumbnail_type", "ThumbnailType"),
        "thumbnail_sha256": _first_text(row, "thumbnail_sha256", "ThumbnailSha256"),
        "source_mtime_utc": _first_timestamp(row, "source_mtime_utc", "SourceMtimeUtc"),
        "parser_status": _first_text(row, "parser_status", "ParserStatus"),
        "parser_note": _first_text(row, "parser_note", "ParserNote"),
        "details_json": _first_text(row, "details_json", "DetailsJson") or "{}",
    }


def normalized_ntfs_logfile_entry_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "source_file": _first_text(row, "SourceFile", "Source File", "_file", "File"),
        "event_time": _first_timestamp(row, "Timestamp", "TimeStamp", "EventTime", "TimeCreated", "UpdateTimestamp"),
        "operation": _first_text(row, "Operation", "Action", "Event", "Type", "derived record type"),
        "redo_operation": _first_text(row, "RedoOperation", "Redo", "Redo Op", "RedoOperationName", "deriv redo"),
        "undo_operation": _first_text(row, "UndoOperation", "Undo", "Undo Op", "UndoOperationName", "deriv undo"),
        "target_attribute": _first_text(row, "TargetAttribute", "Attribute", "AttributeType", "AttributeName", "target attribute"),
        "file_name": _first_text(row, "FileName", "Name", "em_ATTR filename"),
        "file_path": _first_text(row, "FullPath", "FilePath", "Path"),
        "file_reference_number": _first_text(row, "FileReferenceNumber", "EntryNumber", "FileReference", "MftEntry", "deriv inum"),
        "file_reference_sequence_number": _first_text(row, "FileReferenceSequenceNumber", "SequenceNumber", "Seq", "em_MFT seq value"),
        "parent_file_reference_number": _first_text(row, "ParentFileReferenceNumber", "ParentEntryNumber", "ParentFileReference"),
        "parent_file_reference_sequence_number": _first_text(
            row,
            "ParentFileReferenceSequenceNumber",
            "ParentSequenceNumber",
            "ParentFileSequenceNumber",
        ),
        "log_sequence_number": _first_text(row, "LogSequenceNumber", "LSN", "Lsn", "lsn", "this LSN"),
        "previous_log_sequence_number": _first_text(row, "PreviousLogSequenceNumber", "PreviousLSN", "PrevLsn", "prev_lsn", "previous LSN"),
        "transaction_id": _first_text(row, "TransactionId", "Transaction ID", "TxId", "transaction id", "transaction num"),
        "client_id": _first_text(row, "ClientId", "Client ID", "client index"),
        "record_offset": _first_text(row, "Offset", "RecordOffset", "Record Offset", "record offset"),
        "row_json": json.dumps(row, default=str, sort_keys=True),
    }


def normalized_ntfs_index_entry_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "directory_entry_number": _first_text(row, "directory_entry_number"),
        "directory_path": _first_text(row, "directory_path"),
        "source": _first_text(row, "source"),
        "block_vcn": _first_text(row, "block_vcn"),
        "block_active": _first_text(row, "block_active"),
        "entry_offset": _first_text(row, "entry_offset"),
        "index_entry_length": _first_text(row, "index_entry_length"),
        "index_entry_flags": _first_text(row, "index_entry_flags"),
        "referenced_entry_number": _first_text(row, "referenced_entry_number"),
        "referenced_sequence_number": _first_text(row, "referenced_sequence_number"),
        "parent_entry_number": _first_text(row, "parent_entry_number"),
        "parent_sequence_number": _first_text(row, "parent_sequence_number"),
        "file_name": _first_text(row, "file_name"),
        "name_type": _first_text(row, "name_type"),
        "name_type_label": _first_text(row, "name_type_label"),
        "created_fn": _first_timestamp(row, "created_fn"),
        "modified_fn": _first_timestamp(row, "modified_fn"),
        "record_changed_fn": _first_timestamp(row, "record_changed_fn"),
        "accessed_fn": _first_timestamp(row, "accessed_fn"),
        "allocated_size": _first_text(row, "allocated_size"),
        "real_size": _first_text(row, "real_size"),
        "file_flags": _first_text(row, "file_flags"),
        "from_slack": _first_text(row, "from_slack"),
        "source_file": _first_text(row, "source_file"),
    }


def normalized_ntfs_index_bitmap_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "directory_entry_number": _first_text(row, "directory_entry_number"),
        "directory_path": _first_text(row, "directory_path"),
        "index_root_attr": _first_text(row, "index_root_attr"),
        "index_allocation_attr": _first_text(row, "index_allocation_attr"),
        "bitmap_attr": _first_text(row, "bitmap_attr"),
        "bitmap_hex": _first_text(row, "bitmap_hex"),
        "active_block_count": _first_text(row, "active_block_count"),
        "active_blocks": _first_text(row, "active_blocks"),
        "error": _first_text(row, "error"),
    }


def normalized_image_analysis_item_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "source_artifact_type": _first_text(row, "source_artifact_type", "SourceArtifactType"),
        "source_artifact_id": _first_text(row, "source_artifact_id", "SourceArtifactId"),
        "source_path": _first_text(row, "source_path", "SourcePath"),
        "output_path": _first_text(row, "output_path", "OutputPath"),
        "file_name": _first_text(row, "file_name", "FileName"),
        "file_extension": _first_text(row, "file_extension", "FileExtension"),
        "sha256": _first_text(row, "sha256", "SHA256"),
        "file_size": _first_text(row, "file_size", "FileSize"),
        "width": _first_text(row, "width", "Width"),
        "height": _first_text(row, "height", "Height"),
        "image_format": _first_text(row, "image_format", "ImageFormat"),
        "analysis_type": _first_text(row, "analysis_type", "AnalysisType"),
        "ocr_status": _first_text(row, "ocr_status", "OcrStatus"),
        "ocr_engine": _first_text(row, "ocr_engine", "OcrEngine"),
        "ocr_text": _first_text(row, "ocr_text", "OcrText"),
        "classifier_status": _first_text(row, "classifier_status", "ClassifierStatus"),
        "classifier_label": _first_text(row, "classifier_label", "ClassifierLabel"),
        "details_json": _first_text(row, "details_json", "DetailsJson") or "{}",
    }


def normalized_rdp_cache_item_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "record_type": _first_text(row, "record_type", "RecordType"),
        "user_profile": _first_text(row, "user_profile", "UserProfile"),
        "source_cache_path": _first_text(row, "source_cache_path", "SourceCachePath"),
        "fragment_path": _first_text(row, "fragment_path", "FragmentPath"),
        "contact_sheet_path": _first_text(row, "contact_sheet_path", "ContactSheetPath"),
        "file_name": _first_text(row, "file_name", "FileName"),
        "sha256": _first_text(row, "sha256", "SHA256"),
        "file_size": _first_text(row, "file_size", "FileSize"),
        "width": _first_text(row, "width", "Width"),
        "height": _first_text(row, "height", "Height"),
        "image_format": _first_text(row, "image_format", "ImageFormat"),
        "fragment_index": _first_text(row, "fragment_index", "FragmentIndex"),
        "parser_status": _first_text(row, "parser_status", "ParserStatus"),
        "parser_note": _first_text(row, "parser_note", "ParserNote"),
        "details_json": _first_text(row, "details_json", "DetailsJson") or "{}",
    }


def normalized_rdp_visual_observation_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "user_profile": _first_text(row, "user_profile", "UserProfile"),
        "source_cache_path": _first_text(row, "source_cache_path", "SourceCachePath"),
        "contact_sheet_path": _first_text(row, "contact_sheet_path", "ContactSheetPath"),
        "observation_time_utc": _first_timestamp(row, "observation_time_utc", "ObservationTimeUtc"),
        "time_basis": _first_text(row, "time_basis", "TimeBasis"),
        "observation_type": _first_text(row, "observation_type", "ObservationType"),
        "observed_application": _first_text(row, "observed_application", "ObservedApplication"),
        "observed_text": _first_text(row, "observed_text", "ObservedText"),
        "observed_path": _first_text(row, "observed_path", "ObservedPath"),
        "certainty": _first_text(row, "certainty", "Certainty"),
        "caveat": _first_text(row, "caveat", "Caveat"),
        "details_json": _first_text(row, "details_json", "DetailsJson") or "{}",
    }


def normalized_cloud_sync_artifact_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    provider = _first_text(row, "provider")
    if not provider:
        provider = _cloud_provider_from_text(str(source_csv) + " " + json.dumps(row, default=str))
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "provider": provider,
        "artifact_type": _first_text(row, "artifact_type", "MapDescription", "Description"),
        "user_profile": _first_text(row, "user_profile"),
        "source_path": _first_text(row, "source_path", "SourceFile", "Source File"),
        "source_name": _first_text(row, "source_name", "SourceName"),
        "database_name": _first_text(row, "database_name", "Database", "FileName"),
        "table_name": _first_text(row, "table_name", "Table", "TableName"),
        "event_time_utc": _first_timestamp(row, "event_time_utc", "timestamp", "Timestamp", "Modified", "Created", "LastModified"),
        "local_path": _first_text(row, "local_path", "LocalPath", "Local Path", "Path"),
        "cloud_path": _first_text(row, "cloud_path", "CloudPath", "Cloud Path", "ServerPath", "Server Path", "DisplayPath"),
        "file_name": _first_text(row, "file_name", "FileName", "Filename", "Name", "LocalTitle"),
        "file_id": _first_text(row, "file_id", "FileID", "File Id", "DocID", "Doc Id", "ResourceID", "ID"),
        "parent_id": _first_text(row, "parent_id", "ParentID", "Parent Id", "ParentDocID"),
        "stable_id": _first_text(row, "stable_id", "StableID", "Stable Id"),
        "server_path": _first_text(row, "server_path", "ServerPath", "Server Path"),
        "url": _first_text(row, "url", "URL", "WebURL", "AlternateLink"),
        "mime_type": _first_text(row, "mime_type", "MimeType", "MIME Type"),
        "file_size": _first_text(row, "file_size", "FileSize", "Size"),
        "is_folder": _first_text(row, "is_folder", "IsFolder", "Folder"),
        "is_deleted": _first_text(row, "is_deleted", "IsDeleted", "Deleted", "Removed", "Trashed"),
        "sync_status": _first_text(row, "sync_status", "SyncStatus", "Status", "State"),
        "event_type": _first_text(row, "event_type", "EventType", "Action", "Operation", "FileEventType"),
        "direction": _first_text(row, "direction", "Direction"),
        "owner": _first_text(row, "owner", "Owner", "OwnerEmail", "OwnerDisplayName"),
        "shared": _first_text(row, "shared", "Shared", "IsShared"),
        "protobuf_fields_json": _first_text(row, "protobuf_fields_json"),
        "details_json": _first_text(row, "details_json"),
        "error": _first_text(row, "error", "Error"),
    }


def normalized_browser_session_entry_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    url = _first_text(row, "url", "URL")
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "browser": _first_text(row, "browser"),
        "source_path": _first_text(row, "source_path", "SourceFile", "Source File"),
        "profile_path": _first_text(row, "profile_path"),
        "session_type": _first_text(row, "session_type"),
        "window_id": _first_text(row, "window_id"),
        "tab_id": _first_text(row, "tab_id"),
        "tab_index": _first_text(row, "tab_index"),
        "navigation_index": _first_text(row, "navigation_index"),
        "url": url,
        "title": _first_text(row, "title", "Title"),
        "referrer_url": _first_text(row, "referrer_url", "Referrer"),
        "host": _first_text(row, "host") or _url_host(url),
        "timestamp_utc": _first_timestamp(row, "timestamp_utc", "Timestamp"),
        "last_active_time_utc": _first_timestamp(row, "last_active_time_utc"),
        "is_current": _first_text(row, "is_current"),
        "is_pinned": _first_text(row, "is_pinned"),
        "parser": _first_text(row, "parser"),
        "details_json": _text(row.get("details_json")) or _row_json({}),
        "created_at": utc_now(),
    }


def normalized_browser_site_setting_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    origin = _first_text(row, "origin")
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "browser": _first_text(row, "browser"),
        "source_path": _first_text(row, "source_path", "SourceFile", "Source File"),
        "profile_path": _first_text(row, "profile_path"),
        "setting_type": _first_text(row, "setting_type"),
        "origin": origin,
        "host": _first_text(row, "host") or _url_host(origin),
        "setting_name": _first_text(row, "setting_name"),
        "setting_value": _first_text(row, "setting_value"),
        "last_modified_utc": _first_timestamp(row, "last_modified_utc"),
        "expiration_utc": _first_timestamp(row, "expiration_utc"),
        "details_json": _text(row.get("details_json")) or _row_json({}),
        "created_at": utc_now(),
    }


def normalized_browser_notification_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    origin = _first_text(row, "origin")
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "browser": _first_text(row, "browser"),
        "source_path": _first_text(row, "source_path", "SourceFile", "Source File"),
        "profile_path": _first_text(row, "profile_path"),
        "origin": origin,
        "host": _first_text(row, "host") or _url_host(origin),
        "notification_id": _first_text(row, "notification_id"),
        "title": _first_text(row, "title"),
        "body": _first_text(row, "body"),
        "tag": _first_text(row, "tag"),
        "icon": _first_text(row, "icon"),
        "badge": _first_text(row, "badge"),
        "created_utc": _first_timestamp(row, "created_utc"),
        "notification_timestamp_utc": _first_timestamp(row, "notification_timestamp_utc"),
        "first_click_utc": _first_timestamp(row, "first_click_utc"),
        "last_click_utc": _first_timestamp(row, "last_click_utc"),
        "closed_utc": _first_timestamp(row, "closed_utc"),
        "num_clicks": _first_text(row, "num_clicks"),
        "closed_reason": _first_text(row, "closed_reason"),
        "details_json": _text(row.get("details_json")) or _row_json({}),
        "created_at": utc_now(),
    }


def normalized_google_drive_cache_map_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    details = _json_dict(_first_text(row, "details_json"))
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "account_id": _google_drive_account_id(_first_text(row, "source_path")),
        "stable_id": _first_text(row, "stable_id"),
        "file_id": _first_text(row, "file_id"),
        "virtual_path": _first_text(row, "cloud_path"),
        "file_name": _first_text(row, "file_name"),
        "cache_id": str(details.get("cache_id") or ""),
        "cache_path": _first_text(row, "local_path") or str(details.get("cache_path") or ""),
        "windows_cache_path": str(details.get("windows_cache_path") or ""),
        "cache_file_size": _first_text(row, "file_size"),
        "mapping_method": str(details.get("mapping_method") or ""),
        "evidence_basis": str(details.get("evidence_basis") or ""),
        "details_json": _first_text(row, "details_json"),
    }


def normalized_onedrive_item_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "artifact_type": _first_text(row, "artifact_type"),
        "user_profile": _first_text(row, "user_profile"),
        "account": _first_text(row, "account"),
        "source_path": _first_text(row, "source_path"),
        "source_ode_csv": _first_text(row, "source_csv"),
        "source_ode_row_number": _first_text(row, "source_row_number"),
        "record_type": _first_text(row, "record_type"),
        "name": _first_text(row, "name"),
        "path": _first_text(row, "path"),
        "parent_resource_id": _first_text(row, "parent_resource_id"),
        "resource_id": _first_text(row, "resource_id"),
        "etag": _first_text(row, "etag"),
        "status": _first_text(row, "status"),
        "spo_permissions": _first_text(row, "spo_permissions"),
        "volume_id": _first_text(row, "volume_id"),
        "item_index": _first_text(row, "item_index"),
        "last_change_utc": _first_timestamp(row, "last_change_utc"),
        "disk_last_access_utc": _first_timestamp(row, "disk_last_access_utc"),
        "disk_creation_utc": _first_timestamp(row, "disk_creation_utc"),
        "size": _first_text(row, "size"),
        "local_hash_digest": _first_text(row, "local_hash_digest"),
        "local_hash_algorithm": _first_text(row, "local_hash_algorithm"),
        "shared_item": _first_text(row, "shared_item"),
        "media_json": _first_text(row, "media_json"),
        "hydration_json": _first_text(row, "hydration_json"),
        "metadata_json": _first_text(row, "metadata_json"),
        "is_deleted": _first_text(row, "is_deleted"),
        "delete_time_utc": _first_timestamp(row, "delete_time_utc"),
        "deleting_process": _first_text(row, "deleting_process"),
        "error": _first_text(row, "error"),
    }


def normalized_onedrive_log_entry_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "user_profile": _first_text(row, "user_profile"),
        "account": _first_text(row, "account"),
        "source_path": _first_text(row, "source_path"),
        "source_name": _first_text(row, "source_name"),
        "log_type": _first_text(row, "log_type"),
        "record_index": _first_text(row, "record_index"),
        "odl_version": _first_text(row, "odl_version"),
        "one_drive_version": _first_text(row, "one_drive_version"),
        "windows_version": _first_text(row, "windows_version"),
        "timestamp_utc": _first_timestamp(row, "timestamp_utc"),
        "code_file": _first_text(row, "code_file"),
        "function": _first_text(row, "function"),
        "flags": _first_text(row, "flags"),
        "context_data": _first_text(row, "context_data"),
        "event_type": _first_text(row, "event_type"),
        "local_path": _first_text(row, "local_path"),
        "url": _first_text(row, "url"),
        "resource_id": _first_text(row, "resource_id"),
        "params_text": _first_text(row, "params_text"),
        "params_json": _first_text(row, "params_json"),
        "raw_strings_json": _first_text(row, "raw_strings_json"),
        "parser_status": _first_text(row, "parser_status"),
        "error": _first_text(row, "error"),
    }


def _cloud_provider_from_text(text: str) -> str:
    lower = text.lower()
    if "dropbox" in lower:
        return "Dropbox"
    if "googledrive" in lower or "google drive" in lower or "drivefs" in lower:
        return "Google Drive"
    if "onedrive" in lower or "one drive" in lower:
        return "OneDrive"
    return "Cloud"


def _json_dict(value: str) -> dict[str, Any]:
    if not value:
        return {}
    try:
        loaded = json.loads(value)
    except (TypeError, ValueError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _google_drive_account_id(value: str) -> str:
    parts = Path(value).parts
    lowered = [part.lower() for part in parts]
    if "drivefs" in lowered:
        index = lowered.index("drivefs")
        if index + 1 < len(parts):
            return parts[index + 1]
    return ""


def normalized_srum_record_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "provider_guid": _first_text(row, "provider_guid", "ProviderGuid", "TableName") or _srum_provider_guid(source_csv),
        "provider_name": _first_text(row, "provider_name", "ProviderName") or _srum_provider_name(source_csv),
        "source_table": _first_text(row, "source_table", "SourceTable"),
        "record_type": _first_text(row, "record_type") or _srum_record_type(source_csv),
        "srum_id": _first_text(row, "srum_id", "Id", "ID", "AutoIncId"),
        "timestamp": _first_timestamp(row, "timestamp", "Timestamp", "TimeStamp", "EventTimestamp"),
        "app_id": _first_text(row, "app_id", "AppId", "App ID"),
        "app_name": _first_text(row, "app_name", "AppName", "App", "Name"),
        "app_path": _first_text(row, "app_path", "AppPath", "Path", "FullPath"),
        "app_description": _first_text(row, "app_description", "ExeInfoDescription"),
        "exe_timestamp": _first_timestamp(row, "exe_timestamp", "ExeTimestamp"),
        "user_id": _first_text(row, "user_id", "UserId", "User ID"),
        "user_sid": _first_text(row, "user_sid", "UserSid", "SID", "Sid"),
        "user_name": _first_text(row, "user_name", "UserName", "User"),
        "bytes_received": _first_text(row, "bytes_received", "BytesReceived", "BytesRecvd", "Bytes Received"),
        "bytes_sent": _first_text(row, "bytes_sent", "BytesSent", "Bytes Sent"),
        "interface_luid": _first_text(row, "interface_luid", "InterfaceLuid"),
        "interface_type": _first_text(row, "interface_type", "InterfaceType"),
        "l2_profile_id": _first_text(row, "l2_profile_id", "L2ProfileId"),
        "l2_profile_name": _first_text(row, "l2_profile_name", "L2ProfileName", "ProfileName"),
        "l2_profile_flags": _first_text(row, "l2_profile_flags", "L2ProfileFlags"),
        "connected_time": _first_text(row, "connected_time", "ConnectedTime"),
        "connect_start_time": _first_timestamp(row, "connect_start_time", "ConnectStartTime"),
        "connect_end_time": _first_timestamp(row, "connect_end_time", "ConnectEndTime"),
        "notification_type": _first_text(row, "notification_type", "NotificationType"),
        "payload_size": _first_text(row, "payload_size", "PayloadSize"),
        "network_type": _first_text(row, "network_type", "NetworkType"),
        "foreground_bytes_read": _first_text(row, "foreground_bytes_read", "ForegroundBytesRead"),
        "foreground_bytes_written": _first_text(row, "foreground_bytes_written", "ForegroundBytesWritten"),
        "background_bytes_read": _first_text(row, "background_bytes_read", "BackgroundBytesRead"),
        "background_bytes_written": _first_text(row, "background_bytes_written", "BackgroundBytesWritten"),
        "foreground_cycle_time": _first_text(row, "foreground_cycle_time", "ForegroundCycleTime"),
        "background_cycle_time": _first_text(row, "background_cycle_time", "BackgroundCycleTime"),
        "face_time": _first_text(row, "face_time", "FaceTime"),
        "foreground_context_switches": _first_text(row, "foreground_context_switches", "ForegroundContextSwitches"),
        "background_context_switches": _first_text(row, "background_context_switches", "BackgroundContextSwitches"),
        "foreground_read_operations": _first_text(row, "foreground_read_operations", "ForegroundNumReadOperations"),
        "foreground_write_operations": _first_text(row, "foreground_write_operations", "ForegroundNumWriteOperations"),
        "background_read_operations": _first_text(row, "background_read_operations", "BackgroundNumReadOperations"),
        "background_write_operations": _first_text(row, "background_write_operations", "BackgroundNumWriteOperations"),
        "foreground_flushes": _first_text(row, "foreground_flushes", "ForegroundNumberOfFlushes"),
        "background_flushes": _first_text(row, "background_flushes", "BackgroundNumberOfFlushes"),
        "flags": _first_text(row, "flags", "Flags"),
        "start_time": _first_timestamp(row, "start_time", "StartTime"),
        "end_time": _first_timestamp(row, "end_time", "EndTime"),
        "duration_ms": _first_text(row, "duration_ms", "DurationMS"),
        "span_ms": _first_text(row, "span_ms", "SpanMS"),
        "timeline_end": _first_text(row, "timeline_end", "TimelineEnd"),
        "event_timestamp": _first_timestamp(row, "event_timestamp", "EventTimestamp"),
        "state_transition": _first_text(row, "state_transition", "StateTransition"),
        "charge_level": _first_text(row, "charge_level", "ChargeLevel"),
        "cycle_count": _first_text(row, "cycle_count", "CycleCount"),
        "designed_capacity": _first_text(row, "designed_capacity", "DesignedCapacity"),
        "full_charged_capacity": _first_text(row, "full_charged_capacity", "FullChargedCapacity"),
        "active_ac_time": _first_text(row, "active_ac_time", "ActiveAcTime"),
        "active_dc_time": _first_text(row, "active_dc_time", "ActiveDcTime"),
        "active_discharge_time": _first_text(row, "active_discharge_time", "ActiveDischargeTime"),
        "active_energy": _first_text(row, "active_energy", "ActiveEnergy"),
        "cs_ac_time": _first_text(row, "cs_ac_time", "CsAcTime"),
        "cs_dc_time": _first_text(row, "cs_dc_time", "CsDcTime"),
        "cs_discharge_time": _first_text(row, "cs_discharge_time", "CsDischargeTime"),
        "cs_energy": _first_text(row, "cs_energy", "CsEnergy"),
        "configuration_hash": _first_text(row, "configuration_hash", "ConfigurationHash"),
        "metadata": _first_text(row, "metadata", "Metadata"),
        "energy_data": _first_text(row, "energy_data", "Energy Data", "EnergyData"),
        "tag": _first_text(row, "tag", "Tag"),
        "binary_data": _first_text(row, "binary_data", "BinaryData", "Usage"),
        "vpn_profile_name": _first_text(row, "vpn_profile_name", "VpnProfileName"),
        "vpn_server": _first_text(row, "vpn_server", "VpnServer"),
        "vpn_device": _first_text(row, "vpn_device", "VpnDevice"),
        "vpn_protocol": _first_text(row, "vpn_protocol", "VpnProtocol"),
        "vpn_phonebook_path": _first_text(row, "vpn_phonebook_path", "VpnPhonebookPath"),
        "vpn_match_method": _first_text(row, "vpn_match_method", "VpnMatchMethod"),
        "row_json": _row_json(row),
        "created_at": utc_now(),
    }


def normalized_ual_record_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "database_file": _first_text(row, "database_file", "DatabaseFile"),
        "source_table": _first_text(row, "source_table", "SourceTable"),
        "record_id": _first_text(row, "record_id", "RecordId", "Id", "ID"),
        "role_guid": _first_text(row, "role_guid", "RoleGuid", "RoleId", "RoleID"),
        "role_name": _first_text(row, "role_name", "RoleName", "Role"),
        "product_name": _first_text(row, "product_name", "ProductName", "Product"),
        "tenant_id": _first_text(row, "tenant_id", "TenantId", "TenantID"),
        "user_sid": _first_text(row, "user_sid", "UserSid", "SID", "Sid"),
        "user_name": _first_text(row, "user_name", "UserName", "User"),
        "client_name": _first_text(row, "client_name", "ClientName", "Client", "HostName"),
        "client_ip": _first_text(row, "client_ip", "ClientIp", "ClientIP", "IpAddress", "IPAddress"),
        "client_id": _first_text(row, "client_id", "ClientId", "ClientID", "DeviceId", "DeviceID"),
        "first_seen": _first_timestamp(row, "first_seen", "FirstSeen", "FirstAccess"),
        "last_seen": _first_timestamp(row, "last_seen", "LastSeen", "LastAccess"),
        "insert_date": _first_timestamp(row, "insert_date", "InsertDate"),
        "last_access": _first_timestamp(row, "last_access", "LastAccessDate", "LastAccess"),
        "access_count": _first_text(row, "access_count", "AccessCount", "TotalAccesses", "Count"),
        "activity_count": _first_text(row, "activity_count", "ActivityCount", "TotalCount"),
        "day_count": _first_text(row, "day_count", "DayCount", "Days"),
        "raw_time_bucket": _first_text(row, "raw_time_bucket", "TimeStamp", "Timestamp", "Date", "Day"),
        "created_at": utc_now(),
    }


def normalized_windows_search_file_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    extras = _extra_values(row)
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "work_id": _first_text(row, "WorkId", "Work ID"),
        "gather_time": _first_timestamp(row, "System_Search_GatherTime"),
        "item_path": _first_text(row, "System_ItemPathDisplay", "System_ItemPathDisplayNarrow"),
        "item_url": _first_text(row, "System_ItemUrl"),
        "folder_path": _first_text(row, "System_ItemFolderPathDisplay", "System_ItemFolderPathDisplayNarrow"),
        "file_name": _first_text(row, "System_FileName", "System_ItemNameDisplay", "System_ItemName"),
        "file_extension": _first_text(row, "System_FileExtension"),
        "item_type": _first_text(row, "System_ItemType", "System_ItemTypeText", "System_KindText"),
        "date_created": _first_timestamp(row, "System_DateCreated", "System_Document_DateCreated"),
        "date_modified": _first_timestamp(row, "System_DateModified", "System_Document_DateSaved"),
        "date_accessed": _first_timestamp(row, "System_DateAccessed"),
        "date_imported": _first_timestamp(row, "System_DateImported"),
        "size": _first_text(row, "System_Size") or _extra_text(extras, 0),
        "owner": _first_text(row, "System_FileOwner") or _extra_text(extras, 2),
        "computer_name": _first_text(row, "System_ComputerName") or _extra_text(extras, 1),
        "is_deleted": _first_text(row, "System_IsDeleted", "IsDeleted"),
        "is_folder": _first_text(row, "System_IsFolder", "IsFolder"),
        "row_json": _row_json(row),
    }


def windows_search_indexed_content_rows(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    source_table: str,
    source_record_id: str,
    row_number: int,
    normalized_row: dict[str, Any],
    row: dict[str, Any],
) -> list[dict[str, Any]]:
    fields: list[tuple[str, str]] = []
    for name in (
        "System_Search_Contents",
        "System_FullText",
        "System_Contents",
        "System_Comment",
        "System_Document_Summary",
        "System_Document_Text",
        "System_Message_Body",
    ):
        value = _first_text(row, name)
        if value:
            fields.append((name, value))

    extras = _extra_values(row)
    extra_content = _extra_text(extras, 3)
    if extra_content:
        fields.append(("_extra[3]", extra_content))

    timestamp = (
        _timestamp(normalized_row.get("gather_time"))
        or _timestamp(normalized_row.get("date_modified"))
        or _timestamp(normalized_row.get("date_accessed"))
        or _timestamp(normalized_row.get("start_time"))
    )
    item_path = (
        _text(normalized_row.get("item_path"))
        or _text(normalized_row.get("target_url"))
        or _text(normalized_row.get("content_uri"))
        or _text(normalized_row.get("item_url"))
    )
    item_name = (
        _text(normalized_row.get("file_name"))
        or _text(normalized_row.get("title"))
        or _text(normalized_row.get("display_text"))
    )
    rows = []
    seen: set[tuple[str, str]] = set()
    for content_field, content in fields:
        content = content.strip()
        if not content:
            continue
        fingerprint = (content_field, content)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        content_id = str(uuid.uuid4())
        rows.append(
            {
                "id": content_id,
                "case_id": case_id,
                "computer_id": computer_id,
                "image_id": image_id,
                "tool_output_id": tool_output_id,
                "tool_name": tool_name,
                "source_csv": source_csv,
                "source_table": source_table,
                "source_record_id": source_record_id,
                "row_number": row_number,
                "work_id": _text(normalized_row.get("work_id")),
                "gather_time": _timestamp(normalized_row.get("gather_time")),
                "item_path": item_path,
                "item_name": item_name,
                "item_type": _text(normalized_row.get("item_type")),
                "content_field": content_field,
                "content_text": "",
                "_opensearch_content_text": content,
                "content_sha256": _sha256_text(content),
                "content_length": len(content),
                "opensearch_document_id": _content_document_id(case_id, content),
                "timestamp": timestamp,
                "created_at": utc_now(),
            }
        )
    return rows


def windows_search_property_rows(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    source_table: str,
    source_record_id: str,
    row_number: int,
    normalized_row: dict[str, Any],
    row: dict[str, Any],
) -> list[dict[str, Any]]:
    rows = []
    seen: set[tuple[str, str]] = set()
    item_path = (
        _text(normalized_row.get("item_path"))
        or _text(normalized_row.get("target_url"))
        or _text(normalized_row.get("content_uri"))
        or _text(normalized_row.get("item_url"))
    )
    timestamp = (
        _text(normalized_row.get("gather_time"))
        or _text(normalized_row.get("date_modified"))
        or _text(normalized_row.get("date_accessed"))
        or _text(normalized_row.get("start_time"))
    )
    for key, value in row.items():
        if key is None:
            for index, extra_value in enumerate(value or []):
                property_name = f"_extra[{index}]"
                property_value = _text(extra_value)
                if property_value is None:
                    continue
                normalized_name = _windows_search_extra_name(index) or property_name
                if _is_windows_search_content_property(property_name, normalized_name):
                    continue
                identity = (property_name, property_value)
                if identity in seen:
                    continue
                seen.add(identity)
                rows.append(
                    _windows_search_property_row(
                        case_id=case_id,
                        computer_id=computer_id,
                        image_id=image_id,
                        tool_output_id=tool_output_id,
                        tool_name=tool_name,
                        source_csv=source_csv,
                        source_table=source_table,
                        source_record_id=source_record_id,
                        row_number=row_number,
                        work_id=_text(normalized_row.get("work_id")),
                        item_path=item_path,
                        timestamp=timestamp,
                        property_name=property_name,
                        property_value=property_value,
                        normalized_name=normalized_name,
                    )
                )
            continue
        property_name = str(key)
        property_value = _text(value)
        if property_value is None:
            continue
        if _is_windows_search_content_property(property_name, None):
            continue
        identity = (property_name, property_value)
        if identity in seen:
            continue
        seen.add(identity)
        rows.append(
            _windows_search_property_row(
                case_id=case_id,
                computer_id=computer_id,
                image_id=image_id,
                tool_output_id=tool_output_id,
                tool_name=tool_name,
                source_csv=source_csv,
                source_table=source_table,
                source_record_id=source_record_id,
                row_number=row_number,
                work_id=_text(normalized_row.get("work_id")),
                item_path=item_path,
                timestamp=timestamp,
                property_name=property_name,
                property_value=property_value,
                normalized_name=None,
            )
        )
    return rows


def normalized_windows_search_internet_history_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "work_id": _first_text(row, "WorkId", "Work ID"),
        "gather_time": _first_text(row, "System_Search_GatherTime"),
        "item_url": _first_text(row, "System_ItemUrl"),
        "target_url": _first_text(row, "System_Link_TargetUrl", "System_Link_TargetParsingPath"),
        "target_host": _first_text(row, "System_Link_TargetUrlHostName", "System_ComputerName"),
        "target_path": _first_text(row, "System_Link_TargetUrlPath"),
        "title": _first_text(row, "System_Title", "System_ItemNameDisplay"),
        "file_name": _first_text(row, "System_FileName", "System_ItemName"),
        "item_path": _first_text(row, "System_ItemPathDisplay", "System_ItemPathDisplayNarrow"),
        "folder_path": _first_text(row, "System_ItemFolderPathDisplay", "System_ItemFolderPathDisplayNarrow"),
        "date_created": _first_text(row, "System_DateCreated", "System_Document_DateCreated"),
        "date_modified": _first_text(row, "System_DateModified", "System_Document_DateSaved"),
        "date_accessed": _first_text(row, "System_DateAccessed"),
        "date_imported": _first_text(row, "System_DateImported"),
        "owner": _first_text(row, "System_FileOwner"),
        "row_json": _row_json(row),
    }


def normalized_windows_search_activity_history_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "work_id": _first_text(row, "WorkId", "Work ID"),
        "gather_time": _first_text(row, "System_Search_GatherTime"),
        "item_url": _first_text(row, "System_ItemUrl"),
        "content_uri": _first_text(row, "System_Activity_ContentUri"),
        "app_display_name": _first_text(row, "System_Activity_AppDisplayName"),
        "display_text": _first_text(row, "System_Activity_DisplayText"),
        "description": _first_text(row, "System_Activity_Description"),
        "app_id": _first_text(row, "System_ActivityHistory_AppId"),
        "app_activity_id": _first_text(row, "System_ActivityHistory_AppActivityId"),
        "device_id": _first_text(row, "System_ActivityHistory_DeviceId"),
        "start_time": _first_text(row, "System_ActivityHistory_StartTime"),
        "end_time": _first_text(row, "System_ActivityHistory_EndTime"),
        "local_start_time": _first_text(row, "System_ActivityHistory_LocalStartTime"),
        "local_end_time": _first_text(row, "System_ActivityHistory_LocalEndTime"),
        "active_duration": _first_text(row, "System_ActivityHistory_ActiveDuration"),
        "item_path": _first_text(row, "System_ItemPathDisplay", "System_ItemPathDisplayNarrow"),
        "file_name": _first_text(row, "System_ItemNameDisplay", "System_ItemName"),
        "row_json": _row_json(row),
    }


def normalized_file_internal_metadata_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "source_file": _first_text(row, "source_file"),
        "original_path": _first_text(row, "original_path"),
        "file_name": _first_text(row, "file_name"),
        "extension": _first_text(row, "extension"),
        "parser": _first_text(row, "parser"),
        "metadata_group": _first_text(row, "metadata_group"),
        "property_name": _first_text(row, "property_name"),
        "property_value": _first_text(row, "property_value"),
        "raw_property_name": _first_text(row, "raw_property_name"),
        "file_size": _first_text(row, "file_size"),
        "mft_created": _first_text(row, "mft_created"),
        "mft_modified": _first_text(row, "mft_modified"),
        "mft_accessed": _first_text(row, "mft_accessed"),
        "mft_record_modified": _first_text(row, "mft_record_modified"),
        "mft_in_use": _first_text(row, "mft_in_use"),
        "path_unresolved": _first_text(row, "path_unresolved"),
        "deleted_mft_entry": _first_text(row, "deleted_mft_entry"),
        "live_orphan": _first_text(row, "live_orphan"),
        "extraction_method": _first_text(row, "extraction_method"),
    }


def normalized_mailbox_message_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv,
    row_number: int,
    row: dict[str, object],
) -> dict[str, object]:
    row_id = str(uuid.uuid4())
    body_text = _text(row.get("body_text")) or ""
    body_html = _text(row.get("body_html")) or ""
    return {
        "id": row_id,
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "source_path": _text(row.get("source_path")),
        "container_path": _text(row.get("container_path")),
        "message_path": _text(row.get("message_path")),
        "source_format": _text(row.get("source_format")),
        "parser_status": _text(row.get("parser_status")),
        "parser_error": _text(row.get("parser_error")),
        "user_profile": _text(row.get("user_profile")),
        "user_sid": _text(row.get("user_sid")),
        "message_id": _text(row.get("message_id")),
        "in_reply_to": _text(row.get("in_reply_to")),
        "references_header": _text(row.get("references_header")),
        "reply_to": _text(row.get("reply_to")),
        "conversation_index": _text(row.get("conversation_index")),
        "conversation_topic": _text(row.get("conversation_topic")),
        "importance": _text(row.get("importance")),
        "priority": _text(row.get("priority")),
        "sensitivity": _text(row.get("sensitivity")),
        "x_originating_ip": _text(row.get("x_originating_ip")),
        "message_flags": _text(row.get("message_flags")),
        "message_status": _text(row.get("message_status")),
        "message_status_flags": _text(row.get("message_status_flags")),
        "disposition_notification_to": _text(row.get("disposition_notification_to")),
        "subject": _text(row.get("subject")),
        "sender": _text(row.get("sender")),
        "recipients": _text(row.get("recipients")),
        "cc": _text(row.get("cc")),
        "bcc": _text(row.get("bcc")),
        "message_date_utc": _timestamp(row.get("message_date_utc")),
        "body_text": "",
        "body_html": "",
        "_opensearch_body_text": body_text,
        "_opensearch_body_html": body_html,
        "body_text_sha256": _sha256_text(body_text),
        "body_html_sha256": _sha256_text(body_html),
        "body_text_length": len(body_text),
        "body_html_length": len(body_html),
        "opensearch_document_id": _content_document_id(case_id, "\n".join(part for part in (body_text, body_html) if part)),
        "attachment_names": _text(row.get("attachment_names")),
        "attachment_count": _text(row.get("attachment_count")),
        "has_attachments": _text(row.get("has_attachments")),
        "dedupe_key": _text(row.get("dedupe_key")),
    }


def normalized_mailbox_attachment_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv,
    row_number: int,
    row: dict[str, object],
) -> dict[str, object]:
    row_id = str(uuid.uuid4())
    extracted_text = _text(row.get("extracted_text")) or ""
    metadata_json = _text(row.get("metadata_json")) or ""
    return {
        "id": row_id,
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "source_path": _text(row.get("source_path")),
        "container_path": _text(row.get("container_path")),
        "message_path": _text(row.get("message_path")),
        "user_profile": _text(row.get("user_profile")),
        "user_sid": _text(row.get("user_sid")),
        "message_id": _text(row.get("message_id")),
        "conversation_index": _text(row.get("conversation_index")),
        "conversation_topic": _text(row.get("conversation_topic")),
        "subject": _text(row.get("subject")),
        "sender": _text(row.get("sender")),
        "recipients": _text(row.get("recipients")),
        "message_date_utc": _timestamp(row.get("message_date_utc")),
        "attachment_name": _text(row.get("attachment_name")),
        "attachment_path": _text(row.get("attachment_path")),
        "content_type": _text(row.get("content_type")),
        "size": _text(row.get("size")),
        "sha256": _text(row.get("sha256")),
        "metadata_json": "",
        "metadata_json_sha256": _sha256_text(metadata_json),
        "metadata_json_length": len(metadata_json),
        "extracted_text": "",
        "_opensearch_extracted_text": extracted_text,
        "extracted_text_sha256": _sha256_text(extracted_text),
        "extracted_text_length": len(extracted_text),
        "opensearch_document_id": _content_document_id(
            case_id,
            extracted_text,
        ),
        "extraction_status": _text(row.get("extraction_status")),
        "parser_error": _text(row.get("parser_error")),
        "dedupe_key": _text(row.get("dedupe_key")),
    }


def normalized_windows_mail_store_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv,
    row_number: int,
    row: dict[str, object],
) -> dict[str, object]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "source_database": _text(row.get("source_database")),
        "source_table": _text(row.get("source_table")),
        "table_file": _text(row.get("table_file")),
        "table_row_number": _text(row.get("table_row_number")),
        "user_profile": _text(row.get("user_profile")),
        "source_record_id": _text(row.get("source_record_id")),
        "parent_record_id": _text(row.get("parent_record_id")),
        "display_name": _text(row.get("display_name")),
        "primary_time_utc": _timestamp(row.get("primary_time_utc")),
        "secondary_time_utc": _timestamp(row.get("secondary_time_utc")),
        "row_json": _text(row.get("row_json")),
    }


def normalized_messaging_record_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv,
    row_number: int,
    row: dict[str, object],
) -> dict[str, object]:
    row_id = str(uuid.uuid4())
    message_text = _text(row.get("message_text")) or ""
    raw_text = _text(row.get("raw_text")) or ""
    return {
        "id": row_id,
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "application": _text(row.get("application")),
        "user_profile": _text(row.get("user_profile")),
        "artifact_type": _text(row.get("artifact_type")),
        "source_path": _text(row.get("source_path")),
        "store_path": _text(row.get("store_path")),
        "record_key": _text(row.get("record_key")),
        "record_type": _text(row.get("record_type")),
        "url": _text(row.get("url")),
        "host": _text(row.get("host")),
        "email": _text(row.get("email")),
        "timestamp_utc": _timestamp(row.get("timestamp_utc")),
        "message_text": "",
        "raw_text": "",
        "_opensearch_message_text": message_text,
        "message_text_sha256": _sha256_text(message_text),
        "message_text_length": len(message_text),
        "raw_text_sha256": _sha256_text(raw_text),
        "raw_text_length": len(raw_text),
        "opensearch_document_id": _content_document_id(case_id, message_text),
        "dedupe_key": _text(row.get("dedupe_key")),
    }


def normalized_messaging_message_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv,
    row_number: int,
    row: dict[str, object],
) -> dict[str, object]:
    row_id = str(uuid.uuid4())
    message_text = _text(row.get("message_text")) or ""
    message_html = _text(row.get("message_html")) or ""
    raw_json = _text(row.get("raw_json")) or ""
    return {
        "id": row_id,
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "application": _text(row.get("application")),
        "user_profile": _text(row.get("user_profile")),
        "source_path": _text(row.get("source_path")),
        "store_path": _text(row.get("store_path")),
        "record_key": _text(row.get("record_key")),
        "platform_message_id": _text(row.get("platform_message_id")),
        "conversation_id": _text(row.get("conversation_id")),
        "channel_id": _text(row.get("channel_id")),
        "thread_id": _text(row.get("thread_id")),
        "sender_id": _text(row.get("sender_id")),
        "sender_name": _text(row.get("sender_name")),
        "sender_email": _text(row.get("sender_email")),
        "recipient": _text(row.get("recipient")),
        "timestamp_utc": _timestamp(row.get("timestamp_utc")),
        "message_type": _text(row.get("message_type")),
        "message_text": "",
        "message_html": "",
        "_opensearch_message_text": message_text,
        "_opensearch_message_html": message_html,
        "url": _text(row.get("url")),
        "parser_confidence": _text(row.get("parser_confidence")),
        "raw_json": "",
        "message_text_sha256": _sha256_text(message_text),
        "message_text_length": len(message_text),
        "message_html_sha256": _sha256_text(message_html),
        "message_html_length": len(message_html),
        "raw_json_sha256": _sha256_text(raw_json),
        "raw_json_length": len(raw_json),
        "opensearch_document_id": _content_document_id(case_id, "\n".join(part for part in (message_text, message_html) if part)),
        "dedupe_key": _text(row.get("dedupe_key")),
    }


def windows_search_email_indicator_rows(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    source_table: str,
    source_record_id: str,
    row_number: int,
    normalized_row: dict[str, Any],
    row: dict[str, Any],
) -> list[dict[str, Any]]:
    timestamp = (
        _timestamp(normalized_row.get("gather_time"))
        or _timestamp(normalized_row.get("start_time"))
        or _timestamp(normalized_row.get("date_modified"))
        or _timestamp(normalized_row.get("date_accessed"))
    )
    context_path = (
        _text(normalized_row.get("item_path"))
        or _text(normalized_row.get("target_url"))
        or _text(normalized_row.get("content_uri"))
        or _text(normalized_row.get("item_url"))
    )
    context_title = (
        _text(normalized_row.get("title"))
        or _text(normalized_row.get("display_text"))
        or _text(normalized_row.get("file_name"))
        or _text(normalized_row.get("folder_path"))
    )
    fields = {
        "item_path": normalized_row.get("item_path"),
        "item_url": normalized_row.get("item_url"),
        "folder_path": normalized_row.get("folder_path"),
        "file_name": normalized_row.get("file_name"),
        "owner": normalized_row.get("owner"),
        "target_url": normalized_row.get("target_url"),
        "target_host": normalized_row.get("target_host"),
        "target_path": normalized_row.get("target_path"),
        "title": normalized_row.get("title"),
        "content_uri": normalized_row.get("content_uri"),
        "display_text": normalized_row.get("display_text"),
        "description": normalized_row.get("description"),
        "app_id": normalized_row.get("app_id"),
    }
    seen: set[tuple[str, str]] = set()
    rows: list[dict[str, Any]] = []
    for field_name, value in fields.items():
        text = _text(value)
        if text is None:
            continue
        for match in EMAIL_RE.finditer(text):
            email = match.group(1).lower()
            key = (email, field_name)
            if key in seen:
                continue
            seen.add(key)
            rows.append(
                {
                    "id": str(uuid.uuid4()),
                    "case_id": case_id,
                    "computer_id": computer_id,
                    "image_id": image_id,
                    "tool_output_id": tool_output_id,
                    "tool_name": tool_name,
                    "source_csv": source_csv,
                    "source_table": source_table,
                    "source_record_id": source_record_id,
                    "row_number": row_number,
                    "email": email,
                    "domain": email.rsplit("@", 1)[1],
                    "evidence_field": field_name,
                    "evidence_value": text,
                    "timestamp": timestamp,
                    "context_path": context_path,
                    "context_title": context_title,
                }
            )
    return rows


def normalized_registry_hive_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "source_path": _text(row.get("source_path")),
        "original_path": _text(row.get("original_path")),
        "hive_name": _text(row.get("hive_name")),
        "hive_type": _text(row.get("hive_type")),
        "size": _text(row.get("size")),
        "sha256": _text(row.get("sha256")),
        "header_valid": _text(row.get("header_valid")),
        "key_count": _text(row.get("key_count")),
        "value_count": _text(row.get("value_count")),
        "parser_error": _text(row.get("parser_error")),
    }


def normalized_registry_artifact_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "source_path": _text(row.get("source_path")),
        "hive_type": _text(row.get("hive_type")),
        "user_profile": _text(row.get("user_profile")),
        "user_sid": _text(row.get("user_sid")),
        "artifact": _text(row.get("artifact")),
        "category": _text(row.get("category")),
        "key_path": _text(row.get("key_path")),
        "key_last_write_utc": _timestamp(row.get("key_last_write_utc")),
        "event_time_utc": _timestamp(row.get("event_time_utc")),
        "recentdocs_time_utc": _timestamp(row.get("recentdocs_time_utc")),
        "recentdocs_extension_time_utc": _timestamp(row.get("recentdocs_extension_time_utc")),
        "mru_position": _text(row.get("mru_position")),
        "recentdocs_mru_position": _text(row.get("recentdocs_mru_position")),
        "recentdocs_extension_mru_position": _text(row.get("recentdocs_extension_mru_position")),
        "is_most_recent": _text(row.get("is_most_recent")),
        "value_name": _text(row.get("value_name")),
        "value_type": _text(row.get("value_type")),
        "value_data": _text(row.get("value_data")),
        "display_name": _text(row.get("display_name")),
        "normalized_path": _text(row.get("normalized_path")),
        "run_counter": _text(row.get("run_counter")),
        "focus_count": _text(row.get("focus_count")),
        "focus_time": _text(row.get("focus_time")),
        "last_executed": _timestamp(row.get("last_executed")),
        "value_data_hex": _text(row.get("value_data_hex")),
        "transaction_logs_detected": _text(row.get("transaction_logs_detected")),
        "transaction_logs_applied": _text(row.get("transaction_logs_applied")),
        "transaction_log_paths": _text(row.get("transaction_log_paths")),
        "notes": _text(row.get("notes")),
    }


def normalized_office_trust_row_from_registry_artifact(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any] | None:
    artifact = _text(row.get("artifact"))
    if artifact not in {"office_trusted_locations", "office_trusted_documents"}:
        return None
    key_path = _text(row.get("key_path")) or ""
    value_name = _text(row.get("value_name"))
    value_data = _text(row.get("value_data"))
    parts = [part for part in re.split(r"[\\/]+", key_path) if part]
    office_version = _office_version_from_parts(parts)
    application = _office_application_from_parts(parts, office_version)
    location_id = parts[-1] if artifact == "office_trusted_locations" and parts else None
    path_or_file = value_data if artifact == "office_trusted_locations" and (value_name or "").lower() == "path" else None
    if artifact == "office_trusted_documents":
        path_or_file = value_name if value_name and value_name != "(default)" else value_data
    flags = _office_trust_flags(row)
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "source_path": _text(row.get("source_path")),
        "hive_type": _text(row.get("hive_type")),
        "user_profile": _text(row.get("user_profile")),
        "trust_type": artifact,
        "office_version": office_version,
        "application": application,
        "location_id": location_id,
        "key_path": key_path,
        "key_last_write_utc": _timestamp(row.get("key_last_write_utc")),
        "event_time_utc": _timestamp(row.get("event_time_utc")) or _timestamp(row.get("key_last_write_utc")),
        "value_name": value_name,
        "value_type": _text(row.get("value_type")),
        "value_data": value_data,
        "path_or_file": path_or_file,
        "allow_subfolders": _office_bool_value(value_name, value_data, "allowsubfolders"),
        "allow_network_location": _office_bool_value(value_name, value_data, "allownetworklocations"),
        "permission_flags": flags,
        "permitted_editing": _office_flag_contains(flags, "editing"),
        "permitted_macros_or_scripts": _office_flag_contains(flags, "macro") or _office_flag_contains(flags, "script"),
        "details_json": json.dumps({"value_data_hex": _text(row.get("value_data_hex")), "notes": _text(row.get("notes"))}, sort_keys=True),
    }


def normalized_taskbar_feature_usage_row_from_registry_artifact(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any] | None:
    if _text(row.get("artifact")) not in {"taskbar_usage", "taskbar_feature_usage"}:
        return None
    key_path = _text(row.get("key_path")) or ""
    value_name = _text(row.get("value_name"))
    value_data = _text(row.get("value_data"))
    usage_count = None if value_name == "KeyCreationTime" else _registry_numeric_value(value_data)
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "source_path": _text(row.get("source_path")),
        "hive_type": _text(row.get("hive_type")),
        "user_profile": _text(row.get("user_profile")),
        "artifact": _text(row.get("artifact")),
        "feature": _taskbar_feature_from_key(key_path),
        "key_path": key_path,
        "key_last_write_utc": _timestamp(row.get("key_last_write_utc")),
        "event_time_utc": _timestamp(row.get("event_time_utc")) or _timestamp(row.get("key_last_write_utc")),
        "value_name": value_name,
        "value_type": _text(row.get("value_type")),
        "value_data": value_data,
        "usage_count": usage_count,
        "details_json": json.dumps({
            "value_data_hex": _text(row.get("value_data_hex")),
            "notes": _text(row.get("notes")),
            "value_role": "metadata" if value_name == "KeyCreationTime" else "feature_counter",
        }, sort_keys=True),
    }


def normalized_evtx_event_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "record_number": _text(row.get("RecordNumber")),
        "event_record_id": _text(row.get("EventRecordId")),
        "time_created": _text(row.get("TimeCreated")),
        "event_id": _text(row.get("EventId")),
        "level": _text(row.get("Level")),
        "provider": _text(row.get("Provider")),
        "channel": _text(row.get("Channel")),
        "process_id": _text(row.get("ProcessId")),
        "thread_id": _text(row.get("ThreadId")),
        "computer": _text(row.get("Computer")),
        "user_id": _text(row.get("UserId")),
        "map_description": _text(row.get("MapDescription")),
        "user_name": _text(row.get("UserName")),
        "remote_host": _text(row.get("RemoteHost")),
        "payload_data1": _text(row.get("PayloadData1")),
        "payload_data2": _text(row.get("PayloadData2")),
        "payload_data3": _text(row.get("PayloadData3")),
        "payload_data4": _text(row.get("PayloadData4")),
        "payload_data5": _text(row.get("PayloadData5")),
        "payload_data6": _text(row.get("PayloadData6")),
        "executable_info": _text(row.get("ExecutableInfo")),
        "source_file": _text(row.get("SourceFile")),
        "payload": _text(row.get("Payload")),
    }


def normalized_etl_event_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "source_file": _text(row.get("source_file")),
        "source_name": _text(row.get("source_name")),
        "parser_status": _text(row.get("parser_status")),
        "parser_error": _text(row.get("parser_error")),
        "timestamp_utc": _timestamp(row.get("timestamp_utc")),
        "provider_name": _text(row.get("provider_name")),
        "provider_id": _text(row.get("provider_id")),
        "provider_label": _text(row.get("provider_label")),
        "event_category": _text(row.get("event_category")),
        "event_name": _text(row.get("event_name")),
        "event_id": _text(row.get("event_id")),
        "opcode": _text(row.get("opcode")),
        "version": _text(row.get("version")),
        "process_id": _text(row.get("process_id")),
        "parent_process_id": _text(row.get("parent_process_id")),
        "session_id": _text(row.get("session_id")),
        "image_name": _text(row.get("image_name")),
        "command_line": _text(row.get("command_line")),
        "user_sid": _text(row.get("user_sid")),
        "package_full_name": _text(row.get("package_full_name")),
        "flags": _text(row.get("flags")),
        "payload_strings_json": _text(row.get("payload_strings_json")),
        "event_values_json": _text(row.get("event_values_json")),
        "file_size": _text(row.get("file_size")),
        "sha256_first_mb": _text(row.get("sha256_first_mb")),
    }


def normalized_recycle_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "record_type": _text(row.get("record_type")),
        "recycle_format": _text(row.get("recycle_format")),
        "source_path": _text(row.get("source_path")),
        "top_level_name": _text(row.get("top_level_name")),
        "recycled_path": _text(row.get("recycled_path")),
        "child_relative_path": _text(row.get("child_relative_path")),
        "display_name": _text(row.get("display_name")),
        "original_path": _text(row.get("original_path")),
        "deletion_time_utc": _timestamp(row.get("deletion_time_utc")),
        "file_size": _text(row.get("file_size")),
        "is_directory": _text(row.get("is_directory")),
        "mft_created": _timestamp(row.get("mft_created")),
        "mft_modified": _timestamp(row.get("mft_modified")),
        "mft_accessed": _timestamp(row.get("mft_accessed")),
        "mft_record_modified": _timestamp(row.get("mft_record_modified")),
    }


def normalized_firefox_history_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "source_path": _text(row.get("source_path")),
        "profile_path": _text(row.get("profile_path")),
        "url": _text(row.get("url")),
        "title": _text(row.get("title")),
        "visit_time_utc": _timestamp(row.get("visit_time_utc")),
        "visit_type": _text(row.get("visit_type")),
        "visit_count": _text(row.get("visit_count")),
        "typed": _text(row.get("typed")),
        "hidden": _text(row.get("hidden")),
        "frecency": _text(row.get("frecency")),
        "visit_source": _text(row.get("visit_source")),
        "visit_source_label": _text(row.get("visit_source_label")),
        "local_vs_synced": _text(row.get("local_vs_synced")),
    }


def normalized_firefox_cookie_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "source_path": _text(row.get("source_path")),
        "profile_path": _text(row.get("profile_path")),
        "host": _text(row.get("host")),
        "name": _text(row.get("name")),
        "value": _text(row.get("value")),
        "path": _text(row.get("path")),
        "created_utc": _timestamp(row.get("created_utc")),
        "last_accessed_utc": _timestamp(row.get("last_accessed_utc")),
        "expires_utc": _timestamp(row.get("expires_utc")),
        "is_secure": _text(row.get("is_secure")),
        "is_http_only": _text(row.get("is_http_only")),
    }


def normalized_browser_history_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "browser": _text(row.get("browser")),
        "source_path": _text(row.get("source_path")),
        "profile_path": _text(row.get("profile_path")),
        "url": _text(row.get("url")),
        "title": _text(row.get("title")),
        "visit_time_utc": _timestamp(row.get("visit_time_utc")),
        "visit_count": _text(row.get("visit_count")),
        "typed_count": _text(row.get("typed_count")),
        "visit_source": _text(row.get("visit_source")),
        "visit_source_label": _text(row.get("visit_source_label")),
        "local_vs_synced": _text(row.get("local_vs_synced")),
    }


def normalized_browser_download_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "browser": _text(row.get("browser")),
        "source_path": _text(row.get("source_path")),
        "profile_path": _text(row.get("profile_path")),
        "target_path": _text(row.get("target_path")),
        "tab_url": _text(row.get("tab_url")),
        "site_url": _text(row.get("site_url")),
        "referrer": _text(row.get("referrer")),
        "start_time_utc": _timestamp(row.get("start_time_utc")),
        "end_time_utc": _timestamp(row.get("end_time_utc")),
        "received_bytes": _text(row.get("received_bytes")),
        "total_bytes": _text(row.get("total_bytes")),
        "state": _text(row.get("state")),
        "danger_type": _text(row.get("danger_type")),
        "interrupt_reason": _text(row.get("interrupt_reason")),
    }


def normalized_browser_cookie_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "browser": _text(row.get("browser")),
        "source_path": _text(row.get("source_path")),
        "profile_path": _text(row.get("profile_path")),
        "host": _text(row.get("host")),
        "name": _text(row.get("name")),
        "path": _text(row.get("path")),
        "created_utc": _timestamp(row.get("created_utc")),
        "last_accessed_utc": _timestamp(row.get("last_accessed_utc")),
        "expires_utc": _timestamp(row.get("expires_utc")),
        "is_secure": _text(row.get("is_secure")),
        "is_http_only": _text(row.get("is_http_only")),
    }


def normalized_browser_cache_entry_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "browser": _text(row.get("browser")),
        "source_path": _text(row.get("source_path")),
        "profile_path": _text(row.get("profile_path")),
        "cache_type": _text(row.get("cache_type")),
        "url": _text(row.get("url")),
        "host": _text(row.get("host")),
        "cache_file": _text(row.get("cache_file")),
        "cache_file_size": _text(row.get("cache_file_size")),
        "cache_file_modified_utc": _timestamp(row.get("cache_file_modified_utc")),
    }


def normalized_browser_artifact_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "browser": _text(row.get("browser")),
        "artifact_type": _text(row.get("artifact_type")),
        "source_path": _text(row.get("source_path")),
        "profile_path": _text(row.get("profile_path")),
        "name": _text(row.get("name")),
        "value": _text(row.get("value")),
        "url": _text(row.get("url")),
        "title": _text(row.get("title")),
        "host": _text(row.get("host")),
        "local_path": _text(row.get("local_path")),
        "timestamp_utc": _timestamp(row.get("timestamp_utc")),
        "details_json": _text(row.get("details_json")) or "{}",
    }


def normalized_office_backstage_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "artifact_type": _text(row.get("artifact_type")),
        "source_path": _text(row.get("source_path")),
        "user_profile": _text(row.get("user_profile")),
        "application": _text(row.get("application")),
        "name": _text(row.get("name")),
        "value": _text(row.get("value")),
        "path": _text(row.get("path")),
        "url": _text(row.get("url")),
        "host": _text(row.get("host")),
        "timestamp_utc": _timestamp(row.get("timestamp_utc")),
        "details_json": _text(row.get("details_json")) or "{}",
    }


def normalized_user_dictionary_word_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "source_path": _text(row.get("source_path")),
        "user_profile": _text(row.get("user_profile")),
        "application": _text(row.get("application")),
        "office_version": _text(row.get("office_version")),
        "proofing_id": _text(row.get("proofing_id")),
        "dictionary_name": _text(row.get("dictionary_name")),
        "word": _text(row.get("word")),
        "word_index": _int(row.get("word_index")),
        "timestamp_utc": _timestamp(row.get("timestamp_utc")),
        "details_json": _text(row.get("details_json")) or "{}",
    }


def normalized_package_cache_entry_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "user_profile": _text(row.get("user_profile")),
        "application_package": _text(row.get("application_package")),
        "source_database": _text(row.get("source_database")),
        "source_table": _text(row.get("source_table")),
        "table_row_number": _text(row.get("table_row_number")),
        "cache_name": _text(row.get("cache_name")),
        "site_origin": _text(row.get("site_origin")),
        "request_url": _text(row.get("request_url")),
        "host": _text(row.get("host")),
        "response_status": _text(row.get("response_status")),
        "response_type": _text(row.get("response_type")),
        "response_headers": _text(row.get("response_headers")),
        "response_date_utc": _timestamp(row.get("response_date_utc")),
        "content_type": _text(row.get("content_type")),
        "content_length": _text(row.get("content_length")),
        "source_body_path": _text(row.get("source_body_path")),
        "stored_body_path": _text(row.get("stored_body_path")),
        "body_file_name": _text(row.get("body_file_name")),
        "body_size": _text(row.get("body_size")),
        "body_sha256": _text(row.get("body_sha256")),
        "body_encrypted": _text(row.get("body_encrypted")),
        "encryption_version": _text(row.get("encryption_version")),
        "decoded_state": _text(row.get("decoded_state")),
    }


def normalized_package_artifact_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "record_type": _text(row.get("record_type")),
        "user_profile": _text(row.get("user_profile")),
        "application_package": _text(row.get("application_package")),
        "source_path": _text(row.get("source_path")),
        "source_name": _text(row.get("source_name")),
        "file_name": _text(row.get("file_name")),
        "file_extension": _text(row.get("file_extension")),
        "file_size": _text(row.get("file_size")),
        "modified_utc": _timestamp(row.get("modified_utc")),
        "event_time_utc": _timestamp(row.get("event_time_utc")),
        "url": _text(row.get("url")),
        "host": _text(row.get("host")),
        "title": _text(row.get("title")),
        "artifact_value": _text(row.get("artifact_value")),
        "artifact_text": _text(row.get("artifact_text")),
        "details_json": _text(row.get("details_json")),
        "error": _text(row.get("error")),
    }


def normalized_spotify_artifact_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "artifact_type": _text(row.get("artifact_type")),
        "user_profile": _text(row.get("user_profile")),
        "source_path": _text(row.get("source_path")),
        "source_name": _text(row.get("source_name")),
        "source_file": _text(row.get("source_file")),
        "file_size": _text(row.get("file_size")),
        "modified_utc": _timestamp(row.get("modified_utc")),
        "account_user_id": _text(row.get("account_user_id")),
        "spotify_user_id": _text(row.get("spotify_user_id")),
        "spotify_user_uri": _text(row.get("spotify_user_uri")),
        "display_name": _text(row.get("display_name")),
        "key_name": _text(row.get("key_name")),
        "value": _text(row.get("value")),
        "evidence": _text(row.get("evidence")),
        "error": _text(row.get("error")),
        "created_at": utc_now(),
    }


def normalized_telemetry_artifact_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "record_type": _text(row.get("record_type")),
        "artifact_group": _text(row.get("artifact_group")),
        "user_profile": _text(row.get("user_profile")),
        "application": _text(row.get("application")),
        "source_path": _text(row.get("source_path")),
        "source_name": _text(row.get("source_name")),
        "file_name": _text(row.get("file_name")),
        "file_extension": _text(row.get("file_extension")),
        "file_size": _text(row.get("file_size")),
        "modified_utc": _timestamp(row.get("modified_utc")),
        "event_time_utc": _timestamp(row.get("event_time_utc")),
        "identifier": _text(row.get("identifier")),
        "path": _text(row.get("path")),
        "url": _text(row.get("url")),
        "host": _text(row.get("host")),
        "title": _text(row.get("title")),
        "value_name": _text(row.get("value_name")),
        "value_data": _text(row.get("value_data")),
        "artifact_text": _text(row.get("artifact_text")),
        "sha256_first_mb": _text(row.get("sha256_first_mb")),
        "details_json": _text(row.get("details_json")),
        "error": _text(row.get("error")),
    }


def normalized_windows_search_gather_log_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "source_file": _text(row.get("source_file")),
        "source_name": _text(row.get("source_name")),
        "log_type": _text(row.get("log_type")),
        "line_number": _text(row.get("line_number")),
        "timestamp_utc": _timestamp(row.get("timestamp_utc")),
        "filetime_hex": _text(row.get("filetime_hex")),
        "time_low_hex": _text(row.get("time_low_hex")),
        "time_high_hex": _text(row.get("time_high_hex")),
        "item_url": _text(row.get("item_url")),
        "item_path": _text(row.get("item_path")),
        "item_scheme": _text(row.get("item_scheme")),
        "is_deleted_path": _text(row.get("is_deleted_path")),
        "status_hex": _text(row.get("status_hex")),
        "crawl_code_hex": _text(row.get("crawl_code_hex")),
        "scope_id": _text(row.get("scope_id")),
        "document_id": _text(row.get("document_id")),
        "raw_fields_json": _text(row.get("raw_fields_json")) or "[]",
        "created_at": utc_now(),
    }


def normalized_windows_activity_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "source_path": _text(row.get("source_path")),
        "user_profile": _text(row.get("user_profile")),
        "source_table": _text(row.get("source_table")),
        "activity_id": _text(row.get("activity_id")),
        "app_id": _text(row.get("app_id")),
        "app_display_name": _text(row.get("app_display_name")),
        "activity_type": _text(row.get("activity_type")),
        "display_text": _text(row.get("display_text")),
        "file_name": _text(row.get("file_name")),
        "content_uri": _text(row.get("content_uri")),
        "activation_uri": _text(row.get("activation_uri")),
        "fallback_uri": _text(row.get("fallback_uri")),
        "start_time_utc": _timestamp(row.get("start_time_utc")),
        "end_time_utc": _timestamp(row.get("end_time_utc")),
        "last_modified_utc": _timestamp(row.get("last_modified_utc")),
        "expiration_time_utc": _timestamp(row.get("expiration_time_utc")),
        "platform_device_id": _text(row.get("platform_device_id")),
        "payload_json": _text(row.get("payload_json")),
        "raw_json": _text(row.get("raw_json")),
    }


def normalized_webcache_entry_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "source_database": _text(row.get("source_database")),
        "source_table": _text(row.get("source_table")),
        "table_row_number": _text(row.get("table_row_number")),
        "user_name": _text(row.get("user_name")) or _webcache_user_from_source_database(_text(row.get("source_database"))),
        "application": _text(row.get("application")),
        "application_package": _text(row.get("application_package")),
        "container_directory": _text(row.get("container_directory")),
        "attribution_method": _text(row.get("attribution_method")),
        "container_id": _text(row.get("container_id")),
        "container_name": _text(row.get("container_name")),
        "entry_id": _text(row.get("entry_id")),
        "entry_type": _text(row.get("entry_type")),
        "url": _text(row.get("url")),
        "host": _text(row.get("host")),
        "cache_file": _text(row.get("cache_file")),
        "file_name": _text(row.get("file_name")),
        "content_type": _text(row.get("content_type")),
        "http_status": _text(row.get("http_status")),
        "created_utc": _timestamp(row.get("created_utc")),
        "accessed_utc": _timestamp(row.get("accessed_utc")),
        "modified_utc": _timestamp(row.get("modified_utc")),
        "expires_utc": _timestamp(row.get("expires_utc")),
        "synced_utc": _timestamp(row.get("synced_utc")),
        "request_headers": _text(row.get("request_headers")),
        "response_headers": _text(row.get("response_headers")),
        "raw_metadata_json": _text(row.get("raw_metadata_json")),
    }


def webcache_file_access_row_from_entry(entry: dict[str, Any]) -> dict[str, Any] | None:
    url = _text(entry.get("url"))
    local_path = _local_path_from_file_url(url)
    if not url or local_path is None:
        return None
    return {
        "id": str(uuid.uuid4()),
        "case_id": entry["case_id"],
        "computer_id": entry["computer_id"],
        "image_id": entry["image_id"],
        "tool_output_id": entry["tool_output_id"],
        "tool_name": entry["tool_name"],
        "source_csv": entry["source_csv"],
        "row_number": entry["row_number"],
        "source_webcache_entry_id": entry["id"],
        "source_database": entry.get("source_database"),
        "source_table": entry.get("source_table"),
        "user_name": entry.get("user_name"),
        "application": entry.get("application"),
        "application_package": entry.get("application_package"),
        "container_directory": entry.get("container_directory"),
        "attribution_method": entry.get("attribution_method"),
        "container_name": entry.get("container_name"),
        "entry_id": entry.get("entry_id"),
        "url": url,
        "local_path": local_path,
        "normalized_path": _normalize_local_file_path(local_path),
        "cache_file": entry.get("cache_file"),
        "file_name": entry.get("file_name"),
        "created_utc": entry.get("created_utc"),
        "accessed_utc": entry.get("accessed_utc"),
        "modified_utc": entry.get("modified_utc"),
        "expires_utc": entry.get("expires_utc"),
        "synced_utc": entry.get("synced_utc"),
        "raw_metadata_json": entry.get("raw_metadata_json"),
    }


def _local_path_from_file_url(url: str | None) -> str | None:
    if not url or "file://" not in url.lower():
        return None
    match = re.search(r"(?i)file://[^\s\"'<>]+", url)
    if not match:
        return None
    url = match.group(0)
    parsed = urlparse(url)
    path = unquote(parsed.path or "")
    if parsed.netloc and parsed.netloc.lower() != "localhost":
        return f"//{parsed.netloc}{path}".replace("/", "\\")
    if re.match(r"^/[A-Za-z]:/", path):
        path = path[1:]
    return path.replace("/", "\\") if path else None


def _normalize_local_file_path(path: str) -> str:
    return path.replace("\\", "/").lower()


def _webcache_user_from_source_database(source_database: str | None) -> str | None:
    if not source_database:
        return None
    normalized = source_database.replace("\\", "/")
    match = re.search(r"/WebCache/([^/]+)/AppData/Local/Microsoft/Windows/WebCache/", normalized, re.IGNORECASE)
    if match:
        return match.group(1)
    match = re.search(r"/Users/([^/]+)/AppData/Local/Microsoft/Windows/WebCache/", normalized, re.IGNORECASE)
    return match.group(1) if match else None


def _office_version_from_parts(parts: list[str]) -> str | None:
    for index, part in enumerate(parts[:-1]):
        if part.lower() == "office" and index + 1 < len(parts):
            return parts[index + 1]
    return None


def _office_application_from_parts(parts: list[str], office_version: str | None) -> str | None:
    if not office_version:
        return None
    for index, part in enumerate(parts[:-1]):
        if part == office_version and index + 1 < len(parts):
            return parts[index + 1]
    return None


def _office_bool_value(value_name: str | None, value_data: str | None, expected_name: str) -> str | None:
    if (value_name or "").lower() != expected_name:
        return None
    parsed = _registry_numeric_value(value_data)
    if parsed is None:
        text = (value_data or "").strip().lower()
        if text in {"true", "yes"}:
            return "true"
        if text in {"false", "no"}:
            return "false"
        return None
    return "true" if parsed != 0 else "false"


def _office_trust_flags(row: dict[str, Any]) -> str | None:
    value_name = _text(row.get("value_name")) or ""
    value_data = _text(row.get("value_data")) or ""
    notes = _text(row.get("notes")) or ""
    text = " ".join([value_name, value_data, notes]).lower()
    flags: list[str] = []
    if any(token in text for token in ("edit", "editing", "enable editing")):
        flags.append("editing")
    if any(token in text for token in ("macro", "vba", "script", "activex", "content")):
        flags.append("macros_or_scripts")
    return ";".join(flags) if flags else None


def _office_flag_contains(flags: str | None, token: str) -> str | None:
    if not flags:
        return None
    return "true" if token in flags else "false"


def _registry_numeric_value(value: str | None) -> int | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    first = text.split(" ", 1)[0].strip()
    try:
        return int(first, 0)
    except ValueError:
        return None


def _taskbar_feature_from_key(key_path: str) -> str | None:
    parts = [part for part in re.split(r"[\\/]+", key_path) if part]
    for marker in ("FeatureUsage", "Taskband"):
        for index, part in enumerate(parts[:-1]):
            if part.lower() == marker.lower() and index + 1 < len(parts):
                return parts[index + 1]
    return parts[-1] if parts else None


def _text(value: Any) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


def _timestamp(value: Any) -> str | None:
    text = _text(value)
    if text is None:
        return None
    return normalize_timestamp(text) or text


def _int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _first_text(row: dict[str, Any], *names: str) -> str | None:
    for name in names:
        value = _text(row.get(name))
        if value is not None:
            return value
    return None


def _first_timestamp(row: dict[str, Any], *names: str) -> str | None:
    for name in names:
        value = _timestamp(row.get(name))
        if value is not None:
            return value
    return None


def _extra_values(row: dict[str, Any]) -> list[Any]:
    values = row.get(None)
    if isinstance(values, list):
        return values
    return []


def _extra_text(values: list[Any], index: int) -> str | None:
    if index >= len(values):
        return None
    return _text(values[index])


def _windows_search_extra_name(index: int) -> str | None:
    return {
        0: "System_Size",
        1: "System_ComputerName",
        2: "System_FileOwner",
        3: "IndexedContent",
    }.get(index)


def _windows_search_property_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    source_table: str,
    source_record_id: str,
    row_number: int,
    work_id: str | None,
    item_path: str | None,
    timestamp: str | None,
    property_name: str,
    property_value: str,
    normalized_name: str | None,
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "source_table": source_table,
        "source_record_id": source_record_id,
        "row_number": row_number,
        "work_id": work_id,
        "item_path": item_path,
        "property_name": property_name,
        "property_value": property_value,
        "normalized_name": normalized_name,
        "timestamp": timestamp,
        "created_at": utc_now(),
    }


def _srum_record_type(source_csv: Path) -> str:
    name = source_csv.name.lower()
    for marker, (record_type, _) in _SRUM_PROVIDER_MARKERS:
        if marker in name:
            return record_type
    return source_csv.stem


def _srum_provider_name(source_csv: Path) -> str:
    name = source_csv.name.lower()
    for marker, (_, provider_name) in _SRUM_PROVIDER_MARKERS:
        if marker in name:
            return provider_name
    return ""


def _srum_provider_guid(source_csv: Path) -> str:
    name = source_csv.name.lower()
    for marker, provider_guid in _SRUM_PROVIDER_GUID_MARKERS:
        if marker in name:
            return provider_guid
    match = re.search(r"\{([^}]+)\}", source_csv.name)
    return match.group(1).lower() if match else ""


_SRUM_PROVIDER_MARKERS = (
    ("apptimelineprovider", ("app_timeline_provider", "App Timeline Provider")),
    ("vfuprov", ("vfu_provider", "Vfuprov")),
    ("networkusages", ("network_usage", "Windows Network Data Usage Monitor")),
    ("networkusage", ("network_usage", "Windows Network Data Usage Monitor")),
    ("taggedenergy", ("tagged_energy", "Tagged Energy Provider")),
    ("pushnotifications", ("push_notifications", "Windows Push Notifications Provider")),
    ("pushnotification", ("push_notifications", "Windows Push Notifications Provider")),
    ("appresourceuseinfo", ("app_resource_usage", "Application Resource Usage Provider")),
    ("appresource", ("app_resource_usage", "Application Resource Usage Provider")),
    ("energyestimation", ("energy_estimation", "Energy Estimation Provider")),
    ("networkconnections", ("network_connectivity", "Windows Network Connectivity Usage Monitor")),
    ("networkconnection", ("network_connectivity", "Windows Network Connectivity Usage Monitor")),
    ("energyusage", ("energy_usage", "Energy Usage Provider")),
)

_SRUM_PROVIDER_GUID_MARKERS = (
    ("apptimelineprovider", "5c8cf1c7-7257-4f13-b223-970ef5939312"),
    ("vfuprov", "7acbbaa3-d029-4be4-9a7a-0885927f1d8f"),
    ("networkusage", "973f5d5c-1d90-4944-be8e-24b94231a174"),
    ("taggedenergy", "b6d82af1-f780-4e17-8077-6cb9ad8a6fc4"),
    ("pushnotification", "d10ca2fe-6fcf-4f6d-848e-b2e99266fa86"),
    ("appresource", "d10ca2fe-6fcf-4f6d-848e-b2e99266fa89"),
    ("energyestimation", "da73fb89-2bea-4ddc-86b8-6e048c6da477"),
    ("networkconnection", "dd6636c4-8929-4683-974e-22c046a43763"),
    ("energyusage", "fee4e14f-02a9-4550-b5ce-5fa2da202e37"),
)


def normalized_windows_error_report_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "source_file": _text(row.get("source_file")),
        "source_name": _text(row.get("source_name")),
        "report_folder": _text(row.get("report_folder")),
        "event_type": _text(row.get("event_type")),
        "event_time_utc": _timestamp(row.get("event_time_utc")),
        "upload_time_utc": _timestamp(row.get("upload_time_utc")),
        "report_type": _text(row.get("report_type")),
        "consent": _text(row.get("consent")),
        "report_status": _text(row.get("report_status")),
        "report_identifier": _text(row.get("report_identifier")),
        "integrator_report_identifier": _text(row.get("integrator_report_identifier")),
        "app_name": _text(row.get("app_name")),
        "original_filename": _text(row.get("original_filename")),
        "target_app_id": _text(row.get("target_app_id")),
        "target_app_version": _text(row.get("target_app_version")),
        "fault_module_name": _text(row.get("fault_module_name")),
        "fault_module_version": _text(row.get("fault_module_version")),
        "exception_code": _text(row.get("exception_code")),
        "exception_offset": _text(row.get("exception_offset")),
        "is_fatal": _text(row.get("is_fatal")),
        "bucket_id": _text(row.get("bucket_id")),
        "legacy_bucket_id": _text(row.get("legacy_bucket_id")),
        "ui_path": _text(row.get("ui_path")),
        "loaded_modules_json": _text(row.get("loaded_modules_json")),
        "signatures_json": _text(row.get("signatures_json")),
        "dynamic_signatures_json": _text(row.get("dynamic_signatures_json")),
        "ui_json": _text(row.get("ui_json")),
        "raw_json": _text(row.get("raw_json")),
        "created_at": utc_now(),
    }


def normalized_windows_defender_event_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "source_file": _text(row.get("source_file")),
        "source_name": _text(row.get("source_name")),
        "artifact_type": _text(row.get("artifact_type")),
        "line_number": _text(row.get("line_number")),
        "event_time_utc": _timestamp(row.get("event_time_utc")),
        "event_type": _text(row.get("event_type")),
        "component": _text(row.get("component")),
        "severity": _text(row.get("severity")),
        "threat_name": _text(row.get("threat_name")),
        "action": _text(row.get("action")),
        "path": _text(row.get("path")),
        "resource": _text(row.get("resource")),
        "message": _text(row.get("message")),
        "file_size": _text(row.get("file_size")),
        "modified_time_utc": _timestamp(row.get("modified_time_utc")),
        "sha256_first_mb": _text(row.get("sha256_first_mb")),
        "raw_json": _text(row.get("raw_json")),
        "created_at": utc_now(),
    }


def normalized_archive_entry_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "archive_path": _text(row.get("archive_path")),
        "archive_file_name": _text(row.get("archive_file_name")),
        "archive_extension": _text(row.get("archive_extension")),
        "archive_file_size": _text(row.get("archive_file_size")),
        "archive_modified_time_utc": _timestamp(row.get("archive_modified_time_utc")),
        "archive_status": _text(row.get("archive_status")),
        "archive_error": _text(row.get("archive_error")),
        "member_path": _text(row.get("member_path")),
        "member_file_name": _text(row.get("member_file_name")),
        "member_extension": _text(row.get("member_extension")),
        "member_size": _text(row.get("member_size")),
        "member_compressed_size": _text(row.get("member_compressed_size")),
        "member_crc": _text(row.get("member_crc")),
        "member_modified_time_utc": _timestamp(row.get("member_modified_time_utc")),
        "member_is_dir": _text(row.get("member_is_dir")),
        "member_is_encrypted": _text(row.get("member_is_encrypted")),
        "nested_evidence_format": _text(row.get("nested_evidence_format")),
        "multipart_set_id": _text(row.get("multipart_set_id")),
        "multipart_part_number": _text(row.get("multipart_part_number")),
        "multipart_part_count": _text(row.get("multipart_part_count")),
        "multipart_is_first_part": _text(row.get("multipart_is_first_part")),
        "multipart_related_parts": _text(row.get("multipart_related_parts")),
        "created_at": utc_now(),
    }


def normalized_cloud_server_event_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "provider": _text(row.get("provider")),
        "service": _text(row.get("service")),
        "event_type": _text(row.get("event_type")),
        "event_time_utc": _timestamp(row.get("event_time_utc")),
        "actor": _text(row.get("actor")),
        "actor_id": _text(row.get("actor_id")),
        "actor_ip": _text(row.get("actor_ip")),
        "target": _text(row.get("target")),
        "target_id": _text(row.get("target_id")),
        "target_type": _text(row.get("target_type")),
        "operation": _text(row.get("operation")),
        "result": _text(row.get("result")),
        "user_agent": _text(row.get("user_agent")),
        "client_app": _text(row.get("client_app")),
        "file_name": _text(row.get("file_name")),
        "file_path": _text(row.get("file_path")),
        "url": _text(row.get("url")),
        "message_id": _text(row.get("message_id")),
        "conversation_id": _text(row.get("conversation_id")),
        "content_sha256": _text(row.get("content_sha256")),
        "content_length": _int(row.get("content_length")),
        "opensearch_document_id": _text(row.get("opensearch_document_id")),
        "_opensearch_content_text": _text(row.get("_opensearch_content_text")),
        "source_log_type": _text(row.get("source_log_type")),
        "source_record_id": _text(row.get("source_record_id")),
        "raw_fields_json": _text(row.get("raw_fields_json")) or "{}",
        "created_at": utc_now(),
    }


def normalized_memory_string_hit_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "source_artifact_type": _text(row.get("source_artifact_type")),
        "source_path": _text(row.get("source_path")),
        "scanned_path": _text(row.get("scanned_path")),
        "decompressed_path": _text(row.get("decompressed_path")),
        "scanner": _text(row.get("scanner")),
        "encoding": _text(row.get("encoding")),
        "hit_category": _text(row.get("hit_category")),
        "matched_term": _text(row.get("matched_term")),
        "string_value": _text(row.get("string_value")),
        "string_sha256": _text(row.get("string_sha256")),
        "string_length": _int(row.get("string_length")),
        "offset": _text(row.get("offset")),
        "context_hint": _text(row.get("context_hint")),
        "created_at": utc_now(),
    }


def _row_json(row: dict[str, Any]) -> str:
    normalized = {
        str(key) if key is not None else "_extra": value
        for key, value in row.items()
    }
    return json.dumps(normalized, sort_keys=True)


def _sha256_text(value: str) -> str:
    if not value:
        return ""
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _content_document_id(case_id: str, content: str) -> str:
    content_hash = hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()
    return hashlib.sha256(f"{case_id}|content|{content_hash}".encode("utf-8", errors="replace")).hexdigest()


def _is_windows_search_content_property(property_name: str, normalized_name: str | None) -> bool:
    if normalized_name == "IndexedContent":
        return True
    return property_name in {
        "System_Search_Contents",
        "System_FullText",
        "System_Contents",
        "System_Comment",
        "System_Document_Summary",
        "System_Document_Text",
        "System_Message_Body",
    }


def _url_host(value: str | None) -> str:
    if not value:
        return ""
    try:
        return urlparse(value).netloc
    except ValueError:
        return ""
