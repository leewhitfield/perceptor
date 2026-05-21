from __future__ import annotations

import csv
import struct
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .sam import RegistryKeyRecord, registry_path, scan_registry_keys


REGISTRY_ARTIFACT_FIELDS = [
    "source_path",
    "hive_type",
    "user_profile",
    "user_sid",
    "artifact",
    "category",
    "key_path",
    "key_last_write_utc",
    "event_time_utc",
    "recentdocs_time_utc",
    "recentdocs_extension_time_utc",
    "mru_position",
    "recentdocs_mru_position",
    "recentdocs_extension_mru_position",
    "is_most_recent",
    "value_name",
    "value_type",
    "value_data",
    "display_name",
    "normalized_path",
    "value_data_hex",
    "transaction_logs_detected",
    "transaction_logs_applied",
    "transaction_log_paths",
    "notes",
]
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
REG_TYPES = {
    0: "REG_NONE",
    1: "REG_SZ",
    2: "REG_EXPAND_SZ",
    3: "REG_BINARY",
    4: "REG_DWORD",
    5: "REG_DWORD_BIG_ENDIAN",
    6: "REG_LINK",
    7: "REG_MULTI_SZ",
    8: "REG_RESOURCE_LIST",
    9: "REG_FULL_RESOURCE_DESCRIPTOR",
    10: "REG_RESOURCE_REQUIREMENTS_LIST",
    11: "REG_QWORD",
}


@dataclass(frozen=True)
class ArtifactRule:
    artifact: str
    category: str
    hive_types: tuple[str, ...]
    path_contains: tuple[str, ...]
    recursive: bool = False


RULES = [
    ArtifactRule("current_control_set", "system", ("system",), ("select",)),
    ArtifactRule("computer_name", "system", ("system",), ("currentcontrolset", "control", "computername"), recursive=True),
    ArtifactRule("time_zone", "system", ("system",), ("currentcontrolset", "control", "timezoneinformation")),
    ArtifactRule("shutdown_time", "system", ("system",), ("currentcontrolset", "control", "windows")),
    ArtifactRule("install_time_source_os", "system", ("system",), ("setup", "source os"), recursive=True),
    ArtifactRule("usb_device_history", "usb", ("system",), ("currentcontrolset", "enum", "usbstor"), recursive=True),
    ArtifactRule("usb_device_history", "usb", ("system",), ("currentcontrolset", "enum", "usb"), recursive=True),
    ArtifactRule("usb_device_history", "usb", ("system",), ("currentcontrolset", "enum", "scsi"), recursive=True),
    ArtifactRule("usb_device_history", "usb", ("system",), ("currentcontrolset", "enum", "hid"), recursive=True),
    ArtifactRule("usb_volume_history", "usb", ("system",), ("currentcontrolset", "enum", "swd", "wpdbusenum"), recursive=True),
    ArtifactRule("usb_volume_name", "usb", ("software",), ("microsoft", "windows portable devices", "devices"), recursive=True),
    ArtifactRule("usb_volume_info_cache", "usb", ("software",), ("microsoft", "windows search", "volumeinfocache"), recursive=True),
    ArtifactRule("usb_mountpoints2", "usb", ("ntuser",), ("explorer", "mountpoints2"), recursive=True),
    ArtifactRule(
        "usb_device_migration",
        "usb",
        ("system",),
        ("setup", "upgrade", "pnp", "currentcontrolset", "control", "devicemigration", "devices"),
        recursive=True,
    ),
    ArtifactRule("mounted_devices", "usb", ("system",), ("mounteddevices",), recursive=True),
    ArtifactRule("shimcache", "execution", ("system",), ("currentcontrolset", "control", "session manager", "appcompatcache")),
    ArtifactRule("bam", "execution", ("system",), ("currentcontrolset", "services", "bam", "state", "usersettings"), recursive=True),
    ArtifactRule("dam", "execution", ("system",), ("currentcontrolset", "services", "dam", "state", "usersettings"), recursive=True),
    ArtifactRule("services", "persistence", ("system",), ("currentcontrolset", "services"), recursive=True),
    ArtifactRule("scheduled_task_cache", "persistence", ("software",), ("microsoft", "windows nt", "currentversion", "schedule", "taskcache"), recursive=True),
    ArtifactRule("wmi_persistence", "persistence", ("software",), ("microsoft", "wbem", "cimom"), recursive=True),
    ArtifactRule("com_autostart", "persistence", ("software", "ntuser", "usrclass"), ("microsoft", "windows", "currentversion", "explorer", "shellexecutehooks"), recursive=True),
    ArtifactRule("com_autostart", "persistence", ("software", "ntuser", "usrclass"), ("microsoft", "windows", "currentversion", "explorer", "browser helper objects"), recursive=True),
    ArtifactRule("com_autostart", "persistence", ("software", "ntuser", "usrclass"), ("microsoft", "windows", "currentversion", "explorer", "shelliconoverlayidentifiers"), recursive=True),
    ArtifactRule("com_autostart", "persistence", ("software", "ntuser", "usrclass"), ("microsoft", "windows", "currentversion", "shellserviceobjectdelayload"), recursive=True),
    ArtifactRule("com_autostart", "persistence", ("software", "ntuser", "usrclass"), ("microsoft", "internet explorer", "toolbar"), recursive=True),
    ArtifactRule("com_autostart", "persistence", ("software", "ntuser", "usrclass"), ("microsoft", "internet explorer", "extensions"), recursive=True),
    ArtifactRule("com_registration", "software", ("software", "ntuser", "usrclass"), ("classes", "clsid"), recursive=True),
    ArtifactRule("com_registration", "software", ("software", "ntuser", "usrclass"), ("classes", "appid"), recursive=True),
    ArtifactRule("applocker_policy", "security_policy", ("software",), ("policies", "microsoft", "windows", "srpv2"), recursive=True),
    ArtifactRule("applocker_policy", "security_policy", ("system",), ("currentcontrolset", "control", "srp"), recursive=True),
    ArtifactRule("wdac_policy", "security_policy", ("system",), ("currentcontrolset", "control", "ci"), recursive=True),
    ArtifactRule("wdac_policy", "security_policy", ("software",), ("policies", "microsoft", "windows", "deviceguard"), recursive=True),
    ArtifactRule("wdac_policy", "security_policy", ("software",), ("microsoft", "windows", "currentversion", "deviceguard"), recursive=True),
    ArtifactRule("startup_approved", "persistence", ("software", "ntuser"), ("microsoft", "windows", "currentversion", "explorer", "startupapproved"), recursive=True),
    ArtifactRule("winlogon_persistence", "persistence", ("software",), ("microsoft", "windows nt", "currentversion", "winlogon"), recursive=True),
    ArtifactRule("image_file_execution_options", "persistence", ("software",), ("microsoft", "windows nt", "currentversion", "image file execution options"), recursive=True),
    ArtifactRule("appinit_dlls", "persistence", ("software",), ("microsoft", "windows nt", "currentversion", "windows")),
    ArtifactRule("install_time_software", "system", ("software",), ("microsoft", "windows nt", "currentversion")),
    ArtifactRule("autostart", "execution", ("software", "ntuser"), ("microsoft", "windows", "currentversion", "run")),
    ArtifactRule("autostart", "execution", ("software", "ntuser"), ("microsoft", "windows", "currentversion", "runonce")),
    ArtifactRule("installed_applications", "software", ("software",), ("microsoft", "windows", "currentversion", "uninstall"), recursive=True),
    ArtifactRule("connected_networks", "network", ("software",), ("microsoft", "windows nt", "currentversion", "networklist"), recursive=True),
    ArtifactRule("network_interfaces", "network", ("system",), ("currentcontrolset", "services", "tcpip", "parameters", "interfaces"), recursive=True),
    ArtifactRule("network_cards", "network", ("software",), ("microsoft", "windows nt", "currentversion", "networkcards"), recursive=True),
    ArtifactRule("cloud_onedrive_account", "cloud", ("ntuser",), ("microsoft", "onedrive", "accounts"), recursive=True),
    ArtifactRule("cloud_onedrive_sync_engine", "cloud", ("ntuser",), ("syncengines", "providers", "onedrive"), recursive=True),
    ArtifactRule("cloud_google_drivefs", "cloud", ("ntuser",), ("google", "drivefs"), recursive=True),
    ArtifactRule("cloud_dropbox_syncroot", "cloud", ("software", "ntuser"), ("explorer", "syncrootmanager", "dropbox"), recursive=True),
    ArtifactRule("cloud_icloud", "cloud", ("software", "ntuser"), ("apple inc.", "icloud"), recursive=True),
    ArtifactRule("ras_phonebook_registry", "network", ("ntuser",), ("microsoft", "ras phonebook"), recursive=True),
    ArtifactRule("ras_connection_manager", "network", ("software", "system", "ntuser"), ("remoteaccess"), recursive=True),
    ArtifactRule("ras_connection_manager", "network", ("software", "system", "ntuser"), ("rasman"), recursive=True),
    ArtifactRule("capability_access_manager", "privacy", ("software", "ntuser"), ("capabilityaccessmanager", "consentstore"), recursive=True),
    ArtifactRule("cloud_account_details", "account", ("sam",), ("domains", "account", "users"), recursive=True),
    ArtifactRule("amcache", "execution", ("amcache",), ("root",), recursive=True),
    ArtifactRule("wordwheel_query", "user_activity", ("ntuser",), ("explorer", "wordwheelquery")),
    ArtifactRule("typed_paths", "user_activity", ("ntuser",), ("explorer", "typedpaths")),
    ArtifactRule("recentdocs", "user_activity", ("ntuser",), ("explorer", "recentdocs"), recursive=True),
    ArtifactRule("mui_cache", "user_activity", ("usrclass",), ("muicache",), recursive=True),
    ArtifactRule("office_trusted_locations", "user_activity", ("ntuser",), ("microsoft", "office", "trusted locations"), recursive=True),
    ArtifactRule("office_trusted_documents", "user_activity", ("ntuser",), ("microsoft", "office", "trusted documents"), recursive=True),
    ArtifactRule("office_recent_docs", "user_activity", ("ntuser",), ("microsoft", "office"), recursive=True),
    ArtifactRule("outlook_secure_temp", "email", ("ntuser",), ("outlook", "security"), recursive=True),
    ArtifactRule("common_dialog", "user_activity", ("ntuser",), ("explorer", "comdlg32"), recursive=True),
    ArtifactRule("runmru", "user_activity", ("ntuser",), ("explorer", "runmru")),
    ArtifactRule("userassist", "execution", ("ntuser",), ("explorer", "userassist"), recursive=True),
    ArtifactRule("taskbar_usage", "user_activity", ("ntuser",), ("explorer", "taskband"), recursive=True),
    ArtifactRule("taskbar_feature_usage", "user_activity", ("ntuser",), ("explorer", "featureusage"), recursive=True),
    ArtifactRule("shellbags", "user_activity", ("ntuser", "usrclass"), ("shell", "bagmru"), recursive=True),
    ArtifactRule("shellbags", "user_activity", ("ntuser", "usrclass"), ("shell", "bags"), recursive=True),
]


def parse_registry_artifacts_to_csv(sources: list[Path], output: Path) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    csv_path = output / "RegistryArtifactParser.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=REGISTRY_ARTIFACT_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for source in _iter_hive_files(sources):
            try:
                rows = parse_registry_artifacts(source)
            except Exception as exc:
                writer.writerow(
                    {
                        "source_path": str(source),
                        "hive_type": infer_hive_type(source),
                        "artifact": "parser_error",
                        "category": "error",
                        "notes": str(exc),
                    }
                )
                continue
            for row in rows:
                writer.writerow(row)
    return csv_path


def parse_registry_artifacts(path: Path) -> list[dict[str, str | None]]:
    records = scan_registry_keys(path.read_bytes())
    hive_type = infer_hive_type(path)
    user_profile = infer_user_profile(path)
    log_status = _transaction_log_status(path)
    paths = {offset: registry_path(records, offset) for offset in records}
    current_control_set = _current_control_set(records, paths)
    rows: list[dict[str, str | None]] = []
    for offset, record in records.items():
        key_path = _normalize_control_set_path(paths[offset], current_control_set)
        rules = _matching_rules(hive_type, key_path)
        if not rules:
            continue
        mru_rank = _mru_rank(record, rules)
        recentdocs_scope = _recentdocs_scope(key_path)
        for value_name, value_type in record.values.items():
            raw = record.value_data.get(value_name, b"")
            value_data = decode_registry_value(value_type, raw)
            if _skip_noisy_value(rules, value_name, value_data, key_path):
                continue
            for rule in rules:
                display_name = _display_name_for_value(rule.artifact, value_type, raw, value_data)
                user_sid = _user_sid_for_artifact(rule.artifact, key_path)
                normalized_path = _normalized_path_for_artifact(rule.artifact, value_name)
                recentdocs_time = _recentdocs_time_for_value(rule.artifact, recentdocs_scope, record, value_name)
                recentdocs_extension_time = _recentdocs_extension_time_for_value(
                    rule.artifact, recentdocs_scope, record, value_name
                )
                event_time = _event_time_for_value(rule.artifact, record, value_name)
                if rule.artifact == "recentdocs":
                    event_time = recentdocs_time or recentdocs_extension_time
                position = mru_rank.get(value_name)
                rows.append(
                    {
                        "source_path": str(path),
                        "hive_type": hive_type,
                        "user_profile": user_profile,
                        "user_sid": user_sid,
                        "artifact": rule.artifact,
                        "category": rule.category,
                        "key_path": key_path,
                        "key_last_write_utc": record.last_write_utc,
                        "event_time_utc": event_time,
                        "recentdocs_time_utc": recentdocs_time,
                        "recentdocs_extension_time_utc": recentdocs_extension_time,
                        "mru_position": str(position) if position is not None else None,
                        "recentdocs_mru_position": (
                            str(position) if rule.artifact == "recentdocs" and recentdocs_scope == "root" and position is not None else None
                        ),
                        "recentdocs_extension_mru_position": (
                            str(position) if rule.artifact == "recentdocs" and recentdocs_scope == "extension" and position is not None else None
                        ),
                        "is_most_recent": "true" if position == 1 else "false" if position is not None else None,
                        "value_name": value_name or "(default)",
                        "value_type": REG_TYPES.get(value_type, f"REG_{value_type}"),
                        "value_data": display_name or value_data,
                        "display_name": display_name,
                        "normalized_path": normalized_path,
                        "value_data_hex": raw[:256].hex(),
                        "transaction_logs_detected": "true" if log_status["detected"] else "false",
                        "transaction_logs_applied": "false",
                        "transaction_log_paths": ";".join(log_status["paths"]),
                        "notes": _join_notes(
                            _notes_for_value(rule.artifact, value_name, value_type, raw, value_data),
                            _transaction_log_note(log_status),
                        ),
                    }
                )
    return rows


def _iter_hive_files(sources: list[Path]) -> list[Path]:
    files: list[Path] = []
    for source in sources:
        if source.is_file():
            files.append(source)
        elif source.is_dir():
            for candidate in source.rglob("*"):
                if candidate.is_file() and infer_hive_type(candidate) != "unknown":
                    files.append(candidate)
    return sorted(files)


def infer_hive_type(path: Path) -> str:
    name = path.name.lower()
    if name == "system":
        return "system"
    if name == "software":
        return "software"
    if name == "security":
        return "security"
    if name == "sam":
        return "sam"
    if name == "ntuser.dat":
        return "ntuser"
    if name == "usrclass.dat":
        return "usrclass"
    if name == "amcache.hve":
        return "amcache"
    return "unknown"


def infer_user_profile(path: Path) -> str | None:
    parts = path.parts
    lowered = [part.lower() for part in parts]
    if "ntuser" in lowered:
        index = lowered.index("ntuser")
        if index + 1 < len(parts):
            return parts[index + 1]
    if "usrclass" in lowered:
        index = lowered.index("usrclass")
        if index + 1 < len(parts):
            return parts[index + 1]
    if "users" not in lowered:
        if path.name.lower() == "ntuser.dat":
            return path.parent.name
        if path.name.lower() == "usrclass.dat":
            for marker in ("appdata", "local", "microsoft", "windows"):
                if marker in lowered:
                    index = lowered.index(marker)
                    if index > 0:
                        return parts[index - 1]
            return path.parent.name
        return None
    index = lowered.index("users")
    if index + 1 < len(parts):
        return parts[index + 1]
    return None


def _transaction_log_status(path: Path) -> dict[str, object]:
    candidates = [
        path.with_name(path.name + ".LOG"),
        path.with_name(path.name + ".LOG1"),
        path.with_name(path.name + ".LOG2"),
        path.with_name(path.name.lower() + ".LOG"),
        path.with_name(path.name.lower() + ".LOG1"),
        path.with_name(path.name.lower() + ".LOG2"),
    ]
    seen: set[Path] = set()
    paths: list[str] = []
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        if candidate.exists():
            paths.append(str(candidate))
    return {"detected": bool(paths), "paths": paths}


def _transaction_log_note(log_status: dict[str, object]) -> str | None:
    if not log_status["detected"]:
        return None
    return "registry transaction logs detected but not applied by the internal parser; values may reflect the unrecovered base hive"


def _join_notes(*notes: str | None) -> str | None:
    parts = [note for note in notes if note]
    return "; ".join(parts) if parts else None


def decode_registry_value(value_type: int, raw: bytes) -> str:
    if value_type in {1, 2}:
        return _decode_utf16(raw).rstrip("\x00")
    if value_type == 7:
        return ";".join(part for part in _decode_utf16(raw).split("\x00") if part)
    if value_type == 4 and len(raw) >= 4:
        value = struct.unpack_from("<I", raw)[0]
        return f"{value} (0x{value:08X})"
    if value_type == 5 and len(raw) >= 4:
        value = struct.unpack_from(">I", raw)[0]
        return f"{value} (0x{value:08X})"
    if value_type == 11 and len(raw) >= 8:
        value = struct.unpack_from("<Q", raw)[0]
        return f"{value} (0x{value:016X})"
    if len(raw) == 8:
        filetime = _filetime_to_iso(struct.unpack_from("<Q", raw)[0])
        if filetime:
            return filetime
    text = _decode_utf16(raw).strip("\x00")
    if text and sum(char.isprintable() for char in text) / max(len(text), 1) > 0.8:
        return text
    return raw[:256].hex()


def _decode_utf16(raw: bytes) -> str:
    try:
        return raw.decode("utf-16-le", errors="replace")
    except UnicodeDecodeError:
        return raw.decode("latin1", errors="replace")


def _filetime_to_iso(value: int) -> str | None:
    if not value or value in {0x7FFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}:
        return None
    try:
        timestamp = FILETIME_EPOCH + timedelta(microseconds=value // 10)
    except (OverflowError, ValueError):
        return None
    if timestamp.year < 1990 or timestamp.year > 2100:
        return None
    return timestamp.isoformat().replace("+00:00", "Z")


def _current_control_set(records: dict[int, RegistryKeyRecord], paths: dict[int, str]) -> str:
    for offset, path in paths.items():
        if path.lower().endswith("/select") or path.lower() == "select":
            raw = records[offset].value_data.get("Current")
            if raw and len(raw) >= 4:
                return f"ControlSet{struct.unpack_from('<I', raw)[0]:03d}"
    return "CurrentControlSet"


def _normalize_control_set_path(path: str, current_control_set: str) -> str:
    parts = path.split("/")
    return "/".join("CurrentControlSet" if part.lower() == current_control_set.lower() else part for part in parts)


def _matching_rules(hive_type: str, key_path: str) -> list[ArtifactRule]:
    key_parts = [part.lower() for part in key_path.split("/") if part]
    matches: list[ArtifactRule] = []
    for rule in RULES:
        if hive_type not in rule.hive_types:
            continue
        needle = [part.lower() for part in rule.path_contains]
        if _contains_sequence(key_parts, needle) and (rule.recursive or key_parts[-len(needle):] == needle):
            matches.append(rule)
    if any(rule.artifact == "outlook_secure_temp" for rule in matches):
        matches = [rule for rule in matches if rule.artifact != "office_recent_docs"]
    return matches


def _contains_sequence(parts: list[str], needle: list[str]) -> bool:
    if not needle:
        return True
    for index in range(0, len(parts) - len(needle) + 1):
        if all(expected in actual for actual, expected in zip(parts[index : index + len(needle)], needle)):
            return True
    return False


def _skip_noisy_value(rules: list[ArtifactRule], value_name: str, value_data: str, key_path: str = "") -> bool:
    artifacts = {rule.artifact for rule in rules}
    if artifacts & {"bam", "dam"} and value_name.lower() in {"version", "sequencenumber"}:
        return True
    if "usb_device_migration" in artifacts and not _is_usb_device_migration_evidence(
        key_path, value_name, value_data
    ):
        return True
    if "cloud_account_details" in artifacts:
        return value_name.lower() not in {
            "internetusername",
            "internetuid",
            "internetsid",
            "internetprovidername",
            "internetusermodified",
        }
    if artifacts & {"cloud_onedrive_account", "cloud_onedrive_sync_engine", "cloud_google_drivefs", "cloud_dropbox_syncroot", "cloud_icloud"}:
        return value_name.lower() not in {
            "(default)",
            "cid",
            "clientfirstsignintimestamp",
            "email",
            "lastsigninname",
            "lastsignintime",
            "librarytype",
            "mountpoint",
            "providerid",
            "resourceid",
            "sporesourceid",
            "tenantid",
            "tenantname",
            "urlnamespace",
            "usercid",
            "useremail",
            "userfolder",
            "usersyncroots",
            "value",
        }
    if "recentdocs" in artifacts and value_name in {"MRUList", "MRUListEx"}:
        return True
    if artifacts & {"office_trusted_locations", "office_trusted_documents", "taskbar_feature_usage", "mui_cache"}:
        return False
    if "outlook_secure_temp" in artifacts:
        return value_name.lower() not in {"outlooksecuretempfolder", "securetempfolder"}
    if "com_registration" in artifacts:
        lowered_name = value_name.lower()
        lowered_path = key_path.lower()
        if any(token in lowered_path for token in ("/inprocserver32", "/localserver32", "/treatas", "/scriptleturl")):
            return False
        return lowered_name not in {"", "(default)", "appid", "localizedstring", "threadingmodel"}
    if "office_recent_docs" in artifacts:
        lowered = value_name.lower()
        return "mru" not in lowered and "item" not in lowered and "file" not in lowered
    return value_name == "" and value_data == ""


def _is_usb_device_migration_evidence(key_path: str, value_name: str, value_data: str) -> bool:
    lowered_path = key_path.lower()
    normalized = lowered_path.strip("/")
    if not (
        normalized.startswith("root/setup/upgrade/pnp/currentcontrolset/control/devicemigration/devices/")
        or normalized.startswith("setup/upgrade/pnp/currentcontrolset/control/devicemigration/devices/")
    ):
        return False
    text = " ".join((key_path, value_name, value_data)).upper()
    return any(
        marker in text
        for marker in (
            "USBSTOR",
            "USB\\",
            "USB#",
            "SCSI\\",
            "SCSI#",
            "VID_",
            "SWD\\WPDBUSENUM",
            "SWD#WPDBUSENUM",
        )
    )


def _mru_rank(record: RegistryKeyRecord, rules: list[ArtifactRule] | None = None) -> dict[str, int]:
    artifacts = {rule.artifact for rule in rules or []}
    if "typed_paths" in artifacts:
        ranks: dict[str, int] = {}
        for value_name in record.values:
            lowered = value_name.lower()
            if not lowered.startswith("url"):
                continue
            try:
                ranks[value_name] = int(lowered[3:])
            except ValueError:
                continue
        if ranks:
            return ranks
    raw = record.value_data.get("MRUList") or record.value_data.get("MRUListEx")
    if not raw:
        return {}
    if "MRUListEx" in record.value_data:
        order = []
        for index in range(0, len(raw), 4):
            if index + 4 > len(raw):
                break
            value = struct.unpack_from("<I", raw, index)[0]
            if value == 0xFFFFFFFF:
                break
            order.append(str(value))
        return {name: position for position, name in enumerate(order, start=1)}
    order_text = decode_registry_value(record.values.get("MRUList", 1), raw)
    return {name: position for position, name in enumerate(order_text, start=1)}


def _event_time_for_value(artifact: str, record: RegistryKeyRecord, value_name: str) -> str | None:
    if artifact in {"bam", "dam"}:
        raw = record.value_data.get(value_name, b"")
        if len(raw) >= 8:
            return _filetime_to_iso(struct.unpack_from("<Q", raw)[0])
    if artifact == "typed_paths":
        try:
            if value_name.lower().startswith("url") and int(value_name[3:]) == 1:
                return record.last_write_utc
        except ValueError:
            return None
    if artifact in {
        "runmru",
        "wordwheel_query",
        "recentdocs",
        "office_recent_docs",
        "common_dialog",
    }:
        rank = _mru_rank(record)
        if rank.get(value_name) == 1:
            return record.last_write_utc
    return None


def _user_sid_for_artifact(artifact: str, key_path: str) -> str | None:
    if artifact not in {"bam", "dam"}:
        return None
    for part in reversed([part for part in key_path.split("/") if part]):
        if part.upper().startswith("S-1-"):
            return part
    return None


def _normalized_path_for_artifact(artifact: str, value_name: str) -> str | None:
    if artifact not in {"bam", "dam"} or not value_name:
        return None
    path = value_name.replace("/", "\\")
    while "\\\\" in path:
        path = path.replace("\\\\", "\\")
    if path.startswith("\\Device\\HarddiskVolume"):
        remainder = path[len("\\Device\\") :]
        volume, sep, rest = remainder.partition("\\")
        return f"{volume}:\\{rest}" if sep else f"{volume}:"
    return path


def _recentdocs_scope(key_path: str) -> str | None:
    lowered = [part.lower() for part in key_path.split("/") if part]
    for index, part in enumerate(lowered):
        if part == "recentdocs":
            return "root" if index == len(lowered) - 1 else "extension"
    return None


def _recentdocs_time_for_value(
    artifact: str,
    scope: str | None,
    record: RegistryKeyRecord,
    value_name: str,
) -> str | None:
    if artifact != "recentdocs" or scope != "root":
        return None
    return record.last_write_utc if _mru_rank(record).get(value_name) == 1 else None


def _recentdocs_extension_time_for_value(
    artifact: str,
    scope: str | None,
    record: RegistryKeyRecord,
    value_name: str,
) -> str | None:
    if artifact != "recentdocs" or scope != "extension":
        return None
    return record.last_write_utc if _mru_rank(record).get(value_name) == 1 else None


def _display_name_for_value(artifact: str, value_type: int, raw: bytes, value_data: str) -> str | None:
    if artifact in {"bam", "dam"}:
        return None
    if artifact == "mui_cache":
        return value_data or None
    if artifact == "recentdocs" and value_type == 3:
        return _decode_recentdocs_binary_name(raw)
    return value_data or None


def _decode_recentdocs_binary_name(raw: bytes) -> str | None:
    if not raw:
        return None
    end = raw.find(b"\x00\x00")
    if end == -1:
        end = min(len(raw), 512)
    if end % 2:
        end += 1
    try:
        text = raw[:end].decode("utf-16-le", errors="replace").strip("\x00")
    except UnicodeDecodeError:
        return None
    return text or None


def _notes_for_value(artifact: str, value_name: str, value_type: int, raw: bytes, value_data: str) -> str:
    notes: list[str] = []
    if artifact == "userassist" and value_name:
        notes.append(f"rot13_name={_rot13(value_name)}")
    if artifact == "mui_cache" and value_name:
        notes.append(f"mui_cache_value={value_name}")
    if artifact in {"bam", "dam"}:
        if value_name:
            notes.append(f"executed_path={value_name}")
        if len(raw) >= 8:
            filetime = _filetime_to_iso(struct.unpack_from("<Q", raw)[0])
            if filetime:
                notes.append(f"filetime={filetime}")
    if artifact == "com_registration":
        if value_name:
            notes.append(f"com_value={value_name}")
    if artifact in {"shutdown_time", "install_time_software"} and len(raw) == 8:
        filetime = _filetime_to_iso(struct.unpack_from("<Q", raw)[0])
        if filetime:
            notes.append(f"filetime={filetime}")
    if artifact == "install_time_software" and value_name.lower() == "installdate" and value_type == 4:
        try:
            unix_time = int(value_data.split(" ", 1)[0])
            if unix_time > 0:
                notes.append(datetime.fromtimestamp(unix_time, tz=timezone.utc).isoformat().replace("+00:00", "Z"))
        except (ValueError, OSError, OverflowError):
            pass
    return "; ".join(notes)


def _rot13(value: str) -> str:
    output = []
    for char in value:
        if "a" <= char <= "z":
            output.append(chr((ord(char) - ord("a") + 13) % 26 + ord("a")))
        elif "A" <= char <= "Z":
            output.append(chr((ord(char) - ord("A") + 13) % 26 + ord("A")))
        else:
            output.append(char)
    return "".join(output)
