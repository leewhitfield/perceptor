from __future__ import annotations

import csv
import configparser
import json
import os
import re
import shutil
import struct
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path, PureWindowsPath
from typing import Any, Iterable

from Registry import Registry


SRUM_FIELDS = [
    "provider_guid", "provider_name", "record_type", "source_table",
    "srum_id", "timestamp", "app_id", "app_name", "app_path",
    "app_description", "exe_timestamp", "user_id", "user_sid", "user_name",
    "bytes_received", "bytes_sent", "interface_luid", "interface_type",
    "l2_profile_id", "l2_profile_name", "l2_profile_flags", "connected_time",
    "connect_start_time", "connect_end_time", "notification_type",
    "payload_size", "network_type", "foreground_bytes_read",
    "foreground_bytes_written", "background_bytes_read",
    "background_bytes_written", "foreground_cycle_time",
    "background_cycle_time", "face_time", "foreground_context_switches",
    "background_context_switches", "foreground_read_operations",
    "foreground_write_operations", "background_read_operations",
    "background_write_operations", "foreground_flushes", "background_flushes",
    "flags", "start_time", "end_time", "duration_ms", "span_ms",
    "timeline_end", "event_timestamp", "state_transition", "charge_level",
    "cycle_count", "designed_capacity", "full_charged_capacity",
    "active_ac_time", "active_dc_time", "active_discharge_time",
    "active_energy", "cs_ac_time", "cs_dc_time", "cs_discharge_time",
    "cs_energy", "configuration_hash", "metadata", "energy_data", "tag",
    "binary_data", "vpn_profile_name", "vpn_server", "vpn_device",
    "vpn_protocol", "vpn_phonebook_path", "vpn_match_method", "row_json",
]

PROVIDERS = {
    "5c8cf1c7-7257-4f13-b223-970ef5939312": ("app_timeline_provider", "App Timeline Provider"),
    "7acbbaa3-d029-4be4-9a7a-0885927f1d8f": ("vfu_provider", "Vfuprov"),
    "973f5d5c-1d90-4944-be8e-24b94231a174": ("network_usage", "Windows Network Data Usage Monitor"),
    "b6d82af1-f780-4e17-8077-6cb9ad8a6fc4": ("tagged_energy", "Tagged Energy Provider"),
    "d10ca2fe-6fcf-4f6d-848e-b2e99266fa86": ("push_notifications", "Windows Push Notifications Provider"),
    "d10ca2fe-6fcf-4f6d-848e-b2e99266fa89": ("app_resource_usage", "Application Resource Usage Provider"),
    "da73fb89-2bea-4ddc-86b8-6e048c6da477": ("energy_estimation", "Energy Estimation Provider"),
    "dd6636c4-8929-4683-974e-22c046a43763": ("network_connectivity", "Windows Network Connectivity Usage Monitor"),
    "fee4e14f-02a9-4550-b5ce-5fa2da202e37": ("energy_usage", "Energy Usage Provider"),
}

FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def parse_srum_artifacts_to_csv(
    source: Path,
    output: Path,
    *,
    software_hive: Path | None = None,
    phonebooks: Path | None = None,
) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    srudb = source / "SRUDB.dat" if source.is_dir() else source
    csv_path = output / "SrumRecords.csv"
    if not srudb.exists():
        _write_csv(csv_path, [])
        return csv_path
    target = output / "_esedbexport"
    actual_export_dir = output / "_esedbexport.export"
    for export_dir in (target, actual_export_dir):
        if export_dir.exists():
            shutil.rmtree(export_dir)
    result = subprocess.run(
        ["esedbexport", "-t", str(target), str(srudb)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        fallback_rows = _parse_srum_with_dissect(srudb, software_hive=software_hive, phonebooks=phonebooks)
        if fallback_rows:
            (output / "SrumExportError.txt").write_text(
                f"esedbexport failed with exit code {result.returncode}; recovered with dissect.esedb fallback\n"
                f"source={srudb}\n\n"
                f"stdout:\n{result.stdout.strip()}\n\n"
                f"stderr:\n{result.stderr.strip()}\n",
                encoding="utf-8",
            )
            _write_csv(csv_path, fallback_rows)
            return csv_path
        (output / "SrumExportError.txt").write_text(
            f"esedbexport failed with exit code {result.returncode}\n"
            f"source={srudb}\n\n"
            f"stdout:\n{result.stdout.strip()}\n\n"
            f"stderr:\n{result.stderr.strip()}\n",
            encoding="utf-8",
        )
        _write_csv(csv_path, [])
        return csv_path
    software_maps = _load_software_maps(software_hive)
    id_maps = _load_id_maps(actual_export_dir, software_maps)
    vpn_profiles = _load_vpn_profiles(phonebooks)
    rows: list[dict[str, object]] = []
    for table_path in sorted(actual_export_dir.glob("{*}*")):
        provider_guid = _provider_guid_from_name(table_path.name)
        if not provider_guid:
            continue
        record_type, provider_name = PROVIDERS.get(provider_guid.lower(), (provider_guid.lower(), provider_guid))
        for row in _read_tsv(table_path):
            rows.append(_normalize_srum_row(
                row,
                provider_guid=provider_guid,
                provider_name=provider_name,
                record_type=record_type,
                source_table=table_path.name,
                id_maps=id_maps,
                vpn_profiles=vpn_profiles,
            ))
    _write_csv(csv_path, rows)
    return csv_path


def _parse_srum_with_dissect(
    srudb: Path,
    *,
    software_hive: Path | None = None,
    phonebooks: Path | None = None,
) -> list[dict[str, object]]:
    try:
        from dissect.esedb import EseDB
    except ImportError:
        return []
    try:
        with srudb.open("rb") as handle:
            db = EseDB(handle)
            software_maps = _load_software_maps(software_hive)
            id_maps = _load_id_maps_from_dissect(db, software_maps)
            vpn_profiles = _load_vpn_profiles(phonebooks)
            rows: list[dict[str, object]] = []
            for table in db.tables():
                provider_guid = _provider_guid_from_name(table.name)
                if not provider_guid:
                    continue
                record_type, provider_name = PROVIDERS.get(provider_guid.lower(), (provider_guid.lower(), provider_guid))
                try:
                    records = table.records()
                except Exception:
                    continue
                for row in records:
                    try:
                        rows.append(_normalize_srum_row(
                            row.as_dict(),
                            provider_guid=provider_guid,
                            provider_name=provider_name,
                            record_type=record_type,
                            source_table=table.name,
                            id_maps=id_maps,
                            vpn_profiles=vpn_profiles,
                        ))
                    except Exception:
                        continue
            return rows
    except Exception:
        return []


def _normalize_srum_row(
    row: dict[str, Any],
    *,
    provider_guid: str,
    provider_name: str,
    record_type: str,
    source_table: str,
    id_maps: dict[str, dict[str, str]],
    vpn_profiles: list[dict[str, str]],
) -> dict[str, object]:
    app_id = _first(row, "AppId")
    user_id = _first(row, "UserId")
    app = id_maps["apps"].get(app_id or "", {})
    user = id_maps["users"].get(user_id or "", {})
    normalized = {
        "provider_guid": provider_guid,
        "provider_name": provider_name,
        "record_type": record_type,
        "source_table": source_table,
        "srum_id": _first(row, "AutoIncId", "Id", "ID"),
        "timestamp": _srum_time(_first(row, "TimeStamp", "Timestamp")),
        "app_id": app_id,
        "app_name": app.get("name") or _first(row, "AppName", "Name"),
        "app_path": app.get("path") or _first(row, "ExeInfo", "AppPath", "Path", "FullPath"),
        "app_description": app.get("description") or _first(row, "ExeInfoDescription"),
        "exe_timestamp": app.get("timestamp") or _srum_time(_first(row, "ExeTimestamp")),
        "user_id": user_id,
        "user_sid": user.get("sid") or _first(row, "Sid", "UserSid", "SID"),
        "user_name": user.get("name") or _first(row, "UserName", "User"),
        "bytes_received": _first(row, "BytesReceived", "BytesRecvd", "Bytes Received"),
        "bytes_sent": _first(row, "BytesSent", "Bytes Sent"),
        "interface_luid": _first(row, "InterfaceLuid"),
        "interface_type": _interface_type(_first(row, "InterfaceLuid")),
        "l2_profile_id": _first(row, "L2ProfileId"),
        "l2_profile_name": _first(row, "ProfileName", "L2ProfileName") or id_maps.get("profile_index_to_ssid", {}).get(_first(row, "L2ProfileId"), ""),
        "l2_profile_flags": _first(row, "L2ProfileFlags"),
        "connected_time": _first(row, "ConnectedTime"),
        "connect_start_time": _filetime_or_text(_first(row, "ConnectStartTime")),
        "connect_end_time": "",
        "notification_type": _first(row, "NotificationType"),
        "payload_size": _first(row, "PayloadSize"),
        "network_type": _first(row, "NetworkType"),
        "foreground_bytes_read": _first(row, "ForegroundBytesRead"),
        "foreground_bytes_written": _first(row, "ForegroundBytesWritten"),
        "background_bytes_read": _first(row, "BackgroundBytesRead"),
        "background_bytes_written": _first(row, "BackgroundBytesWritten"),
        "foreground_cycle_time": _first(row, "ForegroundCycleTime"),
        "background_cycle_time": _first(row, "BackgroundCycleTime"),
        "face_time": _first(row, "FaceTime"),
        "foreground_context_switches": _first(row, "ForegroundContextSwitches"),
        "background_context_switches": _first(row, "BackgroundContextSwitches"),
        "foreground_read_operations": _first(row, "ForegroundNumReadOperations"),
        "foreground_write_operations": _first(row, "ForegroundNumWriteOperations"),
        "background_read_operations": _first(row, "BackgroundNumReadOperations"),
        "background_write_operations": _first(row, "BackgroundNumWriteOperations"),
        "foreground_flushes": _first(row, "ForegroundNumberOfFlushes"),
        "background_flushes": _first(row, "BackgroundNumberOfFlushes"),
        "flags": _first(row, "Flags"),
        "start_time": _filetime_or_text(_first(row, "StartTime")),
        "end_time": _filetime_or_text(_first(row, "EndTime")),
        "duration_ms": _first(row, "DurationMS"),
        "span_ms": _first(row, "SpanMS"),
        "timeline_end": _first(row, "TimelineEnd"),
        "event_timestamp": _filetime_or_text(_first(row, "EventTimestamp")),
        "state_transition": _first(row, "StateTransition"),
        "charge_level": _first(row, "ChargeLevel"),
        "cycle_count": _first(row, "CycleCount"),
        "designed_capacity": _first(row, "DesignedCapacity"),
        "full_charged_capacity": _first(row, "FullChargedCapacity"),
        "active_ac_time": _first(row, "ActiveAcTime"),
        "active_dc_time": _first(row, "ActiveDcTime"),
        "active_discharge_time": _first(row, "ActiveDischargeTime"),
        "active_energy": _first(row, "ActiveEnergy"),
        "cs_ac_time": _first(row, "CsAcTime"),
        "cs_dc_time": _first(row, "CsDcTime"),
        "cs_discharge_time": _first(row, "CsDischargeTime"),
        "cs_energy": _first(row, "CsEnergy"),
        "configuration_hash": _first(row, "ConfigurationHash"),
        "metadata": _first(row, "Metadata"),
        "energy_data": _first(row, "Energy Data", "EnergyData"),
        "tag": _first(row, "Tag"),
        "binary_data": _first(row, "BinaryData", "Usage"),
    }
    normalized.update(_vpn_profile_for_row(normalized, vpn_profiles))
    normalized["row_json"] = json.dumps(row, sort_keys=True)
    return normalized


def _vpn_profile_for_row(row: dict[str, object], vpn_profiles: list[dict[str, str]]) -> dict[str, str]:
    empty = {
        "vpn_profile_name": "",
        "vpn_server": "",
        "vpn_device": "",
        "vpn_protocol": "",
        "vpn_phonebook_path": "",
        "vpn_match_method": "",
    }
    if str(row.get("record_type") or "") != "network_connectivity":
        return empty
    if str(row.get("interface_type") or "") != "23":
        return empty
    if not vpn_profiles:
        return empty

    current = [profile for profile in vpn_profiles if "pbk_old" not in profile.get("source_path", "").lower()]
    candidates = current or vpn_profiles
    unique = _dedupe_vpn_profiles(candidates)
    if len(unique) == 1:
        profile = unique[0]
        return {
            "vpn_profile_name": profile.get("profile_name", ""),
            "vpn_server": profile.get("server", ""),
            "vpn_device": profile.get("device", ""),
            "vpn_protocol": profile.get("protocol", ""),
            "vpn_phonebook_path": profile.get("source_path", ""),
            "vpn_match_method": "single_profile",
        }

    return {
        "vpn_profile_name": "; ".join(sorted({p.get("profile_name", "") for p in unique if p.get("profile_name")})),
        "vpn_server": "; ".join(sorted({p.get("server", "") for p in unique if p.get("server")})),
        "vpn_device": "; ".join(sorted({p.get("device", "") for p in unique if p.get("device")})),
        "vpn_protocol": "; ".join(sorted({p.get("protocol", "") for p in unique if p.get("protocol")})),
        "vpn_phonebook_path": "; ".join(p.get("source_path", "") for p in unique if p.get("source_path")),
        "vpn_match_method": "ambiguous_profile",
    }


def _load_id_maps(
    export_dir: Path,
    software_maps: dict[str, dict[str, str]],
) -> dict[str, dict[str, dict[str, str]]]:
    apps: dict[str, dict[str, str]] = {}
    users: dict[str, dict[str, str]] = {}
    for path in export_dir.glob("SruDbIdMapTable.*"):
        for row in _read_tsv(path):
            index = _first(row, "IdIndex")
            blob = _first(row, "IdBlob") or ""
            if not index:
                continue
            if _first(row, "IdType") == "0":
                apps[index] = _decode_app_blob(blob)
            elif _first(row, "IdType") == "3":
                sid = _decode_sid(bytes.fromhex(blob)) if blob else ""
                users[index] = {"sid": sid, "name": software_maps["sid_to_user"].get(sid, "")}
    return {
        "apps": apps,
        "users": users,
        "profile_index_to_ssid": software_maps["profile_index_to_ssid"],
    }


def _load_id_maps_from_dissect(
    db: Any,
    software_maps: dict[str, dict[str, str]],
) -> dict[str, dict[str, dict[str, str]]]:
    apps: dict[str, dict[str, str]] = {}
    users: dict[str, dict[str, str]] = {}
    try:
        records = db.table("SruDbIdMapTable").records()
    except Exception:
        records = []
    for record in records:
        row = record.as_dict()
        index = str(row.get("IdIndex") or "")
        blob = row.get("IdBlob") or b""
        if not index:
            continue
        if row.get("IdType") == 0:
            apps[index] = _decode_app_blob(blob.hex() if isinstance(blob, bytes) else str(blob))
        elif row.get("IdType") == 3:
            sid = _decode_sid(blob) if isinstance(blob, bytes) and blob else ""
            users[index] = {"sid": sid, "name": software_maps["sid_to_user"].get(sid, "")}
    return {
        "apps": apps,
        "users": users,
        "profile_index_to_ssid": software_maps["profile_index_to_ssid"],
    }


def _load_vpn_profiles(phonebooks: Path | None) -> list[dict[str, str]]:
    if phonebooks is None or not phonebooks.exists():
        return []
    paths = [phonebooks] if phonebooks.is_file() else sorted(_iter_phonebook_paths(phonebooks))
    profiles: list[dict[str, str]] = []
    for path in paths:
        profiles.extend(_read_phonebook(path))
    return _dedupe_vpn_profiles(profiles)


def _iter_phonebook_paths(root: Path) -> Iterable[Path]:
    for current_root, _, filenames in os.walk(root, onerror=lambda _error: None):
        for filename in filenames:
            if filename.lower().endswith(".pbk"):
                yield Path(current_root) / filename


def _read_phonebook(path: Path) -> list[dict[str, str]]:
    text = ""
    for encoding in ("utf-8", "utf-16-le", "utf-16"):
        try:
            text = path.read_text(encoding=encoding)
        except (OSError, UnicodeError):
            continue
        if "[" in text and "]" in text:
            break
    if not text:
        return []

    parser = configparser.ConfigParser(strict=False, interpolation=None)
    parser.optionxform = str
    try:
        parser.read_string(text)
    except configparser.Error:
        return []

    profiles: list[dict[str, str]] = []
    for section in parser.sections():
        values = parser[section]
        device = values.get("Device") or values.get("PreferredDevice") or ""
        server = values.get("PhoneNumber") or ""
        vpn_type = values.get("Type") or ""
        if not _looks_like_vpn_profile(device=device, server=server, vpn_type=vpn_type):
            continue
        profiles.append(
            {
                "profile_name": section,
                "server": server,
                "device": device,
                "protocol": _vpn_protocol(device, values.get("VpnStrategy") or ""),
                "guid": values.get("Guid") or "",
                "source_path": str(path),
            }
        )
    return profiles


def _looks_like_vpn_profile(*, device: str, server: str, vpn_type: str) -> bool:
    haystack = f"{device} {server}".lower()
    return vpn_type == "2" or "vpn" in haystack or "wan miniport" in haystack


def _vpn_protocol(device: str, strategy: str) -> str:
    lowered = device.lower()
    for protocol in ("sstp", "ikev2", "l2tp", "pptp"):
        if protocol in lowered:
            return protocol.upper()
    return {
        "1": "PPTP",
        "2": "L2TP",
        "3": "SSTP",
        "4": "IKEv2",
        "6": "SSTP",
    }.get(strategy, "")


def _dedupe_vpn_profiles(profiles: list[dict[str, str]]) -> list[dict[str, str]]:
    deduped: dict[tuple[str, str, str], dict[str, str]] = {}
    for profile in profiles:
        key = (
            profile.get("profile_name", "").casefold(),
            profile.get("server", "").casefold(),
            profile.get("guid", "").casefold(),
        )
        existing = deduped.get(key)
        if existing is None or _vpn_source_rank(profile.get("source_path", "")) < _vpn_source_rank(existing.get("source_path", "")):
            deduped[key] = profile
    return list(deduped.values())


def _vpn_source_rank(source_path: str) -> int:
    lowered = source_path.lower()
    rank = 0
    if "_hiddenpbk" in lowered:
        rank += 1
    if "pbk_old" in lowered:
        rank += 2
    return rank


def _load_software_maps(software_hive: Path | None) -> dict[str, dict[str, str]]:
    maps: dict[str, dict[str, str]] = {"sid_to_user": {}, "profile_index_to_ssid": {}}
    if software_hive is None or not software_hive.exists():
        return maps
    try:
        hive = Registry.Registry(str(software_hive))
    except Exception:
        return maps
    try:
        profile_list = hive.open("Microsoft\\Windows NT\\CurrentVersion\\ProfileList")
        for subkey in profile_list.subkeys():
            try:
                profile_path = subkey.value("ProfileImagePath").value()
            except Registry.RegistryValueNotFoundException:
                continue
            maps["sid_to_user"][subkey.name()] = PureWindowsPath(str(profile_path)).name
    except Registry.RegistryKeyNotFoundException:
        pass
    try:
        interfaces = hive.open("Microsoft\\WlanSvc\\Interfaces")
        for interface_key in interfaces.subkeys():
            try:
                profiles = interface_key.subkey("Profiles")
            except Registry.RegistryKeyNotFoundException:
                continue
            for profile_key in profiles.subkeys():
                try:
                    profile_index = str(profile_key.value("ProfileIndex").value())
                    metadata = profile_key.subkey("MetaData")
                    channel_hints = _metadata_channel_hints(metadata)
                except (Registry.RegistryKeyNotFoundException, Registry.RegistryValueNotFoundException):
                    continue
                ssid = _decode_channel_hints(channel_hints)
                if profile_index and ssid:
                    maps["profile_index_to_ssid"][profile_index] = ssid
    except Registry.RegistryKeyNotFoundException:
        pass
    return maps


def _metadata_channel_hints(metadata) -> bytes:
    for name in ("Channel Hints", "Band Channel Hints"):
        try:
            return metadata.value(name).raw_data()
        except Registry.RegistryValueNotFoundException:
            continue
    raise Registry.RegistryValueNotFoundException("Channel Hints")


def _decode_channel_hints(data: bytes) -> str:
    if len(data) < 4:
        return ""
    length = int.from_bytes(data[:4], "little", signed=True)
    if length <= 0:
        return ""
    payload = data[4:4 + length]
    for encoding in ("ascii", "utf-8", "utf-16-le"):
        try:
            text = payload.decode(encoding, errors="strict").strip("\x00")
        except UnicodeDecodeError:
            continue
        if text:
            return text
    return payload.decode("utf-8", errors="replace").strip("\x00")


def _decode_app_blob(hex_blob: str) -> dict[str, str]:
    if not hex_blob:
        return {}
    try:
        text = bytes.fromhex(hex_blob).decode("utf-16-le", errors="replace").strip("\x00")
    except ValueError:
        return {}
    parts = text.split("!")
    clean = [part for part in parts if part]
    return {
        "path": clean[0] if len(clean) > 0 else "",
        "name": Path(clean[0]).name if len(clean) > 0 else "",
        "timestamp": _app_blob_time(clean[1]) if len(clean) > 1 else "",
        "description": clean[3] if len(clean) > 3 else "",
        "raw": text,
    }


def _decode_sid(data: bytes) -> str:
    if len(data) < 8:
        return ""
    revision = data[0]
    subauth_count = data[1]
    authority = int.from_bytes(data[2:8], "big")
    parts = [f"S-{revision}-{authority}"]
    offset = 8
    for _ in range(subauth_count):
        if offset + 4 > len(data):
            break
        parts.append(str(int.from_bytes(data[offset:offset + 4], "little")))
        offset += 4
    return "-".join(parts)


def _read_tsv(path: Path) -> Iterable[dict[str, str]]:
    with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        yield from csv.DictReader(handle, delimiter="\t")


def _write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=SRUM_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _provider_guid_from_name(name: str) -> str:
    match = re.match(r"\{([^}]+)\}", name)
    return match.group(1).lower() if match else ""


def _first(row: dict[str, Any], *names: str) -> str:
    for name in names:
        value = row.get(name)
        if value not in (None, ""):
            return str(value)
    return ""


def _srum_time(value: str | None) -> str:
    if value is None or value == "":
        return ""
    if isinstance(value, int):
        return _srum_ole_datetime(value)
    if str(value).startswith("("):
        return value or ""
    value = str(value).strip()
    if re.fullmatch(r"\d{12,}", value):
        return _srum_ole_datetime(int(value))
    match = re.match(r"([A-Z][a-z]{2} \d{1,2}, \d{4} \d{2}:\d{2}:\d{2})(?:\.(\d+))?", value)
    if not match:
        return value
    base, fraction = match.groups()
    try:
        dt = datetime.strptime(base, "%b %d, %Y %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return value
    if fraction:
        dt += timedelta(microseconds=int(fraction[:6].ljust(6, "0")))
    return dt.isoformat().replace("+00:00", "Z")


def _srum_ole_datetime(value: int) -> str:
    try:
        ole_days = struct.unpack("<d", int(value).to_bytes(8, "little", signed=False))[0]
        return (datetime(1899, 12, 30, tzinfo=timezone.utc) + timedelta(days=ole_days)).isoformat().replace("+00:00", "Z")
    except (OverflowError, ValueError, struct.error):
        return str(value)


def _filetime_or_text(value: str | None) -> str:
    if not value:
        return ""
    try:
        number = int(value)
    except ValueError:
        return _srum_time(value)
    if number <= 0:
        return ""
    try:
        return (FILETIME_EPOCH + timedelta(microseconds=number / 10)).isoformat().replace("+00:00", "Z")
    except (OverflowError, ValueError):
        return value


def _app_blob_time(value: str) -> str:
    try:
        return datetime.strptime(value, "%Y/%m/%d:%H:%M:%S").replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
    except ValueError:
        return value


def _interface_type(interface_luid: str | None) -> str:
    if not interface_luid:
        return ""
    try:
        return str((int(interface_luid) >> 48) & 0xFFFF)
    except ValueError:
        return ""
