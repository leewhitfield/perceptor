from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from forensic_orchestrator.analytics_query import query_rows
from forensic_orchestrator.db import Database, utc_now
from forensic_orchestrator.reports import _parse_report_timestamp, _rdp_client_sessions


def rebuild_sessions(db: Database, *, case_id: str, image_id: str | None = None) -> dict[str, Any]:
    db.get_case(case_id)
    _delete_existing(db, case_id=case_id, image_id=image_id)

    sessions: list[dict[str, Any]] = []
    members: list[dict[str, Any]] = []
    for builder in (_vpn_sessions, _rdp_sessions, _logon_sessions):
        built_sessions, built_members = builder(db, case_id=case_id, image_id=image_id)
        sessions.extend(built_sessions)
        members.extend(built_members)

    _insert_sessions(db, sessions)
    _insert_members(db, members)
    db.log_activity(
        case_id=case_id,
        image_id=image_id,
        event="derived_sessions.rebuilt",
        message=f"Rebuilt {len(sessions)} derived sessions with {len(members)} evidence rows",
        details={"image_id": image_id, "sessions": len(sessions), "members": len(members)},
    )
    db.conn.commit()
    return {"case_id": case_id, "image_id": image_id, "sessions": len(sessions), "members": len(members)}


def _vpn_sessions(db: Database, *, case_id: str, image_id: str | None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows = _vpn_session_rows(db, case_id, image_id)
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        key = row.get("evidence_group") or row.get("profile_name") or row.get("server") or "unknown"
        groups.setdefault(str(key), []).append(row)

    sessions: list[dict[str, Any]] = []
    members: list[dict[str, Any]] = []
    for key, items in groups.items():
        items.sort(key=lambda item: str(item.get("event_time_utc") or ""))
        times = [_parse_report_timestamp(str(item.get("event_time_utc") or "")) for item in items]
        valid_times = [time for time in times if time is not None]
        first = items[0]
        start = _first_activity_time(items, {"connected", "connect_attempt"}) or (min(valid_times) if valid_times else None)
        end = _first_activity_time(items, {"disconnected", "failed"}, after=start) or (max(valid_times) if len(valid_times) > 1 else None)
        session = _session(
            case_id=case_id,
            computer_id=None,
            image_id=image_id,
            session_type="vpn",
            session_key=f"vpn:{key}",
            user_profile=first.get("user"),
            remote_host=first.get("server"),
            profile_name=first.get("profile_name"),
            protocol=first.get("protocol"),
            start_time=start,
            end_time=end,
            evidence_count=len(items),
            source_tables=sorted({str(item.get("source_type") or "vpn_evidence") for item in items}),
            status="paired" if start and end and start != end else "observed",
            details={"evidence_group": key, "activity_types": sorted({str(item.get("activity_type") or "") for item in items})},
        )
        sessions.append(session)
        for item in items:
            members.append(
                _member(
                    session,
                    source_table=str(item.get("source_type") or "vpn_evidence"),
                    source_row_id=None,
                    source_tool=None,
                    event_time=item.get("event_time_utc"),
                    event_type=item.get("activity_type"),
                    description=item.get("event"),
                    details=item,
                )
            )
    return sessions, members


def _vpn_session_rows(db: Database, case_id: str, image_id: str | None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    image_filter = "AND image_id = ?" if image_id else ""
    params: list[Any] = [case_id]
    if image_id:
        params.append(image_id)
    rows.extend(
        _vpn_row(
            source_type="srum_records",
            activity_type="connection_observation",
            event_time_utc=row["timestamp"],
            profile_name=row["vpn_profile_name"] or row["l2_profile_name"],
            server=row["vpn_server"],
            protocol=row["vpn_protocol"],
            user=row["user_name"],
            event="SRUM PPP/VPN connectivity observation",
            details={
                "id": row["id"],
                "connected_seconds": row["connected_time"],
                "interface_type": row["interface_type"],
                "app": row["app_name"] or row["app_path"],
            },
        )
        for row in query_rows(
            db,
            "srum_records",
            f"""
            SELECT id, timestamp, user_name, app_name, app_path, interface_type,
                   connected_time, vpn_profile_name, vpn_server, vpn_protocol,
                   l2_profile_name
            FROM srum_records
            WHERE case_id = ? {image_filter}
              AND interface_type = '23'
            LIMIT 20000
            """,
            tuple(params),
        )
    )
    rows.extend(
        _vpn_event_row(row)
        for row in query_rows(
            db,
            "evtx_events",
            f"""
            SELECT id, time_created, event_id, user_name, payload_data1,
                   payload_data2, payload_data3, map_description, provider,
                   channel, source_file
            FROM evtx_events
            WHERE case_id = ? {image_filter}
              AND event_id IN (
                '20220', '20221', '20222', '20223', '20224', '20225',
                '20226', '20227', '20228', '20268', '20269', '20270',
                '20271', '20272', '20275'
              )
            LIMIT 20000
            """,
            tuple(params),
        )
    )
    return rows


def _vpn_row(
    *,
    source_type: str,
    activity_type: str,
    event_time_utc: Any = "",
    profile_name: Any = "",
    server: Any = "",
    protocol: Any = "",
    event: Any = "",
    user: Any = "",
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "source_type": source_type,
        "activity_type": activity_type,
        "event_time_utc": event_time_utc or "",
        "profile_name": profile_name or "",
        "server": server or "",
        "protocol": protocol or "",
        "event": event or "",
        "user": user or "",
        "evidence_group": _vpn_evidence_group(profile_name=profile_name, server=server, protocol=protocol),
        "details": details or {},
    }


def _vpn_event_row(row: Any) -> dict[str, Any]:
    event_id = str(row["event_id"] or "")
    meanings = {
        "20220": ("connect_attempt", "VPN connection started"),
        "20221": ("connected", "VPN connection established"),
        "20222": ("disconnected", "VPN connection disconnected"),
        "20223": ("failed", "VPN connection failed"),
        "20224": ("disconnected", "VPN link disconnected"),
        "20225": ("failed", "VPN authentication failed"),
        "20226": ("failed", "VPN connection failed"),
        "20227": ("failed", "VPN connection failed"),
        "20228": ("failed", "VPN connection failed"),
        "20268": ("connect_attempt", "VPN connection started"),
        "20269": ("connected", "VPN connection established"),
        "20270": ("connect_attempt", "VPN reconnect started"),
        "20271": ("connected", "VPN reconnect completed"),
        "20272": ("failed", "VPN authentication failed"),
        "20275": ("failed", "VPN connection blocked or failed"),
    }
    activity_type, event = meanings.get(event_id, ("connection_observation", row["map_description"] or "VPN/RasClient event"))
    payload = " ".join(str(row[key] or "") for key in ("payload_data1", "payload_data2", "payload_data3", "map_description"))
    return _vpn_row(
        source_type="evtx_events",
        activity_type=activity_type,
        event_time_utc=row["time_created"],
        profile_name=_extract_after_label(payload, "connection") or _extract_after_label(payload, "profile"),
        server=_extract_after_label(payload, "server") or _extract_ip(payload),
        protocol="vpn",
        event=event,
        user=row["user_name"],
        details={"id": row["id"], "event_id": event_id, "payload": payload, "source_file": row["source_file"]},
    )


def _vpn_evidence_group(*, profile_name: Any = "", server: Any = "", protocol: Any = "") -> str:
    values = [str(value or "").strip().lower() for value in (profile_name, server, protocol) if str(value or "").strip()]
    return "|".join(values) if values else "unknown"


def _extract_after_label(text: str, label: str) -> str:
    match = re.search(rf"{re.escape(label)}\s*(?:name|profile|server)?\s*[:=]\s*([^,;\r\n]+)", text, re.IGNORECASE)
    return match.group(1).strip() if match else ""


def _extract_ip(text: str) -> str:
    match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    return match.group(0) if match else ""


def _rdp_sessions(db: Database, *, case_id: str, image_id: str | None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    sessions: list[dict[str, Any]] = []
    members: list[dict[str, Any]] = []
    for index, row in enumerate(_rdp_client_sessions(db, case_id), start=1):
        start = _parse_report_timestamp(row.get("connected_time_utc") or row.get("start_time_utc"))
        end = _parse_report_timestamp(row.get("end_time_utc"))
        session = _session(
            case_id=case_id,
            computer_id=None,
            image_id=image_id,
            session_type="rdp",
            session_key=f"rdp:{row.get('user') or ''}:{row.get('remote_host') or row.get('remote_ip') or index}:{row.get('start_time_utc') or ''}",
            user_profile=row.get("user"),
            source_host=row.get("client_computer"),
            remote_host=row.get("remote_host"),
            remote_ip=row.get("remote_ip"),
            profile_name=row.get("domain"),
            protocol="rdp",
            start_time=start,
            end_time=end,
            evidence_count=int(row.get("event_count") or len(row.get("events") or []) or 1),
            source_tables=["evtx_events"],
            status="paired" if start and end else "open_or_unpaired",
            details={key: value for key, value in row.items() if key != "events"},
        )
        sessions.append(session)
        for event in row.get("events") or []:
            members.append(
                _member(
                    session,
                    source_table="evtx_events",
                    source_row_id=None,
                    event_time=event.get("time_created"),
                    event_type=str(event.get("event_id") or ""),
                    description=event.get("description"),
                    details=event,
                )
            )
    return sessions, members


def _logon_sessions(db: Database, *, case_id: str, image_id: str | None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    image_filter = "AND image_id = ?" if image_id else ""
    params: list[Any] = [case_id]
    if image_id:
        params.append(image_id)
    rows = [
        dict(row)
        for row in query_rows(
            db,
            "evtx_events",
            f"""
            SELECT id, case_id, computer_id, image_id, time_created, event_id, provider,
                   channel, computer, user_name, user_id, remote_host, payload_data1,
                   payload_data2, payload_data3, map_description, source_file
            FROM evtx_events
            WHERE case_id = ? {image_filter}
              AND event_id IN ('4624', '4634', '4647', '4778', '4779')
            ORDER BY time_created
            """,
            tuple(params),
        )
    ]
    open_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    sessions: list[dict[str, Any]] = []
    members: list[dict[str, Any]] = []
    for row in rows:
        event_id = str(row.get("event_id") or "")
        user = str(row.get("user_name") or row.get("user_id") or "").strip()
        if not user or user.endswith("$") or user in {"-", "\\", "-\\-", "\\-"}:
            continue
        key = (user.lower(), str(row.get("computer") or row.get("computer_id") or ""))
        timestamp = _parse_report_timestamp(row.get("time_created"))
        if event_id in {"4624", "4778"}:
            if key in open_by_key:
                _finalize_logon(sessions, members, open_by_key.pop(key), None, image_id)
            open_by_key[key] = {"start": row, "events": [row]}
        elif key in open_by_key:
            open_by_key[key]["events"].append(row)
            _finalize_logon(sessions, members, open_by_key.pop(key), timestamp, image_id)
        else:
            open_by_key[key] = {"start": row, "events": [row], "unpaired_end": True}
            _finalize_logon(sessions, members, open_by_key.pop(key), timestamp, image_id)
    for item in open_by_key.values():
        _finalize_logon(sessions, members, item, None, image_id)
    return sessions, members


def _finalize_logon(
    sessions: list[dict[str, Any]],
    members: list[dict[str, Any]],
    item: dict[str, Any],
    end: datetime | None,
    image_id: str | None,
) -> None:
    start_row = item["start"]
    start = None if item.get("unpaired_end") else _parse_report_timestamp(start_row.get("time_created"))
    session = _session(
        case_id=start_row["case_id"],
        computer_id=start_row.get("computer_id"),
        image_id=image_id or start_row.get("image_id"),
        session_type="logon",
        session_key=f"logon:{start_row.get('user_name') or start_row.get('user_id')}:{start_row.get('computer')}:{start_row.get('time_created')}",
        user_profile=start_row.get("user_name") or start_row.get("user_id"),
        source_host=start_row.get("computer"),
        remote_host=start_row.get("remote_host"),
        protocol="windows-logon",
        start_time=start,
        end_time=end,
        evidence_count=len(item.get("events") or []),
        source_tables=["evtx_events"],
        status="paired" if start and end else "open_or_unpaired",
        details={"start_event_id": start_row.get("event_id"), "unpaired_end": bool(item.get("unpaired_end"))},
    )
    sessions.append(session)
    for event in item.get("events") or []:
        members.append(
            _member(
                session,
                source_table="evtx_events",
                source_row_id=event.get("id"),
                source_tool=None,
                event_time=event.get("time_created"),
                event_type=str(event.get("event_id") or ""),
                description=event.get("map_description"),
                details=event,
            )
        )


def _first_activity_time(items: list[dict[str, Any]], activity_types: set[str], after: datetime | None = None) -> datetime | None:
    for item in items:
        if item.get("activity_type") not in activity_types:
            continue
        timestamp = _parse_report_timestamp(str(item.get("event_time_utc") or ""))
        if timestamp and (after is None or timestamp >= after):
            return timestamp
    return None


def _session(
    *,
    case_id: str,
    computer_id: str | None,
    image_id: str | None,
    session_type: str,
    session_key: str,
    user_profile: Any = None,
    source_host: Any = None,
    remote_host: Any = None,
    remote_ip: Any = None,
    profile_name: Any = None,
    protocol: Any = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    status: str,
    evidence_count: int,
    source_tables: list[str],
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "session_type": session_type,
        "session_key": session_key,
        "user_profile": str(user_profile or "") or None,
        "source_host": str(source_host or "") or None,
        "remote_host": str(remote_host or "") or None,
        "remote_ip": str(remote_ip or "") or None,
        "profile_name": str(profile_name or "") or None,
        "protocol": str(protocol or "") or None,
        "start_time_utc": _iso(start_time),
        "end_time_utc": _iso(end_time),
        "duration_seconds": _duration(start_time, end_time),
        "status": status,
        "evidence_count": evidence_count,
        "source_tables": ",".join(source_tables),
        "details_json": json.dumps(details or {}, default=str),
        "created_at": utc_now(),
    }


def _member(
    session: dict[str, Any],
    *,
    source_table: str,
    source_row_id: Any,
    source_tool: str | None = None,
    event_time: Any = None,
    event_type: Any = None,
    description: Any = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "session_id": session["id"],
        "case_id": session["case_id"],
        "computer_id": session.get("computer_id"),
        "image_id": session.get("image_id"),
        "source_table": source_table,
        "source_row_id": str(source_row_id) if source_row_id else None,
        "source_tool": source_tool,
        "event_time_utc": str(event_time) if event_time else None,
        "event_type": str(event_type) if event_type else None,
        "description": str(description) if description else None,
        "details_json": json.dumps(details or {}, default=str),
        "created_at": utc_now(),
    }


def _duration(start: datetime | None, end: datetime | None) -> int | None:
    if not start or not end or end < start:
        return None
    return int((end - start).total_seconds())


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value.isoformat(sep=" ")


def _delete_existing(db: Database, *, case_id: str, image_id: str | None) -> None:
    where = ["case_id = ?"]
    params: list[Any] = [case_id]
    if image_id:
        where.append("image_id = ?")
        params.append(image_id)
    session_ids = [row["id"] for row in db.conn.execute(f"SELECT id FROM derived_sessions WHERE {' AND '.join(where)}", params)]
    if not session_ids:
        return
    placeholders = ",".join("?" for _ in session_ids)
    db.conn.execute(f"DELETE FROM derived_session_members WHERE session_id IN ({placeholders})", session_ids)
    db.conn.execute(f"DELETE FROM derived_sessions WHERE id IN ({placeholders})", session_ids)


def _insert_sessions(db: Database, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    db.conn.executemany(
        """
        INSERT INTO derived_sessions (
          id, case_id, computer_id, image_id, session_type, session_key, user_profile,
          source_host, remote_host, remote_ip, profile_name, protocol, start_time_utc,
          end_time_utc, duration_seconds, status, evidence_count, source_tables,
          details_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                row["id"], row["case_id"], row.get("computer_id"), row.get("image_id"),
                row["session_type"], row["session_key"], row.get("user_profile"),
                row.get("source_host"), row.get("remote_host"), row.get("remote_ip"),
                row.get("profile_name"), row.get("protocol"), row.get("start_time_utc"),
                row.get("end_time_utc"), row.get("duration_seconds"), row.get("status"),
                row.get("evidence_count", 0), row.get("source_tables", ""),
                row.get("details_json", "{}"), row["created_at"],
            )
            for row in rows
        ],
    )


def _insert_members(db: Database, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    db.conn.executemany(
        """
        INSERT INTO derived_session_members (
          id, session_id, case_id, computer_id, image_id, source_table, source_row_id,
          source_tool, event_time_utc, event_type, description, details_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                row["id"], row["session_id"], row["case_id"], row.get("computer_id"),
                row.get("image_id"), row["source_table"], row.get("source_row_id"),
                row.get("source_tool"), row.get("event_time_utc"), row.get("event_type"),
                row.get("description"), row.get("details_json", "{}"), row["created_at"],
            )
            for row in rows
        ],
    )
