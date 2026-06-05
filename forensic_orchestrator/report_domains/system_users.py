from __future__ import annotations

import re
from typing import Any

from forensic_orchestrator.db import Database


def accounts_report(db: Database, case_id: str) -> dict[str, Any]:
    db.get_case(case_id)
    rows = _query_report_rows(
        db,
        case_id,
        "sam_accounts",
        """
        SELECT sam_accounts.*, NULL AS computer_label, NULL AS image_path
        FROM sam_accounts
        WHERE sam_accounts.case_id = ?
        ORDER BY sam_accounts.image_id, TRY_CAST(sam_accounts.rid AS INTEGER)
        """,
        (case_id,),
    )
    accounts = []
    computer_labels = _computer_labels(db, case_id)
    image_paths = _image_paths(db, case_id)
    for row in rows:
        accounts.append(
            {
                "computer_id": row["computer_id"],
                "computer_label": row["computer_label"] or computer_labels.get(str(row["computer_id"])),
                "image_id": row["image_id"],
                "image_path": row["image_path"] or image_paths.get(str(row["image_id"])),
                "username": row["username"],
                "rid": row["rid"],
                "rid_hex": row["rid_hex"],
                "account_category": row["account_category"],
                "last_login_utc": row["last_login_utc"],
                "password_last_set_utc": row["password_last_set_utc"],
                "last_bad_password_utc": row["last_bad_password_utc"],
                "account_expires_utc": row["account_expires_utc"],
                "logon_count": row["logon_count"],
                "bad_password_count": row["bad_password_count"],
                "account_flags_hex": row["account_flags_hex"],
                "account_flags": row["account_flags"],
                "account_flags_unknown_hex": row["account_flags_unknown_hex"],
                "registry_path": row["registry_path"],
            }
        )
    return {"case_id": case_id, "accounts": accounts, "total_accounts": len(accounts)}


def system_users_report(
    db: Database,
    case_id: str,
    *,
    computer_id: str | None = None,
    include_builtin: bool = True,
    limit: int = 500,
) -> dict[str, Any]:
    db.get_case(case_id)
    filters = ["case_id = ?"]
    params: list[Any] = [case_id]
    if computer_id:
        filters.append("computer_id = ?")
        params.append(computer_id)
    rows = _query_report_rows(
        db,
        case_id,
        "sam_accounts",
        f"""
        SELECT *
        FROM sam_accounts
        WHERE {' AND '.join(filters)}
        ORDER BY image_id, TRY_CAST(rid AS INTEGER), username
        LIMIT ?
        """,
        [*params, max(limit * 4, limit)],
    )
    computer_labels = _computer_labels(db, case_id)
    image_paths = _image_paths(db, case_id)
    sid_by_key = _system_user_sid_lookup(db, case_id, computer_id=computer_id)
    cloud_by_key = _system_user_cloud_account_lookup(db, case_id, computer_id=computer_id)
    users: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for row in rows:
        rid = str(row.get("rid") or "").strip()
        username = str(row.get("username") or "").strip()
        if not username:
            continue
        category = str(row.get("account_category") or "").strip() or _sam_account_category(rid)
        if not include_builtin and category == "builtin":
            continue
        key = (str(row.get("computer_id") or ""), str(row.get("image_id") or ""), rid, username.casefold())
        if key in seen:
            continue
        seen.add(key)
        lookup_key = (str(row.get("computer_id") or ""), str(row.get("image_id") or ""), rid)
        cloud = cloud_by_key.get(lookup_key) or cloud_by_key.get(("", "", rid)) or {}
        sid = sid_by_key.get(lookup_key) or sid_by_key.get((str(row.get("computer_id") or ""), "", rid)) or sid_by_key.get(("", "", rid))
        internet_username = cloud.get("internet_username")
        account_type = "microsoft_account" if internet_username else ("builtin" if category == "builtin" else "local_account")
        users.append(
            {
                "computer_id": row.get("computer_id"),
                "computer_label": computer_labels.get(str(row.get("computer_id") or "")),
                "image_id": row.get("image_id"),
                "image_path": image_paths.get(str(row.get("image_id") or "")),
                "username": username,
                "first_name": None,
                "last_name": None,
                "sid": sid,
                "rid": rid,
                "rid_hex": row.get("rid_hex") or _rid_hex(rid),
                "account_type": account_type,
                "account_category": category,
                "internet_username": internet_username,
                "internet_provider": cloud.get("internet_provider"),
                "last_login_utc": row.get("last_login_utc"),
                "password_last_set_utc": row.get("password_last_set_utc"),
                "last_bad_password_utc": row.get("last_bad_password_utc"),
                "logon_count": row.get("logon_count"),
                "account_flags": row.get("account_flags"),
                "profile_path": _profile_path_for_username(username),
                "evidence_sources": [
                    {
                        "source_table": "sam_accounts",
                        "source_row_id": row.get("id"),
                        "source_tool": row.get("tool_name"),
                        "field_basis": ["username", "rid", "account_category", "last_login_utc", "account_flags"],
                    },
                    *cloud.get("evidence_sources", []),
                    *(
                        [
                            {
                                "source_table": "registry_artifacts",
                                "field_basis": ["user_sid"],
                                "note": "SID inferred by matching RID suffix from registry artifacts.",
                            }
                        ]
                        if sid
                        else []
                    ),
                ],
            }
        )
        if len(users) >= limit:
            break
    return {
        "case_id": case_id,
        "filters": {"computer_id": computer_id, "include_builtin": include_builtin, "limit": limit},
        "users": users,
        "total_returned": len(users),
        "source_of_truth": ["sam_accounts", "registry_artifacts cloud_account_details", "registry_artifacts user_sid"],
        "caveats": [
            "First and last names are only populated when a parsed artifact provides them; SAM usernames are not split into names.",
            "Microsoft account attribution is based on cloud_account_details InternetUserName values keyed to the SAM RID.",
        ],
    }


def _system_user_sid_lookup(db: Database, case_id: str, *, computer_id: str | None) -> dict[tuple[str, str, str], str]:
    filters = ["case_id = ?", "COALESCE(user_sid, '') != ''"]
    params: list[Any] = [case_id]
    if computer_id:
        filters.append("computer_id = ?")
        params.append(computer_id)
    rows = _query_report_rows(
        db,
        case_id,
        "registry_artifacts",
        f"""
        SELECT DISTINCT computer_id, image_id, user_sid
        FROM registry_artifacts
        WHERE {' AND '.join(filters)}
        """,
        params,
    )
    lookup: dict[tuple[str, str, str], str] = {}
    for row in rows:
        sid = str(row.get("user_sid") or "")
        rid = sid.rsplit("-", 1)[-1] if "-" in sid else ""
        if not rid.isdigit():
            continue
        lookup.setdefault((str(row.get("computer_id") or ""), str(row.get("image_id") or ""), rid), sid)
        lookup.setdefault((str(row.get("computer_id") or ""), "", rid), sid)
        lookup.setdefault(("", "", rid), sid)
    return lookup


def _system_user_cloud_account_lookup(db: Database, case_id: str, *, computer_id: str | None) -> dict[tuple[str, str, str], dict[str, Any]]:
    filters = ["case_id = ?", "artifact = 'cloud_account_details'"]
    params: list[Any] = [case_id]
    if computer_id:
        filters.append("computer_id = ?")
        params.append(computer_id)
    rows = _query_report_rows(
        db,
        case_id,
        "registry_artifacts",
        f"""
        SELECT id, computer_id, image_id, key_path, value_name, value_data, key_last_write_utc
        FROM registry_artifacts
        WHERE {' AND '.join(filters)}
        ORDER BY key_last_write_utc DESC, row_number
        """,
        params,
    )
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in rows:
        rid = _rid_from_sam_user_key(row.get("key_path"))
        if not rid:
            continue
        key = (str(row.get("computer_id") or ""), str(row.get("image_id") or ""), rid)
        item = grouped.setdefault(key, {"evidence_sources": []})
        value_name = str(row.get("value_name") or "")
        value_data = str(row.get("value_data") or "")
        if value_name == "InternetUserName" and value_data:
            item["internet_username"] = value_data
        elif value_name == "InternetProviderName" and value_data:
            item["internet_provider"] = value_data
        item["evidence_sources"].append(
            {
                "source_table": "registry_artifacts",
                "source_row_id": row.get("id"),
                "field_basis": [value_name],
                "key_path": row.get("key_path"),
                "key_last_write_utc": row.get("key_last_write_utc"),
            }
        )
    return grouped


def _query_report_rows(db: Database, case_id: str, table: str, sql: str, params: tuple[Any, ...] | list[Any]) -> list[dict[str, Any]]:
    from forensic_orchestrator import reports as _reports

    return _reports._query_report_rows(db, case_id, table, sql, params)


def _computer_labels(db: Database, case_id: str) -> dict[str, str]:
    rows = db.conn.execute("SELECT id, label FROM computers WHERE case_id = ?", (case_id,)).fetchall()
    return {str(row["id"]): row["label"] for row in rows}


def _image_paths(db: Database, case_id: str) -> dict[str, str]:
    rows = db.conn.execute("SELECT id, path FROM images WHERE case_id = ?", (case_id,)).fetchall()
    return {str(row["id"]): row["path"] for row in rows}


def _rid_from_sam_user_key(value: Any) -> str | None:
    text = str(value or "")
    match = re.search(r"Users[\\/]+([0-9A-Fa-f]{8})\b", text)
    if not match:
        return None
    return str(int(match.group(1), 16))


def _rid_hex(value: Any) -> str | None:
    rid = _safe_int(value, -1)
    if rid < 0:
        return None
    return f"{rid:08X}"


def _sam_account_category(rid: str) -> str:
    rid_int = _safe_int(rid, -1)
    if 0 <= rid_int < 1000:
        return "builtin"
    return "local"


def _profile_path_for_username(username: str) -> str | None:
    if not username:
        return None
    return f"C:\\Users\\{username}"


def _safe_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
