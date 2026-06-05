from __future__ import annotations

from typing import Any

from .analytics_query import query_rows
from .db import Database
from .timeline import timeline_events_from_rows
from .tools.normalized import normalized_bits_activity_row_from_evtx


def rebuild_bits_activity(
    db: Database,
    *,
    case_id: str,
    image_id: str | None = None,
) -> int:
    """Rebuild timestamped BITS activity from normalized EVTX rows."""
    _delete_bits_activity(db, case_id=case_id, image_id=image_id)
    evtx_rows = _bits_evtx_rows(db, case_id=case_id, image_id=image_id)
    bits_job_matches = _bits_job_matches(db, case_id=case_id, image_id=image_id)
    activity_rows: list[dict[str, Any]] = []
    for row in evtx_rows:
        activity = normalized_bits_activity_row_from_evtx(row)
        if not activity:
            continue
        _apply_bits_job_match(activity, bits_job_matches)
        activity_rows.append(activity)
    db.insert_bits_activity(activity_rows)
    db.insert_timeline_events(timeline_events_from_rows(activity_rows))
    return len(activity_rows)


def _delete_bits_activity(db: Database, *, case_id: str, image_id: str | None) -> None:
    where = ["case_id = ?"]
    params: list[Any] = [case_id]
    if image_id is not None:
        where.append("image_id = ?")
        params.append(image_id)
    clause = " AND ".join(where)
    timeline_clause = clause + " AND source_table = ?"
    timeline_params = [*params, "bits_activity"]
    if db._sqlite_table_exists("bits_activity"):
        db.conn.execute(f"DELETE FROM bits_activity WHERE {clause}", params)
    if db._sqlite_table_exists("timeline_events"):
        db.conn.execute(f"DELETE FROM timeline_events WHERE {timeline_clause}", timeline_params)
    if db.analytics is not None:
        db.analytics.delete_where("bits_activity", clause, params)
        db.analytics.delete_where("timeline_events", timeline_clause, timeline_params)
    db._commit()


def _bits_evtx_rows(db: Database, *, case_id: str, image_id: str | None) -> list[dict[str, Any]]:
    filters = ["case_id = ?"]
    params: list[Any] = [case_id]
    if image_id is not None:
        filters.append("image_id = ?")
        params.append(image_id)
    filters.append(
        """(
          lower(coalesce(provider, '')) LIKE '%bits%'
          OR lower(coalesce(channel, '')) LIKE '%bits%'
          OR lower(coalesce(payload, '')) LIKE '%jobtitle:%'
          OR lower(coalesce(payload_data1, '')) LIKE '%jobtitle:%'
          OR lower(coalesce(payload_data2, '')) LIKE '%jobtitle:%'
          OR lower(coalesce(payload_data3, '')) LIKE '%jobtitle:%'
        )"""
    )
    return query_rows(
        db,
        "evtx_events",
        f"""
        SELECT *
        FROM evtx_events
        WHERE {' AND '.join(filters)}
        ORDER BY time_created, row_number
        """,
        params,
    )


def _bits_job_matches(db: Database, *, case_id: str, image_id: str | None) -> dict[str, dict[str, str]]:
    filters = ["case_id = ?"]
    params: list[Any] = [case_id]
    if image_id is not None:
        filters.append("image_id = ?")
        params.append(image_id)
    rows = query_rows(
        db,
        "bits_jobs",
        f"""
        SELECT id, job_id, url
        FROM bits_jobs
        WHERE {' AND '.join(filters)}
          AND ((job_id IS NOT NULL AND job_id <> '') OR (url IS NOT NULL AND url <> ''))
        """,
        params,
    )
    matches: dict[str, dict[str, str]] = {}
    for row in rows:
        row_id = str(row.get("id") or "")
        if not row_id:
            continue
        job_id = str(row.get("job_id") or "").strip().lower()
        url = str(row.get("url") or "").strip().lower()
        if job_id:
            matches.setdefault(f"job:{job_id}", {"id": row_id, "basis": "job_id"})
        if url:
            matches.setdefault(f"url:{url}", {"id": row_id, "basis": "url"})
    return matches


def _apply_bits_job_match(activity: dict[str, Any], matches: dict[str, dict[str, str]]) -> None:
    job_id = str(activity.get("job_id") or "").strip().lower()
    url = str(activity.get("url") or "").strip().lower()
    match = matches.get(f"job:{job_id}") if job_id else None
    if match is None and url:
        match = matches.get(f"url:{url}")
    if match is None:
        return
    activity["matched_bits_job_id"] = match["id"]
    activity["correlation_basis"] = match["basis"]
