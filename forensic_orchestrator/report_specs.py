from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import duckdb
import yaml

from .db import Database


DEFAULT_REPORT_SPEC_DIR = Path(__file__).parent / "plugins" / "report_specs"


@dataclass(frozen=True)
class ReportSpec:
    name: str
    title: str
    description: str
    store: str
    query: str
    columns: tuple[str, ...]
    parameters: tuple[str, ...]
    source: Path


def list_report_specs(
    extra_dirs: list[Path] | None = None,
    plugin_paths: list[Path] | None = None,
) -> list[ReportSpec]:
    specs: dict[str, ReportSpec] = {}
    for directory in _spec_dirs(extra_dirs, plugin_paths):
        if not directory.exists():
            continue
        for path in sorted([*directory.glob("*.yaml"), *directory.glob("*.yml")]):
            for spec in _load_spec_file(path):
                specs[spec.name] = spec
    for path in plugin_paths or []:
        if path.exists() and path.is_file():
            for spec in _load_spec_file(path):
                specs[spec.name] = spec
    return sorted(specs.values(), key=lambda item: item.name)


def get_report_spec(
    name: str,
    extra_dirs: list[Path] | None = None,
    plugin_paths: list[Path] | None = None,
) -> ReportSpec:
    for spec in list_report_specs(extra_dirs, plugin_paths):
        if spec.name == name:
            return spec
    raise KeyError(f"Report spec not found: {name}")


def run_report_spec(
    db: Database,
    case_id: str,
    name: str,
    *,
    limit: int = 100,
    extra_dirs: list[Path] | None = None,
    plugin_paths: list[Path] | None = None,
) -> dict[str, Any]:
    db.get_case(case_id)
    spec = get_report_spec(name, extra_dirs, plugin_paths)
    params = [_parameter_value(parameter, case_id, limit) for parameter in spec.parameters]
    rows = _execute_spec_query(db, case_id, spec, params)
    return {
        "case_id": case_id,
        "spec": {
            "name": spec.name,
            "title": spec.title,
            "description": spec.description,
            "store": spec.store,
            "source": str(spec.source),
        },
        "columns": list(spec.columns),
        "rows": rows[:limit],
        "total_returned": min(len(rows), limit),
    }


def _spec_dirs(extra_dirs: list[Path] | None, plugin_paths: list[Path] | None) -> list[Path]:
    dirs = [DEFAULT_REPORT_SPEC_DIR]
    env_dirs = os.environ.get("FORENSIC_REPORT_SPEC_DIRS")
    if env_dirs:
        dirs.extend(Path(item) for item in env_dirs.split(os.pathsep) if item)
    if extra_dirs:
        dirs.extend(extra_dirs)
    for path in plugin_paths or []:
        if path.is_dir():
            dirs.append(path)
            dirs.append(path / "report_specs")
        elif path.parent:
            dirs.append(path.parent / "report_specs")
    return dirs


def _load_spec_file(path: Path) -> list[ReportSpec]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    reports = data.get("reports", [])
    if not isinstance(reports, list):
        raise ValueError(f"Report spec file must contain a reports list: {path}")
    return [_parse_spec(path, item) for item in reports]


def _parse_spec(path: Path, item: dict[str, Any]) -> ReportSpec:
    name = str(item.get("name") or "").strip()
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", name):
        raise ValueError(f"Invalid report spec name in {path}: {name!r}")
    store = str(item.get("store") or "duckdb").strip().lower()
    if store not in {"duckdb", "sqlite"}:
        raise ValueError(f"Report spec {name} uses unsupported store: {store}")
    query = str(item.get("query") or "").strip()
    _validate_read_only_query(name, query)
    columns = tuple(str(column) for column in item.get("columns", []))
    parameters = tuple(str(parameter) for parameter in item.get("parameters", ["case_id", "limit"]))
    unsupported = [parameter for parameter in parameters if parameter not in {"case_id", "limit"}]
    if unsupported:
        raise ValueError(f"Report spec {name} has unsupported parameters: {unsupported}")
    return ReportSpec(
        name=name,
        title=str(item.get("title") or name),
        description=str(item.get("description") or ""),
        store=store,
        query=query,
        columns=columns,
        parameters=parameters,
        source=path,
    )


def _validate_read_only_query(name: str, query: str) -> None:
    normalized = query.strip().lower()
    if not normalized.startswith("select") and not normalized.startswith("with"):
        raise ValueError(f"Report spec {name} must use a SELECT query")
    if ";" in query.rstrip(";"):
        raise ValueError(f"Report spec {name} must contain a single query")
    blocked = re.search(
        r"\b(insert|update|delete|drop|alter|create|copy|attach|detach|pragma|vacuum|call)\b",
        normalized,
    )
    if blocked:
        raise ValueError(f"Report spec {name} contains blocked SQL keyword: {blocked.group(1)}")


def _parameter_value(parameter: str, case_id: str, limit: int) -> Any:
    if parameter == "case_id":
        return case_id
    if parameter == "limit":
        return limit
    raise ValueError(f"Unsupported report parameter: {parameter}")


def _execute_spec_query(db: Database, case_id: str, spec: ReportSpec, params: list[Any]) -> list[dict[str, Any]]:
    if spec.store == "sqlite":
        rows = db.conn.execute(spec.query, params).fetchall()
        return [dict(row) for row in rows]

    db_path = db.get_case(case_id).root / "analytics" / "events.duckdb"
    if not db_path.exists():
        raise FileNotFoundError(f"DuckDB analytics database not found for case {case_id}: {db_path}")
    conn, should_close = _duckdb_report_connection(db, case_id, db_path)
    try:
        result = conn.execute(spec.query, params)
        names = [column[0] for column in result.description or []]
        return [dict(zip(names, row, strict=False)) for row in result.fetchall()]
    finally:
        if should_close:
            conn.close()


def _duckdb_report_connection(
    db: Database,
    case_id: str,
    db_path: Path,
) -> tuple[duckdb.DuckDBPyConnection, bool]:
    analytics = getattr(db, "analytics", None)
    if analytics is not None and hasattr(analytics, "_connect"):
        return analytics._connect(case_id), False
    return duckdb.connect(str(db_path), read_only=True), True
