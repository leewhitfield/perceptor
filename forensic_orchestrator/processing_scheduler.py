from __future__ import annotations

from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
import time
from typing import Any


@dataclass(frozen=True)
class ProcessingTask:
    name: str
    worker: Callable[[], Any]
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ProcessingResult:
    name: str
    status: str
    payload: dict[str, Any]
    value: Any = None
    error: str = ""
    duration_seconds: float = 0.0


def run_processing_tasks(tasks: Sequence[ProcessingTask], *, workers: int = 1) -> list[ProcessingResult]:
    if workers < 1:
        raise ValueError("workers must be at least 1")
    if not tasks:
        return []
    if workers == 1 or len(tasks) == 1:
        return [_run_task(task) for task in tasks]

    results: list[ProcessingResult | None] = [None] * len(tasks)
    max_workers = min(workers, len(tasks))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_run_task, task): index for index, task in enumerate(tasks)}
        for future in as_completed(futures):
            results[futures[future]] = future.result()
    return [result for result in results if result is not None]


def _run_task(task: ProcessingTask) -> ProcessingResult:
    started = time.monotonic()
    try:
        value = task.worker()
        return ProcessingResult(
            name=task.name,
            status="completed",
            payload=task.payload,
            value=value,
            duration_seconds=time.monotonic() - started,
        )
    except Exception as exc:
        return ProcessingResult(
            name=task.name,
            status="failed",
            payload=task.payload,
            error=str(exc),
            duration_seconds=time.monotonic() - started,
        )
