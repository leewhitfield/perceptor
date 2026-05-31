from __future__ import annotations

import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path

from .db import Database, utc_now
from .safety import ToolError


@dataclass(frozen=True)
class CommandResult:
    job_id: str
    exit_code: int | None
    stdout_path: Path
    stderr_path: Path
    output_folder: Path


class JobRunner:
    def __init__(self, db: Database) -> None:
        self.db = db

    def run(
        self,
        *,
        case_id: str,
        image_id: str,
        tool_name: str,
        command: list[str],
        output_folder: Path,
        dry_run: bool,
        tool_version: str | None = None,
        computer_id: str | None = None,
        source_scope: str | None = None,
        check: bool = True,
        nonzero_level: str = "error",
        nonzero_event: str = "job.finished",
        nonzero_message: str | None = None,
    ) -> CommandResult:
        job_id = str(uuid.uuid4())
        job_dir = output_folder / "_job"
        job_dir.mkdir(parents=True, exist_ok=True)
        stdout_path = job_dir / "stdout.txt"
        stderr_path = job_dir / "stderr.txt"
        start_time = utc_now()

        self.db.create_job(
            {
                "id": job_id,
                "case_id": case_id,
                "image_id": image_id,
                "computer_id": computer_id,
                "source_scope": source_scope,
                "tool_name": tool_name,
                "tool_version": tool_version,
                "command": command,
                "start_time": start_time,
                "end_time": utc_now() if dry_run else None,
                "exit_code": 0 if dry_run else None,
                "stdout_path": stdout_path,
                "stderr_path": stderr_path,
                "output_folder": output_folder,
                "dry_run": dry_run,
            }
        )
        self.db.log_activity(
            case_id=case_id,
            computer_id=computer_id,
            image_id=image_id,
            job_id=job_id,
            event="job.started",
            message=f"Started {tool_name}",
            details={"command": command, "output_folder": str(output_folder), "dry_run": dry_run},
        )

        if dry_run:
            stdout_path.write_text("DRY RUN: command not executed\n" + repr(command) + "\n")
            stderr_path.write_text("")
            self.db.log_activity(
                case_id=case_id,
                computer_id=computer_id,
                image_id=image_id,
                job_id=job_id,
                event="job.dry_run",
                message=f"Dry-run recorded {tool_name}; command was not executed",
                details={"stdout_path": str(stdout_path), "stderr_path": str(stderr_path)},
            )
            return CommandResult(job_id, 0, stdout_path, stderr_path, output_folder)

        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            completed = subprocess.run(command, stdout=stdout, stderr=stderr, check=False)

        end_time = utc_now()
        self.db.finish_job(job_id, end_time, completed.returncode)
        self.db.log_activity(
            case_id=case_id,
            computer_id=computer_id,
            image_id=image_id,
            job_id=job_id,
            level=nonzero_level if completed.returncode != 0 else "info",
            event=nonzero_event if completed.returncode != 0 else "job.finished",
            message=(
                nonzero_message.format(tool_name=tool_name, exit_code=completed.returncode)
                if completed.returncode != 0 and nonzero_message
                else f"Finished {tool_name} with exit code {completed.returncode}"
            ),
            details={
                "exit_code": completed.returncode,
                "stdout_path": str(stdout_path),
                "stderr_path": str(stderr_path),
                "anticipated_nonzero": completed.returncode != 0 and nonzero_level != "error",
            },
        )

        if check and completed.returncode != 0:
            raise ToolError(
                f"{tool_name} failed with exit code {completed.returncode}; "
                f"stdout={stdout_path} stderr={stderr_path}"
            )

        return CommandResult(job_id, completed.returncode, stdout_path, stderr_path, output_folder)
