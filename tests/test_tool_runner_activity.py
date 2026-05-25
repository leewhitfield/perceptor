from pathlib import Path

from forensic_orchestrator.db import Database
from forensic_orchestrator.jobs import CommandResult
from forensic_orchestrator.models import ToolDefinition
from forensic_orchestrator.paths import WorkspacePaths
from forensic_orchestrator.tools import runner


def test_no_csv_records_platform_unsupported_activity(monkeypatch, tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    paths = WorkspacePaths(tmp_path)
    stdout_path = paths.outputs_dir(case.id) / "image-1" / "PECmd" / "_job" / "stdout.txt"
    stderr_path = stdout_path.with_name("stderr.txt")
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stdout_path.write_text(
        "Non-Windows platforms not supported due to the need to load decompression specific Windows libraries!\n"
    )
    stderr_path.write_text("")

    def fake_validate_tool(*args, **kwargs):
        return None

    def fake_detect_tool_version(*args, **kwargs):
        return None

    class FakeJobRunner:
        def __init__(self, db):
            self.db = db

        def run(self, **kwargs):
            return CommandResult("job-1", 0, stdout_path, stderr_path, stdout_path.parent.parent)

    monkeypatch.setattr(runner, "validate_tool", fake_validate_tool)
    monkeypatch.setattr(runner, "detect_tool_version", fake_detect_tool_version)
    monkeypatch.setattr(runner, "JobRunner", FakeJobRunner)

    runner.run_tool(
        db=db,
        paths=paths,
        case_id=case.id,
        image_id="image-1",
        computer_id="computer-1",
        tool=ToolDefinition(
            name="PECmd",
            enabled=True,
            type="dotnet",
            executable="/opt/eztools/PECmd/PECmd.dll",
            command=["dotnet", "{executable}", "--csv", "{output}"],
            required_paths=[],
            outputs=["csv"],
            artifacts=[],
        ),
        mount=Path("/unused"),
        dry_run=False,
    )

    activity = db.activity_for_case(case.id, level="warning")
    assert activity[0]["event"] == "tool.platform_unsupported"
    assert "parser reported platform unsupported" in activity[0]["message"]
    assert "Non-Windows platforms not supported" in activity[0]["details_json"]


def test_split_external_tool_generate_then_serial_ingest(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    paths = WorkspacePaths(tmp_path)
    script = tmp_path / "write_csv.sh"
    script.write_text(
        "#!/bin/sh\n"
        "mkdir -p \"$1\"\n"
        "printf 'SourceFile,SourceCreated,SourceModified,SourceAccessed,FileName,FileSize\\n' > \"$1/LECmd_Output.csv\"\n"
        "printf '/tmp/a.lnk,2020-01-01T00:00:00Z,2020-01-01T00:00:00Z,2020-01-01T00:00:00Z,a.txt,1\\n' >> \"$1/LECmd_Output.csv\"\n"
    )
    script.chmod(0o755)
    tool = ToolDefinition(
        name="LECmd",
        enabled=True,
        type="binary",
        executable=str(script),
        command=["{executable}", "{output}"],
        required_paths=[],
        outputs=["csv"],
        artifacts=[],
    )

    generated = runner.generate_external_tool_outputs(
        paths=paths,
        case_id=case.id,
        image_id="image-1",
        tool=tool,
        mount=Path("/unused"),
        dry_run=False,
    )
    runner.ingest_generated_tool_outputs(
        db=db,
        case_id=case.id,
        image_id="image-1",
        computer_id="computer-1",
        tool=tool,
        generated=generated,
        rebuild_correlations=False,
    )

    outputs = db.conn.execute("SELECT tool_name, row_count FROM tool_outputs WHERE case_id = ?", (case.id,)).fetchall()
    assert [tuple(row) for row in outputs] == [("LECmd", 1)]
    jobs = db.conn.execute("SELECT tool_name, exit_code FROM jobs WHERE case_id = ?", (case.id,)).fetchall()
    assert [tuple(row) for row in jobs] == [("LECmd", 0)]
