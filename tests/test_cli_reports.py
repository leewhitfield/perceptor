from __future__ import annotations

import json

from forensic_orchestrator.cli import main as cli_main
from forensic_orchestrator.db import Database
from forensic_orchestrator.paths import WorkspacePaths


def test_cli_search_progress_and_gap_reports(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("FORENSIC_ANALYTICS_MODE", "sqlite")
    paths = WorkspacePaths(tmp_path / "workspace")
    db = Database(paths.db_path())
    db.create_case("case-1", paths.case_dir("case-1"))
    db.create_computer(computer_id="computer-1", case_id="case-1", label="HOST01")
    db.add_image("image-1", "case-1", tmp_path / "host.E01", computer_id="computer-1")
    db.insert_shellbag_entries(
        [
            {
                "id": "shellbag-1",
                "case_id": "case-1",
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "tool-1",
                "tool_name": "SBECmd",
                "source_csv": tmp_path / "shellbags.csv",
                "row_number": 1,
                "user_profile": "Alice",
                "absolute_path": "E:/Cases/powershell notes",
                "drive_letter": "E:",
                "volume_serial_number": "ABCD-1234",
                "last_write_time": "2024-01-01T00:00:00Z",
                "created_at": "2024-01-01T00:00:00Z",
            }
        ]
    )
    db.close()
    progress_dir = paths.root / "progress"
    progress_dir.mkdir(parents=True)
    (progress_dir / "report-bundle-many-test.json").write_text(
        json.dumps({"stage": "completed", "case_id": "case-1", "computers_total": 1, "computers_done": 1, "imported_rows": 7}),
        encoding="utf-8",
    )
    bundle_root = tmp_path / "bundle" / "HOST01"
    bundle_root.mkdir(parents=True)
    (bundle_root / "unknown.csv").write_text("alpha,beta\n1,2\n", encoding="utf-8")

    assert cli_main(["--root", str(paths.root), "report", "artifact-search", "--case", "case-1", "--query", "powershell", "--format", "json"]) == 0
    artifact = json.loads(capsys.readouterr().out)
    assert artifact["summary"]["result_count"] == 1
    assert artifact["results"][0]["drilldown"]["tool"] == "relic_file_dossier"
    assert artifact["results"][0]["score"] > 0

    assert cli_main(["--root", str(paths.root), "report", "lead-search", "--case", "case-1", "--preset", "usb", "--query", "powershell", "--format", "json"]) == 0
    lead = json.loads(capsys.readouterr().out)
    assert lead["preset"] == "usb"
    assert lead["summary"]["result_count"] == 1
    packet_path = tmp_path / "search-packet.json"
    packet_path.write_text(
        json.dumps({"case_id": "case-1", "search_type": "lead", "arguments": {"case_id": "case-1", "preset": "usb", "query": "powershell", "limit": 100}, "search": lead}),
        encoding="utf-8",
    )
    case_packet_dir = paths.case_dir("case-1") / "reports" / "mcp-search-packets"
    case_packet_dir.mkdir(parents=True, exist_ok=True)
    (case_packet_dir / "usb-lead-search-packet.json").write_text(packet_path.read_text(encoding="utf-8"), encoding="utf-8")
    assert cli_main(["--root", str(paths.root), "report", "rerun-search-packet", "--packet", str(packet_path), "--format", "json"]) == 0
    rerun = json.loads(capsys.readouterr().out)
    assert rerun["comparison"]["unchanged_count"] == 1
    assert rerun["comparison"]["changed_count"] == 0
    assert cli_main(["--root", str(paths.root), "report", "rerun-search-packet", "--packet", str(packet_path), "--format", "md"]) == 0
    assert "# Search Packet Rerun" in capsys.readouterr().out

    assert cli_main(["--root", str(paths.root), "report", "changed-search-packets", "--case", "case-1", "--format", "json"]) == 0
    changed_packets = json.loads(capsys.readouterr().out)
    assert changed_packets["summary"]["packet_count"] == 1
    assert changed_packets["summary"]["changed_packet_count"] == 0

    assert cli_main(["--root", str(paths.root), "report", "review-status", "--case", "case-1", "--format", "json"]) == 0
    review_status = json.loads(capsys.readouterr().out)
    assert any(row["category"] == "packets" for row in review_status["items"])

    assert cli_main(["--root", str(paths.root), "report", "runbook", "--case", "case-1", "--format", "json"]) == 0
    runbook = json.loads(capsys.readouterr().out)
    assert any("review-status" in row["command"] for row in runbook["commands"])

    assert cli_main(["--root", str(paths.root), "report", "artifact-search-sources", "--case", "case-1", "--format", "json"]) == 0
    sources = json.loads(capsys.readouterr().out)
    shellbag_source = next(row for row in sources["sources"] if row["table"] == "shellbag_entries")
    assert shellbag_source["populated"] is True
    assert shellbag_source["row_count"] == 1

    assert cli_main(["--root", str(paths.root), "report", "workspace-map", "--case", "case-1", "--format", "json"]) == 0
    workspace = json.loads(capsys.readouterr().out)
    assert workspace["summary"]["case_count"] == 1
    assert workspace["cases"][0]["computers"][0]["label"] == "HOST01"

    assert cli_main(["--root", str(paths.root), "report", "progress-manifests", "--format", "json"]) == 0
    progress = json.loads(capsys.readouterr().out)
    assert progress["summary"]["completed_count"] == 1

    assert cli_main(["--root", str(paths.root), "report-bundle", "gaps", "--path", str(tmp_path / "bundle"), "--format", "json"]) == 0
    gaps = json.loads(capsys.readouterr().out)
    assert gaps["summary"]["unmapped_group_count"] == 1

    assert cli_main(["--root", str(paths.root), "report", "next-actions", "--case", "case-1", "--format", "json"]) == 0
    actions = json.loads(capsys.readouterr().out)
    assert actions["case_id"] == "case-1"

    assert cli_main(["--root", str(paths.root), "report", "activity-digest", "--case", "case-1", "--format", "json"]) == 0
    digest = json.loads(capsys.readouterr().out)
    assert digest["case_id"] == "case-1"

    assert cli_main(["--root", str(paths.root), "report", "activity-digest", "--case", "case-1", "--format", "md"]) == 0
    assert "# Case Activity Digest" in capsys.readouterr().out
