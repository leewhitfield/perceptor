import csv
import sqlite3

from forensic_orchestrator.tools.package_artifacts import parse_package_artifacts_to_csv


def test_package_artifacts_parser_extracts_examiner_edge_artifacts(tmp_path):
    root = tmp_path / "image"
    output = tmp_path / "out"

    sticky = (
        root
        / "Users"
        / "Maya"
        / "AppData"
        / "Local"
        / "Packages"
        / "Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe"
        / "LocalState"
        / "plum.sqlite"
    )
    sticky.parent.mkdir(parents=True)
    conn = sqlite3.connect(sticky)
    conn.execute("CREATE TABLE Note (Text TEXT, UpdatedAt INTEGER)")
    conn.execute("INSERT INTO Note VALUES (?, ?)", ("VPN password reminder", 638989812000000000))
    conn.commit()
    conn.close()

    task = root / "Windows" / "System32" / "Tasks" / "Updater"
    task.parent.mkdir(parents=True)
    task.write_text(
        """<?xml version="1.0"?>
<Task>
  <RegistrationInfo><Date>2025-11-17T13:00:00Z</Date><Author>Maya</Author></RegistrationInfo>
  <Principals><Principal><UserId>S-1-5-21-1000</UserId></Principal></Principals>
  <Triggers><LogonTrigger /></Triggers>
  <Actions><Exec><Command>powershell.exe</Command><Arguments>-NoP -File update.ps1</Arguments></Exec></Actions>
</Task>""",
        encoding="utf-8",
    )

    hosts = root / "Windows" / "System32" / "drivers" / "etc" / "hosts"
    hosts.parent.mkdir(parents=True)
    hosts.write_text("127.0.0.1 blocked.example\n", encoding="utf-8")

    wsl = (
        root
        / "Users"
        / "Maya"
        / "AppData"
        / "Local"
        / "Packages"
        / "CanonicalGroupLimited.Ubuntu_79rhkp1fndgsc"
        / "LocalState"
        / "ext4.vhdx"
    )
    wsl.parent.mkdir(parents=True)
    wsl.write_bytes(b"vhdx")

    credential = root / "Users" / "Maya" / "AppData" / "Local" / "Microsoft" / "Credentials" / "ABCDEF"
    credential.parent.mkdir(parents=True)
    credential.write_bytes(b"credential blob")

    eventtranscript = root / "ProgramData" / "Microsoft" / "Diagnosis" / "EventTranscript" / "EventTranscript.db"
    eventtranscript.parent.mkdir(parents=True)
    conn = sqlite3.connect(eventtranscript)
    conn.execute("CREATE TABLE Events (EventName TEXT, AppName TEXT, Timestamp TEXT, Payload TEXT)")
    conn.execute(
        "INSERT INTO Events VALUES (?, ?, ?, ?)",
        ("AppLaunch", "WINWORD.EXE", "2025-11-17T14:00:00Z", "opened document"),
    )
    conn.execute(
        "INSERT INTO Events VALUES (?, ?, ?, ?)",
        ("NetworkConnect", "", "2025-11-17T14:05:00Z", "connected to https://example.test"),
    )
    conn.execute(
        "INSERT INTO Events VALUES (?, ?, ?, ?)",
        ("FileOpen", "", "2025-11-17T14:10:00Z", "C:\\Users\\Maya\\Desktop\\plan.docx"),
    )
    conn.execute(
        "INSERT INTO Events VALUES (?, ?, ?, ?)",
        ("DeviceCensus", "", "2025-11-17T14:15:00Z", "Bluetooth keyboard"),
    )
    conn.commit()
    conn.close()

    tokenbroker = root / "Users" / "Maya" / "AppData" / "Local" / "Microsoft" / "TokenBroker" / "Cache" / "account.tbres"
    tokenbroker.parent.mkdir(parents=True)
    tokenbroker.write_text('{"account":"maya@example.com","updated":"2025-11-17T15:00:00Z"}', encoding="utf-8")

    thumbs = root / "Users" / "Maya" / "Desktop" / "NetworkShare" / "Thumbs.db"
    thumbs.parent.mkdir(parents=True)
    thumbs.write_bytes(b"\xd0\xcf\x11\xe0legacy thumbs")

    csv_paths = parse_package_artifacts_to_csv(root, output)
    with csv_paths[0].open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))

    record_types = {row["record_type"] for row in rows}
    assert "sticky_note" in record_types
    assert "scheduled_task_xml" in record_types
    assert "eventtranscript_app_launch" in record_types
    assert "eventtranscript_network_activity" in record_types
    assert "eventtranscript_file_activity" in record_types
    assert "eventtranscript_device_census" in record_types
    assert "hosts_mapping" in record_types
    assert "legacy_thumbs_db" in record_types
    assert "tokenbroker_account" in record_types
    assert "wsl_ext4_vhdx" in record_types
    assert "windows_credential_file" in record_types
    assert any(row["artifact_text"] == "VPN password reminder" for row in rows)
    assert any(row["record_type"] == "eventtranscript_app_launch" and row["artifact_value"] == "WINWORD.EXE" for row in rows)
    assert any(row["artifact_value"] == "maya@example.com" for row in rows)
    assert any(row["record_type"] == "sticky_note" and row["event_time_utc"].startswith("2025-11-17T13:00:00") for row in rows)
    assert any("powershell.exe" in row["artifact_value"] for row in rows)
