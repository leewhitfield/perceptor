from __future__ import annotations

import csv
from pathlib import Path

from forensic_orchestrator.tools.windows_mail import parse_windows_mail_artifacts_to_csv


def test_windows_mail_parser_extracts_efmdata_html(tmp_path: Path) -> None:
    source = (
        tmp_path
        / "Users"
        / "Jean"
        / "AppData"
        / "Local"
        / "Packages"
        / "microsoft.windowscommunicationsapps_8wekyb3d8bbwe"
        / "LocalState"
        / "Files"
        / "S0"
        / "4"
        / "EFMData"
    )
    source.mkdir(parents=True)
    (source / "1.dat").write_text(
        "<!doctype html><html><head><title>Daily Brief</title></head>"
        "<body><p>FTL communications update</p></body></html>",
        encoding="utf-8",
    )

    output = tmp_path / "out"
    parse_windows_mail_artifacts_to_csv(tmp_path / "Users", output)

    with (output / "MailboxMessages.csv").open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))

    assert len(rows) == 1
    assert rows[0]["source_format"] == "windows_mail_efmdata_html"
    assert rows[0]["parser_status"] == "body_file_extracted"
    assert rows[0]["user_profile"] == "Jean"
    assert rows[0]["subject"] == "Daily Brief"
    assert "FTL communications update" in rows[0]["body_text"]


def test_windows_mail_parser_extracts_unistore_utf16_body(tmp_path: Path) -> None:
    source = (
        tmp_path
        / "Users"
        / "Devon"
        / "AppData"
        / "Local"
        / "Comms"
        / "Unistore"
        / "data"
        / "5"
        / "a"
    )
    source.mkdir(parents=True)
    (source / "0000000000000005001e.dat").write_bytes(
        "Subject: Test\r\n\r\nThis is Windows Mail body content.".encode("utf-16-be")
    )

    output = tmp_path / "out"
    parse_windows_mail_artifacts_to_csv(tmp_path / "Users", output)

    with (output / "MailboxMessages.csv").open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))

    assert len(rows) == 1
    assert rows[0]["source_format"] == "windows_mail_unistore_body"
    assert rows[0]["user_profile"] == "Devon"
    assert "Windows Mail body content" in rows[0]["body_text"]
