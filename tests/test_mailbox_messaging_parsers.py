import csv
from pathlib import Path

from forensic_orchestrator.db import Database
import forensic_orchestrator.tools.ingest as ingest_module
from forensic_orchestrator.tools.ingest import ingest_csv_output
from forensic_orchestrator.tools.mailbox import parse_mailbox_artifacts_to_csv
from forensic_orchestrator.tools.messaging import parse_messaging_artifacts_to_csv
import pytest


class _FakeContentIndexer:
    documents: list[dict[str, object]] = []

    def __init__(self, config, *, batch_size=500):
        self.config = config

    def add(self, document):
        if document:
            self.documents.append(document)

    def close(self, db, *, case_id):
        return None


def _capture_content(monkeypatch):
    _FakeContentIndexer.documents = []
    monkeypatch.setattr(ingest_module, "IngestContentIndexer", _FakeContentIndexer)
    return _FakeContentIndexer.documents


class _FailingContentIndexer:
    def __init__(self, config, *, batch_size=500):
        self.config = config

    def add(self, document):
        if document:
            raise RuntimeError("opensearch unavailable")

    def close(self, db, *, case_id):
        return None


def test_mailbox_parser_extracts_eml_and_ingests_messages(tmp_path, monkeypatch):
    documents = _capture_content(monkeypatch)
    source = tmp_path / "mail"
    source.mkdir()
    eml = source / "message.eml"
    eml.write_text(
        "From: Jane <jane@example.test>\n"
        "To: Devon <devon@example.test>\n"
        "Subject: Project Update\n"
        "Thread-Index: Adx123456789\n"
        "Thread-Topic: Project Update\n"
        "References: <root@example.test>\n"
        "Reply-To: Jane Reply <reply@example.test>\n"
        "Importance: high\n"
        "X-Originating-IP: [192.0.2.10]\n"
        "Date: Sat, 14 Nov 2020 04:29:51 +0000\n"
        "\n"
        "The file is attached.\n",
        encoding="utf-8",
    )
    csv_path = parse_mailbox_artifacts_to_csv(source, tmp_path / "out")
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")

    count = ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-mailbox",
        tool_name="MailboxParser",
        path=csv_path,
    )
    row = db.conn.execute(
        "SELECT subject, sender, recipients, body_text, body_text_length, body_text_sha256 FROM mailbox_messages"
    ).fetchone()
    metadata = db.conn.execute(
        """
        SELECT source_format, parser_status, user_profile, attachment_count, has_attachments,
               conversation_index, conversation_topic, references_header, reply_to, importance, x_originating_ip
        FROM mailbox_messages
        """
    ).fetchone()
    content_ref = db.conn.execute(
        """
        SELECT source_table, content_role, opensearch_document_id, content_sha256, content_length
        FROM content_references
        WHERE source_table = 'mailbox_messages'
        """
    ).fetchone()

    assert count == 1
    assert row["subject"] == "Project Update"
    assert "jane@example.test" in row["sender"]
    assert "devon@example.test" in row["recipients"]
    assert row["body_text"] == ""
    assert row["body_text_length"] > 0
    assert row["body_text_sha256"]
    assert any("attached" in str(document["content"]) for document in documents)
    assert metadata["source_format"] == "eml"
    assert metadata["parser_status"] == "parsed"
    assert metadata["conversation_index"] == "Adx123456789"
    assert metadata["conversation_topic"] == "Project Update"
    assert metadata["references_header"] == "<root@example.test>"
    assert metadata["reply_to"] == "Jane Reply <reply@example.test>"
    assert metadata["importance"] == "high"
    assert metadata["x_originating_ip"] == "[192.0.2.10]"
    assert metadata["attachment_count"] == 0
    assert metadata["has_attachments"] == "0"
    assert content_ref["content_role"] == "message_body"
    assert content_ref["opensearch_document_id"] == documents[0]["id"]
    assert content_ref["content_sha256"]
    assert content_ref["content_length"] > 0


def test_mailbox_parser_extracts_attachment_rows(tmp_path):
    source = tmp_path / "mail"
    source.mkdir()
    eml = source / "message.eml"
    eml.write_text(
        "From: Jane <jane@example.test>\n"
        "To: Devon <devon@example.test>\n"
        "Subject: Attachment Test\n"
        "Thread-Index: AdxAttachment\n"
        "Thread-Topic: Attachment Test\n"
        "Date: Sat, 14 Nov 2020 04:29:51 +0000\n"
        "MIME-Version: 1.0\n"
        "Content-Type: multipart/mixed; boundary=\"b\"\n"
        "\n"
        "--b\n"
        "Content-Type: text/plain\n\n"
        "See attached.\n"
        "--b\n"
        "Content-Type: text/plain; name=\"notes.txt\"\n"
        "Content-Disposition: attachment; filename=\"notes.txt\"\n"
        "\n"
        "Attachment text mentioning Falcon.\n"
        "--b--\n",
        encoding="utf-8",
    )

    parse_mailbox_artifacts_to_csv(source, tmp_path / "out")
    attachment_csv = tmp_path / "out" / "MailboxAttachments.csv"
    text = attachment_csv.read_text(encoding="utf-8")

    assert "notes.txt" in text
    assert "Attachment text mentioning Falcon" in text
    assert "AdxAttachment" in text


def test_opensearch_ingest_failure_is_logged(tmp_path, monkeypatch):
    monkeypatch.setattr(ingest_module, "IngestContentIndexer", _FailingContentIndexer)
    source = tmp_path / "mail"
    source.mkdir()
    (source / "message.eml").write_text(
        "From: Jane <jane@example.test>\n"
        "To: Devon <devon@example.test>\n"
        "Subject: Project Update\n\n"
        "The file is attached.\n",
        encoding="utf-8",
    )
    csv_path = parse_mailbox_artifacts_to_csv(source, tmp_path / "out")
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")

    with pytest.raises(RuntimeError, match="opensearch unavailable"):
        ingest_csv_output(
            db=db,
            case_id=case.id,
            computer_id="computer-1",
            image_id="image-1",
            tool_output_id="output-mailbox",
            tool_name="MailboxParser",
            path=csv_path,
        )

    activity = db.conn.execute(
        "SELECT event, level, details_json FROM activity_log WHERE event = 'search.opensearch_write_failed'"
    ).fetchone()
    assert activity["level"] == "error"
    assert "opensearch unavailable" in activity["details_json"]


def test_mailbox_parser_derives_text_from_html_body(tmp_path):
    source = tmp_path / "mail"
    source.mkdir()
    eml = source / "message.eml"
    eml.write_text(
        "From: Jane <jane@example.test>\n"
        "To: Devon <devon@example.test>\n"
        "Subject: HTML Only\n"
        "Date: Sat, 14 Nov 2020 04:29:51 +0000\n"
        "MIME-Version: 1.0\n"
        "Content-Type: text/html; charset=utf-8\n"
        "\n"
        "<html><body><div>Hello <b>Devon</b></div><p>Falcon update</p></body></html>",
        encoding="utf-8",
    )

    csv_path = parse_mailbox_artifacts_to_csv(source, tmp_path / "out")
    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        text = handle.read()

    assert "Hello Devon" in text
    assert "Falcon update" in text


def test_mailbox_parser_records_zero_filled_pst_from_manifest(tmp_path):
    source = tmp_path / "mail"
    source.mkdir()
    pst = tmp_path / "EXFIL.pst"
    pst.write_bytes(b"\x00" * 4096)
    manifest = source / "_artifact_manifest.csv"
    manifest.write_text(
        "artifact_path,original_path\n"
        f"{pst},Users/fredr/iCloudDrive/EXFIL.pst\n",
        encoding="utf-8",
    )

    csv_path = parse_mailbox_artifacts_to_csv(source, tmp_path / "out")
    rows = csv_path.read_text(encoding="utf-8").splitlines()

    assert "mailbox_zero_filled" in "\n".join(rows)
    assert str(pst) in "\n".join(rows)


def test_messaging_parser_extracts_leveldb_candidate_strings_and_ingests(tmp_path, monkeypatch):
    documents = _capture_content(monkeypatch)
    source = tmp_path / "Users" / "Jane" / "AppData" / "Roaming" / "Slack" / "Local Storage" / "leveldb"
    source.mkdir(parents=True)
    leveldb = source / "000001.log"
    leveldb.write_bytes(
        b"\x00\x01message hello from slack channel https://example.test/thread\x00"
        b'{"type":"message","client_msg_id":"abc","channel":"C1","user":"U1",'
        b'"ts":"1605328315.929","text":"Structured hello from Slack"}'
    )
    csv_path = parse_messaging_artifacts_to_csv(tmp_path / "Users", tmp_path / "out")
    message_csv_path = tmp_path / "out" / "MessagingMessages.csv"
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")

    count = ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-messaging",
        tool_name="MessagingParser",
        path=csv_path,
    )
    message_count = ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-messaging-messages",
        tool_name="MessagingParser",
        path=message_csv_path,
    )
    row = db.conn.execute(
        "SELECT application, user_profile, artifact_type, record_type, url, host, message_text, message_text_length "
        "FROM messaging_records WHERE url = 'https://example.test/thread'"
    ).fetchone()
    message_row = db.conn.execute(
        "SELECT application, channel_id, sender_id, timestamp_utc, message_text, message_text_length FROM messaging_messages"
    ).fetchone()
    content_refs = db.conn.execute(
        """
        SELECT source_table, content_role, opensearch_document_id
        FROM content_references
        ORDER BY source_table, content_role
        """
    ).fetchall()

    assert count >= 1
    assert message_count == 1
    assert row["application"] == "Slack"
    assert row["user_profile"] == "Jane"
    assert row["artifact_type"] == "leveldb_candidate"
    assert row["record_type"] == "message_candidate"
    assert row["url"] == "https://example.test/thread"
    assert row["host"] == "example.test"
    assert row["message_text"] == ""
    assert row["message_text_length"] > 0
    assert message_row["application"] == "Slack"
    assert message_row["channel_id"] == "C1"
    assert message_row["sender_id"] == "U1"
    assert message_row["timestamp_utc"].startswith("2020-11-14T")
    assert message_row["message_text"] == ""
    assert message_row["message_text_length"] > 0
    assert any("slack channel" in str(document["content"]) for document in documents)
    assert any("Structured hello from Slack" in str(document["content"]) for document in documents)
    assert {row["source_table"] for row in content_refs} == {"messaging_messages", "messaging_records"}
    assert {row["content_role"] for row in content_refs} == {"chat_message", "message_text"}
    assert {row["opensearch_document_id"] for row in content_refs} == {document["id"] for document in documents}


def test_slack_parser_filters_telemetry_noise_and_keeps_readable_metadata(tmp_path):
    source = tmp_path / "Users" / "Jane" / "AppData" / "Roaming" / "Slack"
    log_dir = source / "logs"
    leveldb_dir = source / "Local Storage" / "leveldb"
    log_dir.mkdir(parents=True)
    leveldb_dir.mkdir(parents=True)
    (log_dir / "browser.log").write_text(
        "[11/04/20, 05:37:15:123] info: Slack 4.10.3 win32 Store Windows 10.0.19041 x64\n"
        "[11/04/20, 05:37:16:123] info: AutoLoginEpic: Completed autologin processing - successfully logged in 0 workspaces\n"
        "[11/04/20, 05:37:17:123] info: workspaces: \"Not signed in to any workspaces\"\n"
        "[11/04/20, 05:37:18:123] info: MetricsSender cache_hit https://slack.com/beacon/timing\n",
        encoding="utf-8",
    )
    (leveldb_dir / "000001.log").write_bytes(
        b"https://slack.com/beacon/timing?team_id=T01AAAAAAA&user_id=U01BBBBBBB\x00"
        b"channel:C01CCCCCCC msg_ts:1604460270.002300 team_id=T01AAAAAAA user_id=U01BBBBBBB desc:The user is in Do Not Disturb\x00"
        b"https://starkresearchlabs.sharepoint.com/sites/project/Documents/report.docx\x00"
    )

    csv_path = parse_messaging_artifacts_to_csv(tmp_path / "Users", tmp_path / "out")
    with csv_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    record_types = {row["record_type"] for row in rows}
    urls = {row["url"] for row in rows if row["url"]}
    record_keys = "\n".join(row["record_key"] for row in rows)

    assert "slack_client_start" in record_types
    assert "slack_signin_state" in record_types
    assert "slack_notification_metadata" in record_types
    assert "url_reference" in record_types
    assert not any("/beacon/" in url for url in urls)
    assert "https://starkresearchlabs.sharepoint.com/sites/project/Documents/report.docx" in urls
    assert "channel=C01CCCCCCC" in record_keys
    assert "successfully logged in 0 workspaces" in record_keys


def test_messaging_parser_captures_remote_access_app_history(tmp_path):
    source = tmp_path / "Users" / "Jane" / "AppData" / "Roaming" / "AnyDesk"
    source.mkdir(parents=True)
    (source / "ad_svc.trace").write_text(
        "2024-01-02T03:04:05Z session connected to support.example.test alias 123456789\n",
        encoding="utf-8",
    )

    csv_path = parse_messaging_artifacts_to_csv(tmp_path / "Users", tmp_path / "out")
    with csv_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))

    assert rows
    assert rows[0]["application"] == "AnyDesk"
    assert rows[0]["record_type"] == "application_config_or_history"
    assert rows[0]["artifact_type"] == "log_file"


def test_messaging_parser_extracts_ai_app_json_and_obsidian_notes(tmp_path, monkeypatch):
    documents = _capture_content(monkeypatch)
    chatgpt = tmp_path / "Users" / "Jane" / "AppData" / "Roaming" / "ChatGPT" / "IndexedDB"
    chatgpt.mkdir(parents=True)
    (chatgpt / "000001.log").write_bytes(
        b'{"conversation_id":"conv-1","message_id":"msg-1","role":"assistant",'
        b'"create_time":"2024-05-01T12:00:00Z","content":"Use the red folder for project notes."}'
    )
    vault = tmp_path / "Users" / "Jane" / "Documents" / "Vault" / ".obsidian"
    vault.mkdir(parents=True)
    note = tmp_path / "Users" / "Jane" / "Documents" / "Vault" / "Case Notes.md"
    note.write_text("# Case Notes\nThe suspect mentioned the red folder in Obsidian.\n", encoding="utf-8")
    (vault / "workspace.json").write_text('{"active":"Case Notes.md"}', encoding="utf-8")

    csv_path = parse_messaging_artifacts_to_csv(tmp_path / "Users", tmp_path / "out")
    message_csv_path = tmp_path / "out" / "MessagingMessages.csv"
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")

    ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-app-records",
        tool_name="MessagingParser",
        path=csv_path,
    )
    ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-app-messages",
        tool_name="MessagingParser",
        path=message_csv_path,
    )

    chat_row = db.conn.execute(
        "SELECT application, conversation_id, message_text, message_text_length FROM messaging_messages WHERE application = 'ChatGPT'"
    ).fetchone()
    note_row = db.conn.execute(
        "SELECT application, artifact_type, record_type, message_text, message_text_length "
        "FROM messaging_records WHERE application = 'Obsidian' AND artifact_type = 'markdown_note'"
    ).fetchone()

    assert chat_row["conversation_id"] == "conv-1"
    assert chat_row["message_text"] == ""
    assert chat_row["message_text_length"] > 0
    assert note_row["record_type"] == "note_content"
    assert note_row["message_text"] == ""
    assert note_row["message_text_length"] > 0
    assert any("red folder for project notes" in str(document["content"]) for document in documents)
    assert any("red folder in Obsidian" in str(document["content"]) for document in documents)
