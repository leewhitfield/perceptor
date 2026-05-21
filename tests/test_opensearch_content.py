from pathlib import Path

import pytest

from forensic_orchestrator.db import Database, utc_now
from forensic_orchestrator.search.opensearch import (
    mailbox_attachment_document,
    mailbox_message_document,
    messaging_message_document,
    messaging_record_document,
)


def test_opensearch_documents_only_index_body_or_content_fields():
    base = {
        "id": "row-1",
        "case_id": "case-1",
        "computer_id": "computer-1",
        "image_id": "image-1",
        "opensearch_document_id": "",
    }

    mail = mailbox_message_document(
        {**base, "subject": "Metadata Subject", "source_format": "eml", "parser_status": "parsed"},
        body_text="Actual email body",
        body_html="",
    )
    attachment = mailbox_attachment_document(
        {**base, "subject": "Metadata Subject", "attachment_name": "notes.txt", "metadata_json": '{"Author": "Jane"}'},
        extracted_text="Actual attachment text",
    )
    record = messaging_record_document(
        {**base, "application": "Slack", "raw_text": "raw parser string"},
        message_text="Actual message fragment",
    )
    message = messaging_message_document(
        {**base, "application": "Slack", "raw_json": '{"text": "raw json blob"}'},
        message_text="Actual chat message",
        message_html="",
    )

    assert mail["content"] == "Actual email body"
    assert attachment["content"] == "Actual attachment text"
    assert record["content"] == "Actual message fragment"
    assert message["content"] == "Actual chat message"
    combined = "\n".join(document["content"] for document in (mail, attachment, record, message))
    assert "Metadata Subject" not in combined
    assert "notes.txt" not in combined
    assert "Author" not in combined
    assert "raw parser string" not in combined
    assert "raw json blob" not in combined


def test_content_heavy_db_inserts_keep_only_metadata_references(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    db.insert_tool_output(
        {
            "id": "output-1",
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": "image-1",
            "job_id": None,
            "tool_name": "MailboxParser",
            "output_type": "csv",
            "path": "/tmp/MailboxMessages.csv",
            "content_sha256": "mail",
            "row_count": 1,
        }
    )
    db.insert_tool_output(
        {
            "id": "output-2",
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": "image-1",
            "job_id": None,
            "tool_name": "SIDR",
            "output_type": "csv",
            "path": "/tmp/Search.csv",
            "content_sha256": "search",
            "row_count": 1,
        }
    )
    now = utc_now()
    db.insert_mailbox_messages(
        [
            {
                "id": "mail-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-1",
                "tool_name": "MailboxParser",
                "source_csv": "/tmp/MailboxMessages.csv",
                "row_number": 1,
                "source_path": "/tmp/1.eml",
                "container_path": "/tmp/mail.ost",
                "message_path": "/tmp/1.eml",
                "source_format": "ost",
                "parser_status": "parsed",
                "parser_error": "",
                "user_profile": "Jane",
                "user_sid": "",
                "message_id": "<1@example.test>",
                "in_reply_to": "",
                "subject": "Project Falcon",
                "sender": "a@example.test",
                "recipients": "b@example.test",
                "cc": "",
                "bcc": "",
                "message_date_utc": "2020-01-01T00:00:00+00:00",
                "body_text": "The launch notes are attached.",
                "body_html": "",
                "attachment_names": "notes.docx",
                "attachment_count": 1,
                "has_attachments": "1",
                "dedupe_key": "dedupe-1",
                "created_at": now,
            },
            {
                "id": "windows-mail-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-1",
                "tool_name": "WindowsMailParser",
                "source_csv": "/tmp/MailboxMessages.csv",
                "row_number": 2,
                "source_path": "/Users/Jane/AppData/Local/Packages/mail/EFMData/1.dat",
                "container_path": "/Users/Jane/AppData/Local/Packages/mail/EFMData/1.dat",
                "message_path": "/Users/Jane/AppData/Local/Packages/mail/EFMData/1.dat",
                "source_format": "windows_mail_efmdata_html",
                "parser_status": "body_file_extracted",
                "parser_error": "Standalone Windows Mail body file.",
                "user_profile": "Jane",
                "user_sid": "",
                "message_id": "",
                "in_reply_to": "",
                "subject": "",
                "sender": "",
                "recipients": "",
                "cc": "",
                "bcc": "",
                "message_date_utc": "2020-01-03T00:00:00+00:00",
                "body_text": "Windows Mail cached body about Project Falcon.",
                "body_html": "",
                "attachment_names": "",
                "attachment_count": 0,
                "has_attachments": "0",
                "dedupe_key": "windows-mail-dedupe-1",
                "created_at": now,
            }
        ]
    )
    db.insert_windows_search_indexed_content(
        [
            {
                "id": "search-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-2",
                "tool_name": "SIDR",
                "source_csv": "/tmp/Search.csv",
                "source_table": "windows_search_files",
                "source_record_id": "file-1",
                "row_number": 2,
                "work_id": "10",
                "gather_time": "2020-01-02T00:00:00+00:00",
                "item_path": "C:/Users/Jane/Documents/report.docx",
                "item_name": "report.docx",
                "item_type": "docx",
                "content_field": "_extra[3]",
                "content_text": "Indexed file content about Project Falcon.",
                "content_length": 42,
                "timestamp": "2020-01-02T00:00:00+00:00",
                "created_at": now,
            }
        ]
    )
    db.insert_mailbox_attachments(
        [
            {
                "id": "attachment-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-1",
                "tool_name": "MailboxParser",
                "source_csv": "/tmp/MailboxAttachments.csv",
                "row_number": 1,
                "source_path": "/tmp/1.eml",
                "container_path": "/tmp/mail.ost",
                "message_path": "/tmp/1.eml",
                "user_profile": "Jane",
                "user_sid": "",
                "message_id": "<1@example.test>",
                "subject": "Project Falcon",
                "sender": "a@example.test",
                "recipients": "b@example.test",
                "message_date_utc": "2020-01-01T00:00:00+00:00",
                "attachment_name": "notes.txt",
                "attachment_path": "/tmp/notes.txt",
                "content_type": "text/plain",
                "size": 12,
                "sha256": "abc",
                "metadata_json": '{"FileType": "TXT", "MIMEType": "text/plain"}',
                "extracted_text": "Attachment text about Falcon.",
                "extraction_status": "text_extracted",
                "parser_error": "",
                "dedupe_key": "dedupe-1",
                "created_at": now,
            }
        ]
    )

    mail = db.conn.execute(
        "SELECT body_text, body_text_sha256, body_text_length, opensearch_document_id "
        "FROM mailbox_messages WHERE id = 'mail-1'"
    ).fetchone()
    windows_search = db.conn.execute(
        "SELECT content_text, content_sha256, content_length, opensearch_document_id "
        "FROM windows_search_indexed_content WHERE id = 'search-1'"
    ).fetchone()
    attachment = db.conn.execute(
        "SELECT metadata_json, extracted_text, metadata_json_sha256, extracted_text_sha256, "
        "metadata_json_length, extracted_text_length, opensearch_document_id "
        "FROM mailbox_attachments WHERE id = 'attachment-1'"
    ).fetchone()

    assert mail["body_text"] == ""
    assert mail["body_text_sha256"]
    assert mail["body_text_length"] == len("The launch notes are attached.")
    assert mail["opensearch_document_id"]
    assert windows_search["content_text"] == ""
    assert windows_search["content_sha256"]
    assert windows_search["content_length"] == len("Indexed file content about Project Falcon.")
    assert windows_search["opensearch_document_id"]
    assert attachment["metadata_json"] == ""
    assert attachment["extracted_text"] == ""
    assert attachment["metadata_json_sha256"]
    assert attachment["extracted_text_sha256"]
    assert attachment["metadata_json_length"] > 0
    assert attachment["extracted_text_length"] == len("Attachment text about Falcon.")
    assert attachment["opensearch_document_id"]


def test_database_insert_failure_is_logged_when_activity_log_is_available(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    db.insert_tool_output(
        {
            "id": "output-1",
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": "image-1",
            "job_id": None,
            "tool_name": "SIDR",
            "output_type": "csv",
            "path": "/tmp/Search.csv",
            "content_sha256": "search",
            "row_count": 1,
        }
    )

    row = {
        "id": "search-1",
        "case_id": case.id,
        "computer_id": "computer-1",
        "image_id": "image-1",
        "tool_output_id": "output-1",
        "tool_name": "SIDR",
        "source_csv": "/tmp/Search.csv",
        "source_table": "windows_search_files",
        "source_record_id": "file-1",
        "row_number": 2,
        "work_id": "10",
        "gather_time": "2020-01-02T00:00:00+00:00",
        "item_path": "C:/Users/Jane/Documents/report.docx",
        "item_name": "report.docx",
        "item_type": "docx",
        "content_field": "_extra[3]",
        "content_text": "Indexed file content about Project Falcon.",
        "timestamp": "2020-01-02T00:00:00+00:00",
    }

    db.insert_windows_search_indexed_content([row])
    with pytest.raises(Exception):
        db.insert_windows_search_indexed_content([row])

    activity = db.conn.execute(
        "SELECT event, level, details_json FROM activity_log WHERE event = 'database.write_failed'"
    ).fetchone()
    assert activity["level"] == "error"
    assert "windows_search_indexed_content" in activity["details_json"]
