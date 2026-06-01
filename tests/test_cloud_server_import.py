import zipfile

from forensic_orchestrator.db import Database
from forensic_orchestrator.tools.cloud_server_import import cloud_server_import_diagnostics, import_cloud_server_logs_to_csv
from forensic_orchestrator.tools.google_takeout import google_takeout_diagnostics, import_google_takeout_to_csv
import forensic_orchestrator.tools.ingest as ingest_module
from forensic_orchestrator.tools.ingest import ingest_csv_output


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


def test_cloud_server_log_import_normalizes_csv_to_duckdb(tmp_path):
    source = tmp_path / "ual.csv"
    source.write_text(
        "CreationTime,Workload,Operation,UserId,ClientIP,ObjectId,ResultStatus\n"
        "2020-11-14T01:02:03Z,SharePoint,FileDownloaded,fred@example.com,1.2.3.4,/Shared/report.docx,Succeeded\n",
        encoding="utf-8",
    )
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="cloud-1", case_id=case.id, label="Cloud")
    db.add_image("image-1", case.id, source, computer_id="cloud-1")
    csv_path = import_cloud_server_logs_to_csv(source, tmp_path / "out", provider="Microsoft 365")
    db.insert_tool_output(
        {
            "id": "output-1",
            "case_id": case.id,
            "computer_id": "cloud-1",
            "image_id": "image-1",
            "job_id": None,
            "tool_name": "CloudServerLogImporter",
            "output_type": "csv",
            "path": csv_path,
            "row_count": 1,
        }
    )

    assert ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="cloud-1",
        image_id="image-1",
        tool_output_id="output-1",
        tool_name="CloudServerLogImporter",
        path=csv_path,
    ) == 1

    conn = db.analytics._connect(case.id)
    row = conn.execute("SELECT provider, service, operation, actor, actor_ip, target, result FROM cloud_server_events").fetchone()
    assert tuple(row) == ("Microsoft 365", "SharePoint", "FileDownloaded", "fred@example.com", "1.2.3.4", "/Shared/report.docx", "Succeeded")


def test_google_takeout_zip_without_audit_logs_is_reported_as_unsupported(tmp_path):
    source = tmp_path / "takeout-GMail.zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("Takeout/Mail/All mail Including Spam and Trash.mbox", "From sender@example.com\n\nbody")

    csv_path = import_cloud_server_logs_to_csv(source, tmp_path / "out", provider="Google", service="mail")
    diagnostics = cloud_server_import_diagnostics(source)

    assert csv_path.read_text(encoding="utf-8").count("\n") == 1
    assert diagnostics["status"] == "unsupported_layout"
    assert "Takeout" in diagnostics["reason"]


def test_cloud_log_import_reads_supported_rows_from_zip(tmp_path):
    source = tmp_path / "logs.zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr(
            "audit.csv",
            "CreationTime,Workload,Operation,UserId\n"
            "2020-11-14T01:02:03Z,Drive,FileViewed,fred@example.com\n",
        )

    csv_path = import_cloud_server_logs_to_csv(source, tmp_path / "out", provider="Google")

    text = csv_path.read_text(encoding="utf-8")
    assert "FileViewed" in text


def test_google_takeout_imports_mail_mbox_drive_inventory_and_searchable_drive_content(tmp_path, monkeypatch):
    documents = _capture_content(monkeypatch)
    source = tmp_path / "takeout.zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr(
            "Takeout/Mail/All mail Including Spam and Trash.mbox",
            "From sender@example.test Sat Jan 01 00:00:00 2022\n"
            "From: Sender <sender@example.test>\n"
            "To: Recipient <recipient@example.test>\n"
            "Subject: Takeout Message\n"
            "Date: Sat, 01 Jan 2022 00:00:00 +0000\n"
            "\n"
            "hello from takeout\n",
        )
        archive.writestr(
            "Takeout/Drive/Report.docx",
            _docx_bytes("Searchable Drive Takeout contract language"),
        )
        archive.writestr("Takeout/Drive/Trash/Deleted.pptx", b"deleted")

    diagnostics = google_takeout_diagnostics(source)
    assert diagnostics["services"] == ["mail", "drive"]

    result = import_google_takeout_to_csv(source, tmp_path / "out")
    assert result["mail_message_rows"] == 1
    assert result["drive_rows"] == 2
    assert result["drive_content_rows"] == 2

    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="cloud-1", case_id=case.id, label="Cloud")
    db.add_image("image-1", case.id, source, computer_id="cloud-1")
    db.insert_tool_output(
        {
            "id": "mail-output",
            "case_id": case.id,
            "computer_id": "cloud-1",
            "image_id": "image-1",
            "job_id": None,
            "tool_name": "MailboxParser",
            "output_type": "google_takeout_mail_messages",
            "path": result["mail_messages_csv"],
            "row_count": result["mail_message_rows"],
        }
    )
    ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="cloud-1",
        image_id="image-1",
        tool_output_id="mail-output",
        tool_name="MailboxParser",
        path=result["mail_messages_csv"],
    )
    db.insert_tool_output(
        {
            "id": "drive-output",
            "case_id": case.id,
            "computer_id": "cloud-1",
            "image_id": "image-1",
            "job_id": None,
            "tool_name": "CloudSyncParser",
            "output_type": "google_takeout_drive_inventory",
            "path": result["drive_csv"],
            "row_count": result["drive_rows"],
        }
    )
    ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="cloud-1",
        image_id="image-1",
        tool_output_id="drive-output",
        tool_name="CloudSyncParser",
        path=result["drive_csv"],
    )
    db.insert_tool_output(
        {
            "id": "content-output",
            "case_id": case.id,
            "computer_id": "cloud-1",
            "image_id": "image-1",
            "job_id": None,
            "tool_name": "UserFileContentParser",
            "output_type": "google_takeout_drive_content",
            "path": result["drive_content_csv"],
            "row_count": result["drive_content_rows"],
        }
    )
    ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="cloud-1",
        image_id="image-1",
        tool_output_id="content-output",
        tool_name="UserFileContentParser",
        path=result["drive_content_csv"],
    )

    conn = db.analytics._connect(case.id)
    subject = conn.execute("SELECT subject FROM mailbox_messages").fetchone()[0]
    drive_rows = conn.execute(
        "SELECT cloud_path, is_deleted FROM cloud_sync_artifacts ORDER BY cloud_path"
    ).fetchall()
    content_row = conn.execute(
        "SELECT item_path, item_name, content_length FROM windows_search_indexed_content WHERE item_name = 'Report.docx'"
    ).fetchone()
    assert subject == "Takeout Message"
    assert [tuple(row) for row in drive_rows] == [("/Report.docx", "false"), ("/Trash/Deleted.pptx", "true")]
    assert content_row[0] == "/Report.docx"
    assert content_row[1] == "Report.docx"
    assert int(content_row[2]) == len("Searchable Drive Takeout contract language")
    assert any(document["source_type"] == "indexed_file_content" and "contract language" in document["content"] for document in documents)


def _docx_bytes(text: str) -> bytes:
    from io import BytesIO

    payload = BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"/>")
        archive.writestr("word/document.xml", f"<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body></w:document>")
    return payload.getvalue()
