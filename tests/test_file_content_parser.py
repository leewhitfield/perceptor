import csv
import zipfile

from forensic_orchestrator.tools.file_content import parse_file_content_to_csv


def test_file_content_parser_extracts_openxml_tmp_files(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    tmp_doc = source / "_WRD0001.tmp"
    with zipfile.ZipFile(tmp_doc, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types />")
        archive.writestr(
            "word/document.xml",
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            "<w:body><w:p><w:r><w:t>Temporary Word content</w:t></w:r></w:p></w:body></w:document>",
        )
    (source / "ordinary.tmp").write_text("not indexed", encoding="utf-8")

    csv_path = parse_file_content_to_csv(source, tmp_path / "out")

    with csv_path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert [row["item_name"] for row in rows] == ["_WRD0001.tmp"]
    assert rows[0]["item_type"] == "tmp"
    assert rows[0]["extraction_status"] == "text_extracted"
    assert "Temporary Word content" in rows[0]["content_text"]
