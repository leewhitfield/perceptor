from forensic_orchestrator.tools.office_backstage import parse_office_backstage_artifacts_to_csv


def test_office_backstage_parser_extracts_paths_and_urls(tmp_path):
    office = tmp_path / "Users" / "Devon" / "AppData" / "Local" / "Microsoft" / "Office" / "16.0"
    office.mkdir(parents=True)
    cache = office / "BackstageCache.dat"
    cache.write_text(
        "C:\\Users\\Devon\\Documents\\budget.xlsx\nhttps://sharepoint.example/sites/case/budget.xlsx",
        encoding="utf-8",
    )

    csv_path = parse_office_backstage_artifacts_to_csv(tmp_path / "Users", tmp_path / "out")
    text = csv_path.read_text(encoding="utf-8")

    assert "office_backstage_path" in text
    assert "office_backstage_url" in text
    assert "budget.xlsx" in text
    assert "sharepoint.example" in text


def test_office_backstage_parser_skips_walk_errors(monkeypatch, tmp_path):
    source = tmp_path / "Users"
    office = source / "Devon" / "AppData" / "Local" / "Microsoft" / "Office"
    office.mkdir(parents=True)
    (office / "BackstageCache.dat").write_text("C:\\Users\\Devon\\Documents\\budget.xlsx", encoding="utf-8")

    def fake_walk(root, onerror=None):
        if onerror is not None:
            onerror(OSError("input/output error"))
        yield str(office), [], ["BackstageCache.dat"]

    monkeypatch.setattr("forensic_orchestrator.tools.office_backstage.os.walk", fake_walk)

    csv_path = parse_office_backstage_artifacts_to_csv(source, tmp_path / "out")
    text = csv_path.read_text(encoding="utf-8")

    assert "office_backstage_path" in text
    assert "budget.xlsx" in text


def test_office_backstage_parser_keeps_malformed_url_text_without_failing(tmp_path):
    office = tmp_path / "Users" / "Devon" / "AppData" / "Local" / "Microsoft" / "Office"
    office.mkdir(parents=True)
    (office / "BackstageCache.dat").write_text("https://[bad-ipv6-url", encoding="utf-8")

    csv_path = parse_office_backstage_artifacts_to_csv(tmp_path / "Users", tmp_path / "out")
    text = csv_path.read_text(encoding="utf-8")

    assert "office_backstage_url" in text
    assert "https://[bad-ipv6-url" in text
