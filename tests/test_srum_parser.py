import csv

from forensic_orchestrator.tools.srum import parse_srum_artifacts_to_csv


def test_internal_srum_parser_exports_all_provider_rows(monkeypatch, tmp_path):
    sru_dir = tmp_path / "Windows" / "System32" / "sru"
    sru_dir.mkdir(parents=True)
    (sru_dir / "SRUDB.dat").write_bytes(b"dummy")
    pbk_dir = tmp_path / "Users" / "fredr" / "AppData" / "Roaming" / "Microsoft" / "Network" / "Connections" / "Pbk"
    pbk_dir.mkdir(parents=True)
    (pbk_dir / "rasphone.pbk").write_text(
        "[Stark Research Labs]\n"
        "Type=2\n"
        "Guid=32B9686B6A982F429F8CEDCD256691F4\n"
        "VpnStrategy=6\n"
        "Device=WAN Miniport (SSTP)\n"
        "PhoneNumber=vpn.stark-research-labs.com:8443\n",
        encoding="utf-8",
    )
    stale_export = tmp_path / "out" / "_esedbexport.export"
    stale_export.mkdir(parents=True)
    (stale_export / "old").write_text("stale", encoding="utf-8")

    def fake_run(command, stdout, stderr, text, check):
        assert not stale_export.exists()
        export_dir = tmp_path / "out" / "_esedbexport.export"
        export_dir.mkdir(parents=True)
        (export_dir / "SruDbIdMapTable.4").write_text(
            "IdType\tIdIndex\tIdBlob\n"
            "0\t718\t21005400650061006d0073002e00650078006500210032003000320030002f00310030002f00320030003a00310036003a00300030003a0030003000210061006200630021005400650061006d00730021000000\n"
            "3\t576\t010500000000000515000000010000000200000003000000\n",
            encoding="utf-8",
        )
        (export_dir / "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}.15").write_text(
            "AutoIncId\tTimeStamp\tAppId\tUserId\tNotificationType\tPayloadSize\tNetworkType\n"
            "1\tOct 20, 2020 17:06:59.231231180\t718\t576\t1\t1116\t0\n",
            encoding="utf-8",
        )
        (export_dir / "{DD6636C4-8929-4683-974E-22C046A43763}.14").write_text(
            "AutoIncId\tTimeStamp\tUserId\tInterfaceLuid\tConnectedTime\n"
            "2\tOct 20, 2020 18:00:00.000000000\t576\t6473924464345088\t600\n",
            encoding="utf-8",
        )
        return type("Result", (), {"returncode": 0, "stderr": ""})()

    monkeypatch.setattr("forensic_orchestrator.tools.srum.subprocess.run", fake_run)

    csv_path = parse_srum_artifacts_to_csv(sru_dir, tmp_path / "out", phonebooks=tmp_path / "Users")

    with csv_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["provider_guid"] == "d10ca2fe-6fcf-4f6d-848e-b2e99266fa86"
    assert rows[0]["record_type"] == "push_notifications"
    assert rows[0]["app_name"] == "Teams.exe"
    assert rows[0]["app_description"] == "Teams"
    assert rows[0]["user_sid"] == "S-1-5-21-1-2-3"
    assert rows[0]["payload_size"] == "1116"
    vpn_row = next(row for row in rows if row["record_type"] == "network_connectivity")
    assert vpn_row["interface_type"] == "23"
    assert vpn_row["vpn_profile_name"] == "Stark Research Labs"
    assert vpn_row["vpn_server"] == "vpn.stark-research-labs.com:8443"
    assert vpn_row["vpn_protocol"] == "SSTP"
