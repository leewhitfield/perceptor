from forensic_orchestrator import cli


def test_display_timezone_is_noop_by_default():
    cli._configure_output_timezone(None)
    row = {"timestamp_utc": "2025-11-17T20:51:47Z", "name": "event"}

    assert cli._with_display_timezone(row) == row


def test_display_timezone_adds_local_companion_without_changing_utc():
    cli._configure_output_timezone("America/New_York")
    row = {"timestamp_utc": "2025-11-17T20:51:47Z", "created_at": "2025-11-17T20:51:47Z"}

    enriched = cli._with_display_timezone(row)

    assert enriched["timestamp_utc"] == "2025-11-17T20:51:47Z"
    assert enriched["timestamp_utc_local"] == "2025-11-17T15:51:47-05:00"
    assert enriched["created_at_local"] == "2025-11-17T15:51:47-05:00"
    assert enriched["display_timezone"] == "America/New_York"

    cli._configure_output_timezone(None)


def test_timezone_table_includes_local_companion_for_displayed_columns():
    cli._configure_output_timezone("America/New_York")

    table = cli.generic_table(
        "Timeline",
        [{"timestamp_utc": "2025-11-17T20:51:47Z", "event_type": "browser"}],
        ["timestamp_utc", "event_type"],
    )

    assert "timestamp_utc=2025-11-17T20:51:47Z" in table
    assert "timestamp_utc_local=2025-11-17T15:51:47-05:00" in table

    cli._configure_output_timezone(None)
