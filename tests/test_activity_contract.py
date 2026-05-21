import pytest

from forensic_orchestrator.activity_contract import activity_contract_row, validate_activity_contract


def test_activity_contract_derives_file_name_and_user_from_path():
    row = activity_contract_row(
        source_table="windows_defender_events",
        source_row_id="row-1",
        source_tool="WindowsDefenderParser",
        event_time_utc="2020-11-01T20:10:49+00:00",
        timestamp_meaning="defender_event_time",
        path=r"HarddiskVolume3:\Users\fredr\Documents\report.docx",
        artifact_category="file_reference",
        interpretation_note="Defender observed this path during scanning",
    )

    validate_activity_contract(row)
    assert row["file_name"] == "report.docx"
    assert row["user_profile"] == "fredr"


def test_activity_contract_requires_provenance_and_timestamp_meaning():
    with pytest.raises(ValueError, match="timestamp_meaning"):
        activity_contract_row(
            source_table="windows_defender_events",
            source_row_id="row-1",
            source_tool="WindowsDefenderParser",
            event_time_utc=None,
            timestamp_meaning="",
            path=None,
            artifact_category="file_reference",
            interpretation_note="Observed path",
        )


def test_validate_activity_contract_rejects_missing_fields():
    with pytest.raises(ValueError, match="missing required fields"):
        validate_activity_contract({"source_table": "mft_entries"})
