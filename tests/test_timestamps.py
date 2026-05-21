from forensic_orchestrator.timestamps import normalize_timestamp


def test_normalize_timestamp_handles_tsk_utc_suffix_and_subsecond_precision():
    assert (
        normalize_timestamp("2008-07-06 07:38:56.122500000 (UTC)")
        == "2008-07-06T07:38:56.122500Z"
    )


def test_normalize_timestamp_preserves_iso_utc():
    assert normalize_timestamp("2026-05-12T13:14:15Z") == "2026-05-12T13:14:15Z"
