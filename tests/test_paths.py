from forensic_orchestrator.paths import WorkspacePaths


def test_workspace_paths_are_under_root(tmp_path):
    paths = WorkspacePaths(tmp_path)
    case_id = "case-1"

    assert paths.case_dir(case_id) == tmp_path / "cases" / case_id
    assert paths.ewf_mount_dir(case_id) == tmp_path / "cases" / case_id / "mounts" / "ewf"
    assert paths.ewf_raw_path(case_id) == paths.ewf_mount_dir(case_id) / "ewf1"
    assert paths.analytics_dir(case_id) == tmp_path / "cases" / case_id / "analytics"
    assert paths.analytics_db_path(case_id) == paths.analytics_dir(case_id) / "events.duckdb"
    assert paths.parquet_dir(case_id) == paths.analytics_dir(case_id) / "parquet"
    assert paths.volume_mount_dir(case_id, "part-001") == (
        tmp_path / "cases" / case_id / "mounts" / "volumes" / "part-001"
    )


def test_ensure_case_tree_creates_expected_dirs(tmp_path):
    paths = WorkspacePaths(tmp_path)
    paths.ensure_case_tree("case-1")

    assert paths.logs_dir("case-1").is_dir()
    assert paths.outputs_dir("case-1").is_dir()
    assert paths.analytics_dir("case-1").is_dir()
    assert paths.parquet_dir("case-1").is_dir()
    assert paths.ewf_mount_dir("case-1").is_dir()
    assert (paths.mounts_dir("case-1") / "volumes").is_dir()
