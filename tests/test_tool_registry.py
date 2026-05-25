import inspect
from pathlib import Path

from forensic_orchestrator.tools import profiles
from forensic_orchestrator.config import default_plugin_path
from forensic_orchestrator.tools.registry import (
    ToolRegistry,
    build_tool_command,
    required_paths,
    resolve_dotnet_runtime,
)


def test_registry_loads_eztools_profile():
    registry = ToolRegistry.from_files([default_plugin_path()])

    assert "MFTECmd" in registry.tools
    assert "MFTECmdUSN" in registry.tools
    assert "MFTECmdLogFile" in registry.tools
    assert "NTFSParseLogFile" in registry.tools
    assert "EvtxECmd" in registry.tools
    assert "EvtxECmdTriage" in registry.tools
    assert [tool.name for tool in registry.profile_tools("windows-basic")] == [
        "MFTECmd",
        "MFTECmdUSN",
        "NTFSParseLogFile",
        "MFTECmdI30",
        "SAMParser",
        "RegistryParser",
        "RECmd",
        "RegistryArtifactParser",
        "SrumParser",
        "UalParser",
        "AmcacheParser",
        "AppCompatCacheParser",
        "SBECmd",
        "EvtxECmdTriage",
        "PrefetchParser",
        "RecycleParser",
        "FirefoxParser",
        "ChromiumParser",
        "OfficeBackstageParser",
        "UserDictionaryParser",
        "ZoneIdentifierParser",
        "ThumbcacheParser",
        "WebCacheParser",
        "PackageCacheParser",
        "PackageArtifactsParser",
        "TelemetryParser",
        "MailboxParser",
        "WindowsMailParser",
        "MessagingParser",
        "EtlParser",
        "JLECmd",
        "LECmd",
    ]
    assert [tool.name for tool in registry.profile_tools("windows-no-evtx")] == [
        "MFTECmd",
        "MFTECmdUSN",
        "NTFSParseLogFile",
        "MFTECmdI30",
        "SAMParser",
        "RegistryParser",
        "RECmd",
        "RegistryArtifactParser",
        "SetupApiParser",
        "SrumParser",
        "UalParser",
        "AmcacheParser",
        "AppCompatCacheParser",
        "SBECmd",
        "PrefetchParser",
        "RecycleParser",
        "FirefoxParser",
        "ChromiumParser",
        "OfficeBackstageParser",
        "UserDictionaryParser",
        "ZoneIdentifierParser",
        "ThumbcacheParser",
        "WebCacheParser",
        "PackageCacheParser",
        "PackageArtifactsParser",
        "TelemetryParser",
        "MailboxParser",
        "WindowsMailParser",
        "MessagingParser",
        "EtlParser",
        "JLECmd",
        "LECmd",
    ]
    assert [tool.name for tool in registry.profile_tools("windows-full-evtx")] == [
        "MFTECmd",
        "MFTECmdUSN",
        "NTFSParseLogFile",
        "MFTECmdI30",
        "SAMParser",
        "RegistryParser",
        "RECmd",
        "RegistryArtifactParser",
        "SetupApiParser",
        "SrumParser",
        "UalParser",
        "AmcacheParser",
        "AppCompatCacheParser",
        "SBECmd",
        "EvtxECmd",
        "PrefetchParser",
        "RecycleParser",
        "FirefoxParser",
        "ChromiumParser",
        "OfficeBackstageParser",
        "UserDictionaryParser",
        "ZoneIdentifierParser",
        "ThumbcacheParser",
        "WebCacheParser",
        "PackageCacheParser",
        "PackageArtifactsParser",
        "TelemetryParser",
        "MailboxParser",
        "WindowsMailParser",
        "MessagingParser",
        "EtlParser",
        "JLECmd",
        "LECmd",
    ]
    assert registry.get_tool("RECmd").enabled is True
    assert registry.get_tool("LECmd").enabled is True
    assert registry.get_tool("JLECmd").enabled is True
    assert registry.get_tool("PECmd").enabled is True
    assert registry.get_tool("PrefetchParser").enabled is True
    assert registry.get_tool("SAMParser").enabled is True
    assert registry.get_tool("RegistryParser").enabled is True
    assert registry.get_tool("RegistryArtifactParser").enabled is True
    assert registry.get_tool("UserDictionaryParser").enabled is True
    assert registry.get_tool("ZoneIdentifierParser").enabled is True
    assert registry.get_tool("ZoneIdentifierParser").artifacts[0].use_tsk is False
    assert registry.get_tool("ThumbcacheParser").enabled is True
    assert registry.get_tool("RdpCacheParser").enabled is True
    assert registry.get_tool("RdpVisionReview").enabled is True
    assert [tool.name for tool in registry.profile_tools("windows-rdp-cache")] == ["RdpCacheParser", "RdpVisionReview"]
    assert registry.get_tool("SrumECmd").enabled is True
    assert registry.get_tool("SrumParser").enabled is True
    assert registry.get_tool("UalParser").enabled is True
    assert registry.get_tool("SIDR").enabled is True
    assert registry.get_tool("WindowsSearchESEParser").enabled is True
    assert registry.get_tool("AmcacheParser").enabled is True
    assert registry.get_tool("AppCompatCacheParser").enabled is True
    assert registry.get_tool("SBECmd").enabled is True
    assert registry.get_tool("RecycleParser").enabled is True
    assert registry.get_tool("FirefoxParser").enabled is True
    assert registry.get_tool("ChromiumParser").enabled is True
    assert registry.get_tool("WebCacheParser").enabled is True
    assert registry.get_tool("PackageCacheParser").enabled is True
    assert registry.get_tool("PackageArtifactsParser").enabled is True
    assert registry.get_tool("SpotifyParser").enabled is True
    assert registry.get_tool("TelemetryParser").enabled is True
    assert registry.get_tool("EtlParser").enabled is True
    assert registry.get_tool("WindowsSearchGatherParser").enabled is True
    assert registry.get_tool("WindowsErrorReportingParser").enabled is True
    assert registry.get_tool("WindowsDefenderParser").enabled is True


def test_srum_parser_collects_direct_and_nested_ras_phonebooks():
    registry = ToolRegistry.from_files([default_plugin_path()])
    tool = registry.get_tool("SrumParser")
    artifact = {artifact.name: artifact for artifact in tool.artifacts}["ras_phonebooks"]

    assert artifact.source == "Users"
    assert artifact.destination == "vpn_phonebooks"
    assert artifact.recursive is True
    assert artifact.include_path_patterns == (
        "*/AppData/Roaming/Microsoft/Network/Connections/Pbk*/rasphone.pbk",
        "*/AppData/Roaming/Microsoft/Network/Connections/Pbk*/**/rasphone.pbk",
    )


def test_browser_cache_parser_collects_only_browser_cache_paths():
    registry = ToolRegistry.from_files([default_plugin_path()])
    tool = registry.get_tool("BrowserCacheParser")
    artifact = {artifact.name: artifact for artifact in tool.artifacts}["browser_cache_profiles"]

    assert artifact.source == "Users"
    assert artifact.destination == "browser/Cache"
    assert artifact.recursive is True
    assert artifact.include_path_patterns
    assert all("cache" in pattern.lower() for pattern in artifact.include_path_patterns)


def test_package_cache_parser_collects_only_package_cache_storage_paths():
    registry = ToolRegistry.from_files([default_plugin_path()])
    tool = registry.get_tool("PackageCacheParser")
    artifact = {artifact.name: artifact for artifact in tool.artifacts}["package_cache_profiles"]

    assert artifact.source == "Users"
    assert artifact.destination == "packages/CacheStorage"
    assert artifact.recursive is True
    assert artifact.include_path_patterns
    assert all("/packages/" in pattern.lower() and "cachestorage" in pattern.lower() for pattern in artifact.include_path_patterns)


def test_package_artifacts_parser_is_limited_to_high_value_paths_and_files():
    registry = ToolRegistry.from_files([default_plugin_path()])
    tool = registry.get_tool("PackageArtifactsParser")
    artifact = {artifact.name: artifact for artifact in tool.artifacts}["package_artifact_profiles"]

    assert artifact.source == ""
    assert artifact.recursive is True
    assert artifact.patterns
    assert artifact.include_path_patterns
    include_patterns = " ".join(artifact.include_path_patterns).lower()
    assert "/packages/" in include_patterns
    assert "content.outlook" in include_patterns
    assert "appcompat/programs" in include_patterns


def test_windows_full_includes_complete_current_artifact_set():
    registry = ToolRegistry.from_files([default_plugin_path()])
    assert registry.profiles["windows-full"].get("include_windows_old") is True
    profile_tools = registry.profile_tools("windows-full")
    tools = {tool.name for tool in profile_tools}
    tool_order = [tool.name for tool in profile_tools]

    expected = {
        "MFTECmd",
        "USNRewind",
        "MFTECmdLogFile",
        "NTFSParseLogFile",
        "MFTECmdI30",
        "SrumParser",
        "UalParser",
        "SIDR",
        "WindowsSearchESEParser",
        "WindowsSearchGatherParser",
        "WindowsErrorReportingParser",
        "WindowsDefenderParser",
        "EvtxECmd",
        "SAMParser",
        "RegistryParser",
        "RECmd",
        "RegistryArtifactParser",
        "SetupApiParser",
        "AmcacheParser",
        "AppCompatCacheParser",
        "PECmd",
        "PrefetchParser",
        "RecycleParser",
        "FirefoxParser",
        "ChromiumParser",
        "OfficeBackstageParser",
        "UserDictionaryParser",
        "ZoneIdentifierParser",
        "ThumbcacheParser",
        "RdpCacheParser",
        "RdpVisionReview",
        "WebCacheParser",
        "BrowserCacheParser",
        "PackageCacheParser",
        "PackageArtifactsParser",
        "SpotifyParser",
        "TelemetryParser",
        "SQLECmd",
        "CloudSyncParser",
        "OneDriveExplorer",
        "OneDriveOdlParser",
        "WindowsActivitiesParser",
        "EtlParser",
        "MailboxParser",
        "WindowsMailParser",
        "MessagingParser",
        "JLECmd",
        "LECmd",
        "SBECmd",
    }

    assert expected <= tools

    coverage_categories = registry.profiles["windows-full"].get("coverage_categories")
    assert {
        "application_execution",
        "file_folder_opening",
        "deleted_items_file_existence",
        "browser_activity",
        "cloud_storage",
        "account_usage",
        "network_activity_location",
        "system_information",
        "communications_user_content",
    } <= set(coverage_categories)
    for category_tools in coverage_categories.values():
        assert set(category_tools) <= tools
    assert "FileMetadataExtractor" not in tools
    assert tool_order.index("MFTECmd") < tool_order.index("MailboxParser")
    assert tool_order.index("MFTECmd") < tool_order.index("MFTECmdI30")
    assert tool_order.index("MFTECmd") < tool_order.index("ZoneIdentifierParser")


def test_mft_selected_artifacts_are_extracted_lazily_during_profile_run():
    source = inspect.getsource(profiles._run_profile_impl)

    assert "mft_selected_artifacts" in source
    assert "if artifact.name in mft_selected_artifacts:" in source
    assert "extract_artifact_from_mft" in source
    assert source.index("if artifact.name in mft_selected_artifacts:") < source.index(
        "if artifact.name in mft_selected_artifacts and artifact.name not in artifact_paths:"
    )
    assert source.index("if artifact.name in mft_selected_artifacts and artifact.name not in artifact_paths:") > source.index("for tool in tools:")


def test_dotnet_runtime_can_be_configured(monkeypatch):
    monkeypatch.setenv("FORENSIC_ORCHESTRATOR_DOTNET", "/custom/dotnet")

    assert resolve_dotnet_runtime() == "/custom/dotnet"


def test_tool_command_templates_are_rendered():
    registry = ToolRegistry.from_files([default_plugin_path()])
    tool = registry.get_tool("MFTECmd")

    command = build_tool_command(
        tool,
        mount=Path("/mnt/windows"),
        output=Path("/cases/1/outputs/MFTECmd"),
        artifacts={"MFT": Path("/cases/1/artifacts/$MFT")},
    )

    assert command == [
        resolve_dotnet_runtime(),
        tool.executable,
        "-f",
        "/cases/1/artifacts/$MFT",
        "--csv",
        "/cases/1/outputs/MFTECmd",
    ]
    assert required_paths(
        tool,
        mount=Path("/mnt/windows"),
        output=Path("/out"),
        artifacts={"MFT": Path("/cases/1/artifacts/$MFT")},
    ) == [
        Path("/cases/1/artifacts/$MFT")
    ]
    assert tool.artifacts[0].name == "MFT"
    assert tool.artifacts[0].inode == "0"


def test_recmd_uses_batch_file_and_registry_sidecars():
    registry = ToolRegistry.from_files([default_plugin_path()])
    tool = registry.get_tool("RECmd")
    artifacts = {artifact.name: artifact for artifact in tool.artifacts}
    plugin_dir = Path(__file__).resolve().parents[1] / "forensic_orchestrator" / "plugins"

    assert artifacts["registry_ntuser"].patterns == ("NTUSER.DAT", "UsrClass.dat")
    assert artifacts["registry_user_logs"].patterns == (
        "NTUSER.DAT.LOG1",
        "NTUSER.DAT.LOG2",
        "ntuser.dat.LOG1",
        "ntuser.dat.LOG2",
        "UsrClass.dat.LOG1",
        "UsrClass.dat.LOG2",
        "usrclass.dat.LOG1",
        "usrclass.dat.LOG2",
    )
    assert artifacts["registry_system_log1"].optional is True
    assert build_tool_command(
        tool,
        mount=Path("/unused"),
        output=Path("/cases/1/outputs/RECmd"),
        artifacts={
            "registry_system": Path("/cases/1/artifacts/registry/SYSTEM"),
            "registry_ntuser": Path("/cases/1/artifacts/registry/users"),
        },
    ) == [
        resolve_dotnet_runtime(),
        tool.executable,
        "-d",
        "/cases/1/artifacts/registry",
        "--bn",
        str(plugin_dir / "recmd_windows_activity.reb"),
        "--csv",
        "/cases/1/outputs/RECmd",
        "--csvf",
        "RECmd_WindowsActivity.csv",
    ]
    assert required_paths(
        tool,
        mount=Path("/unused"),
        output=Path("/cases/1/outputs/RECmd"),
        artifacts={
            "registry_system": Path("/cases/1/artifacts/registry/SYSTEM"),
            "registry_ntuser": Path("/cases/1/artifacts/registry/users"),
        },
    ) == [
        Path("/cases/1/artifacts/registry"),
        plugin_dir / "recmd_windows_activity.reb",
    ]


def test_lecmd_extracts_lnk_files_from_partition_root():
    registry = ToolRegistry.from_files([default_plugin_path()])
    tool = registry.get_tool("LECmd")

    assert tool.artifacts[0].name == "lnk_files"
    assert tool.artifacts[0].source == "Users"
    assert tool.artifacts[0].recursive is True
    assert tool.artifacts[0].pattern == "*.lnk"
    assert tool.artifacts[0].exclude_patterns == ("*/Start Menu/*",)
    assert build_tool_command(
        tool,
        mount=Path("/unused"),
        output=Path("/cases/1/outputs/LECmd"),
        artifacts={"lnk_files": Path("/cases/1/artifacts/lnk_files")},
    ) == [
        resolve_dotnet_runtime(),
        tool.executable,
        "-d",
        "/cases/1/artifacts/lnk_files",
        "--csv",
        "/cases/1/outputs/LECmd",
    ]


def test_jlecmd_extracts_jump_lists_from_partition_root():
    registry = ToolRegistry.from_files([default_plugin_path()])
    tool = registry.get_tool("JLECmd")

    assert tool.artifacts[0].name == "jumplists"
    assert tool.artifacts[0].source == "Users"
    assert tool.artifacts[0].recursive is True
    assert tool.artifacts[0].patterns == ("*.automaticDestinations-ms", "*.customDestinations-ms")
    assert build_tool_command(
        tool,
        mount=Path("/unused"),
        output=Path("/cases/1/outputs/JLECmd"),
        artifacts={"jumplists": Path("/cases/1/artifacts/jumplists")},
    ) == [
        resolve_dotnet_runtime(),
        tool.executable,
        "-d",
        "/cases/1/artifacts/jumplists",
        "--csv",
        "/cases/1/outputs/JLECmd",
    ]


def test_pecmd_extracts_prefetch_files():
    registry = ToolRegistry.from_files([default_plugin_path()])
    tool = registry.get_tool("PECmd")

    assert tool.artifacts[0].name == "prefetch_files"
    assert tool.artifacts[0].source == "Windows/Prefetch"
    assert tool.artifacts[0].recursive is True
    assert tool.artifacts[0].pattern == "*.pf"
    assert build_tool_command(
        tool,
        mount=Path("/unused"),
        output=Path("/cases/1/outputs/PECmd"),
        artifacts={"prefetch_files": Path("/cases/1/artifacts/Windows/Prefetch")},
    ) == [
        resolve_dotnet_runtime(),
        tool.executable,
        "-d",
        "/cases/1/artifacts/Windows/Prefetch",
        "--csv",
        "/cases/1/outputs/PECmd",
    ]


def test_internal_prefetch_parser_extracts_prefetch_files():
    registry = ToolRegistry.from_files([default_plugin_path()])
    tool = registry.get_tool("PrefetchParser")

    assert tool.type == "internal_prefetch"
    assert tool.artifacts[0].name == "prefetch_files"
    assert tool.artifacts[0].source == "Windows/Prefetch"
    assert tool.artifacts[0].recursive is True
    assert tool.artifacts[0].pattern == "*.pf"
    assert build_tool_command(
        tool,
        mount=Path("/unused"),
        output=Path("/cases/1/outputs/PrefetchParser"),
        artifacts={"prefetch_files": Path("/cases/1/artifacts/Windows/Prefetch")},
    ) == [
        "internal-prefetch-parser",
        "/cases/1/artifacts/Windows/Prefetch",
        "--csv",
        "/cases/1/outputs/PrefetchParser",
    ]


def test_internal_sam_parser_extracts_sam_hive():
    registry = ToolRegistry.from_files([default_plugin_path()])
    tool = registry.get_tool("SAMParser")

    assert tool.type == "internal_sam"
    assert tool.artifacts[0].name == "sam_hive"
    assert tool.artifacts[0].source == "WINDOWS/system32/config/SAM"
    assert tool.artifacts[0].destination == "registry/SAM"
    assert build_tool_command(
        tool,
        mount=Path("/unused"),
        output=Path("/cases/1/outputs/SAMParser"),
        artifacts={"sam_hive": Path("/cases/1/artifacts/registry/SAM")},
    ) == [
        "internal-sam-parser",
        "/cases/1/artifacts/registry/SAM",
        "--csv",
        "/cases/1/outputs/SAMParser",
    ]


def test_internal_registry_parser_extracts_core_hives():
    registry = ToolRegistry.from_files([default_plugin_path()])
    tool = registry.get_tool("RegistryParser")

    assert tool.type == "internal_registry"
    assert [artifact.name for artifact in tool.artifacts] == [
        "registry_system",
        "registry_software",
        "registry_security",
        "registry_sam",
        "registry_amcache",
        "registry_ntuser",
    ]
    assert tool.artifacts[-1].recursive is True
    assert tool.artifacts[-1].patterns == ("NTUSER.DAT", "UsrClass.dat")
    assert tool.artifacts[4].optional is True


def test_internal_registry_artifact_parser_extracts_hives():
    registry = ToolRegistry.from_files([default_plugin_path()])
    tool = registry.get_tool("RegistryArtifactParser")

    assert tool.type == "internal_registry_artifacts"
    artifacts = {artifact.name: artifact for artifact in tool.artifacts}
    assert {
        "registry_system",
        "registry_system_log1",
        "registry_system_log2",
        "registry_software",
        "registry_software_log1",
        "registry_software_log2",
        "registry_sam",
        "registry_sam_log1",
        "registry_sam_log2",
        "registry_amcache",
        "registry_amcache_log1",
        "registry_amcache_log2",
        "registry_ntuser",
        "registry_ntuser_logs",
        "registry_usrclass",
        "registry_usrclass_logs",
    }.issubset(artifacts)
    assert artifacts["registry_amcache"].optional is True
    assert artifacts["registry_ntuser"].pattern == "NTUSER.DAT"
    assert artifacts["registry_ntuser_logs"].patterns == (
        "NTUSER.DAT.LOG1",
        "NTUSER.DAT.LOG2",
        "ntuser.dat.LOG1",
        "ntuser.dat.LOG2",
    )
    assert artifacts["registry_usrclass"].pattern == "UsrClass.dat"
    assert build_tool_command(
        tool,
        mount=Path("/unused"),
        output=Path("/cases/1/outputs/RegistryArtifactParser"),
        artifacts={
            "registry_system": Path("/cases/1/artifacts/registry/SYSTEM"),
            "registry_software": Path("/cases/1/artifacts/registry/SOFTWARE"),
            "registry_sam": Path("/cases/1/artifacts/registry/SAM"),
            "registry_amcache": Path("/cases/1/artifacts/registry/Amcache.hve"),
            "registry_ntuser": Path("/cases/1/artifacts/registry/users/ntuser"),
            "registry_usrclass": Path("/cases/1/artifacts/registry/users/usrclass"),
        },
    ) == [
        "internal-registry-artifact-parser",
        "/cases/1/artifacts/registry/SYSTEM",
        "/cases/1/artifacts/registry/SOFTWARE",
        "/cases/1/artifacts/registry/SAM",
        "/cases/1/artifacts/registry/Amcache.hve",
        "/cases/1/artifacts/registry/users/ntuser",
        "/cases/1/artifacts/registry/users/usrclass",
        "--csv",
        "/cases/1/outputs/RegistryArtifactParser",
    ]


def test_internal_recycle_parser_extracts_recycle_roots():
    registry = ToolRegistry.from_files([default_plugin_path()])
    tool = registry.get_tool("RecycleParser")

    assert tool.type == "internal_recycle"
    assert [artifact.name for artifact in tool.artifacts] == [
        "recycle_modern",
        "recycle_xp",
        "recycled_xp",
    ]
    assert tool.artifacts[0].source == "$Recycle.Bin"
    assert tool.artifacts[1].source == "RECYCLER"
    assert tool.artifacts[0].recursive is True


def test_internal_firefox_parser_extracts_profile_sqlite_files():
    registry = ToolRegistry.from_files([default_plugin_path()])
    tool = registry.get_tool("FirefoxParser")

    assert tool.type == "internal_firefox"
    assert tool.artifacts[0].name == "firefox_profiles"
    assert tool.artifacts[0].source == "Users"
    assert tool.artifacts[0].use_tsk is False
    assert "places.sqlite" in tool.artifacts[0].patterns
    assert "cookies.sqlite" in tool.artifacts[0].patterns
    assert "formhistory.sqlite" in tool.artifacts[0].patterns
    assert "*.jsonlz4" in tool.artifacts[0].patterns


def test_firefox_deep_recovery_profile_forces_tsk_extraction():
    registry = ToolRegistry.from_files([default_plugin_path()])
    profile_config = registry.profiles["windows-firefox-deep-recovery"]
    tools = profiles._apply_profile_artifact_overrides(registry.profile_tools("windows-firefox-deep-recovery"), profile_config)

    assert [tool.name for tool in tools] == ["FirefoxParser"]
    assert tools[0].artifacts[0].name == "firefox_profiles"
    assert tools[0].artifacts[0].use_tsk is True
    assert tools[0].artifacts[0].recovery["deleted_files"] is True
    assert registry.get_tool("FirefoxParser").artifacts[0].use_tsk is False


def test_deep_recovery_policy_applies_to_recoverable_artifacts_only():
    registry = ToolRegistry.from_files([default_plugin_path()])
    profile_config = registry.profiles["windows-browser-deep-recovery"]
    tools = profiles._apply_profile_artifact_overrides(registry.profile_tools("windows-browser-deep-recovery"), profile_config)
    artifacts = {
        f"{tool.name}:{artifact.name}": artifact
        for tool in tools
        for artifact in tool.artifacts
    }

    assert artifacts["ChromiumParser:chromium_profiles"].use_tsk is True
    assert artifacts["WebCacheParser:webcache"].use_tsk is True
    assert artifacts["LECmd:lnk_files"].use_tsk is True
    assert artifacts["ChromiumParser:chromium_profiles"].recovery["max_files"] == 5000
    assert artifacts["ChromiumParser:chromium_profiles"].recovery["max_seconds"] == 1800
    assert registry.get_tool("ChromiumParser").artifacts[0].use_tsk is False


def test_balanced_recovery_policy_skips_high_cost_artifacts():
    registry = ToolRegistry.from_files([default_plugin_path()])
    preview = profiles.profile_extraction_preview(registry, "windows-browser-balanced-recovery")
    artifacts = {f"{item['tool_name']}:{item['artifact_name']}": item for item in preview["artifacts"]}

    assert preview["extraction_policy"] == "balanced"
    assert preview["recovery_tier"] == "practical_default"
    assert artifacts["LECmd:lnk_files"]["effective_method"] == "tsk"
    assert artifacts["JLECmd:jumplists"]["effective_method"] == "tsk"
    assert artifacts["WebCacheParser:webcache"]["effective_method"] == "tsk"
    assert artifacts["FirefoxParser:firefox_profiles"]["effective_method"] == "mount"
    assert artifacts["BrowserCacheParser:browser_cache_profiles"]["effective_method"] == "mount"


def test_deep_recovery_preview_includes_guardrail_metadata():
    registry = ToolRegistry.from_files([default_plugin_path()])
    preview = profiles.profile_extraction_preview(registry, "windows-basic-evtx-deep-recovery")

    assert preview["recovery_tier"] == "analyst_selected"
    assert preview["recovery_limits"]["max_files_per_artifact"] == 5000
    assert preview["recovery_limits"]["max_seconds_per_artifact"] == 1800


def test_full_deep_recovery_is_separate_from_windows_full():
    registry = ToolRegistry.from_files([default_plugin_path()])

    assert registry.profiles["windows-full"].get("extraction_policy") is None
    deep = registry.profiles["windows-full-deep-recovery"]
    assert deep["extraction_policy"] == "deep"
    assert deep["recovery_tier"] == "analyst_selected"
    assert deep["include_windows_old"] is True
    assert [tool.name for tool in registry.profile_tools("windows-full-deep-recovery")] == [
        tool.name for tool in registry.profile_tools("windows-full")
    ]


def test_internal_chromium_parser_extracts_profile_sqlite_files():
    registry = ToolRegistry.from_files([default_plugin_path()])
    tool = registry.get_tool("ChromiumParser")

    assert tool.type == "internal_chromium"
    assert tool.artifacts[0].name == "chromium_profiles"
    assert tool.artifacts[0].source == "Users"
    assert "History" in tool.artifacts[0].patterns
    assert "Cookies" in tool.artifacts[0].patterns
    assert "Bookmarks" in tool.artifacts[0].patterns
    assert "Web Data" in tool.artifacts[0].patterns
    assert "Shortcuts" in tool.artifacts[0].patterns
    assert "Network Action Predictor" in tool.artifacts[0].patterns
    assert "Top Sites" in tool.artifacts[0].patterns
    assert "Login Data" in tool.artifacts[0].patterns
    assert "Preferences" in tool.artifacts[0].patterns
    assert "SyncData.sqlite3" in tool.artifacts[0].patterns
    assert "Sync Data" in tool.artifacts[0].patterns
    assert "Current Session" in tool.artifacts[0].patterns


def test_internal_webcache_parser_extracts_webcache_dat_files():
    registry = ToolRegistry.from_files([default_plugin_path()])
    tool = registry.get_tool("WebCacheParser")

    assert tool.type == "internal_webcache"
    assert tool.artifacts[0].name == "webcache"
    assert tool.artifacts[0].source == "Users"
    assert tool.artifacts[0].patterns == ("WebCacheV*.dat",)
    assert tool.artifacts[0].optional is True


def test_internal_package_cache_parser_is_configured():
    registry = ToolRegistry.from_files([default_plugin_path()])
    tool = registry.get_tool("PackageCacheParser")

    assert tool.type == "internal_package_cache"
    assert tool.artifacts[0].name == "package_cache_profiles"
    assert tool.artifacts[0].source == "Users"
    assert tool.artifacts[0].process_in_place is True
    assert tool.artifacts[0].optional is True


def test_internal_mailbox_and_messaging_parsers_are_configured():
    registry = ToolRegistry.from_files([default_plugin_path()])
    mailbox = registry.get_tool("MailboxParser")
    messaging = registry.get_tool("MessagingParser")

    assert mailbox.type == "internal_mailbox"
    assert mailbox.artifacts[0].name == "mail_artifacts"
    assert mailbox.artifacts[0].source == "Users"
    assert "*.pst" in mailbox.artifacts[0].patterns
    assert "*.mbx" in mailbox.artifacts[0].patterns
    assert messaging.type == "internal_messaging"
    assert messaging.artifacts[0].name == "messaging_app_data"
    assert "*.ldb" in messaging.artifacts[0].patterns
    assert "*.md" in messaging.artifacts[0].patterns
    assert "*.json" in messaging.artifacts[0].patterns
    assert any("Slack" in pattern for pattern in messaging.artifacts[0].include_path_patterns)
    assert "Users/*/AppData/Local/Packages/*Slack*/*" in messaging.artifacts[0].include_path_patterns
    assert "Users/*/AppData/Local/Packages/*Teams*/*" in messaging.artifacts[0].include_path_patterns
    assert "Users/*/AppData/*/ChatGPT/*" in messaging.artifacts[0].include_path_patterns
    assert "Users/*/AppData/*/Claude/*" in messaging.artifacts[0].include_path_patterns
    assert "Users/*/Documents/*/.obsidian/*" in messaging.artifacts[0].include_path_patterns


def test_dedicated_registry_tools_are_configured():
    registry = ToolRegistry.from_files([default_plugin_path()])

    amcache = registry.get_tool("AmcacheParser")
    assert amcache.enabled is True
    assert build_tool_command(
        amcache,
        mount=Path("/unused"),
        output=Path("/cases/1/outputs/AmcacheParser"),
        artifacts={"amcache_hive": Path("/cases/1/artifacts/registry/Amcache.hve")},
    ) == [
        resolve_dotnet_runtime(),
        amcache.executable,
        "-f",
        "/cases/1/artifacts/registry/Amcache.hve",
        "--csv",
        "/cases/1/outputs/AmcacheParser",
    ]

    shimcache = registry.get_tool("AppCompatCacheParser")
    assert shimcache.enabled is True
    assert build_tool_command(
        shimcache,
        mount=Path("/unused"),
        output=Path("/cases/1/outputs/AppCompatCacheParser"),
        artifacts={"registry_system": Path("/cases/1/artifacts/registry/SYSTEM")},
    ) == [
        resolve_dotnet_runtime(),
        shimcache.executable,
        "-f",
        "/cases/1/artifacts/registry/SYSTEM",
        "--csv",
        "/cases/1/outputs/AppCompatCacheParser",
        "--csvf",
        "AppCompatCache.csv",
    ]

def test_evtx_triage_includes_office_alerts_log():
    registry = ToolRegistry.from_files([default_plugin_path()])
    tool = registry.get_tool("EvtxECmdTriage")
    artifacts = {artifact.name: artifact for artifact in tool.artifacts}

    assert "OAlerts.evtx" in artifacts["evtx_triage_logs"].patterns


def test_dedicated_shellbag_tool_is_configured():
    registry = ToolRegistry.from_files([default_plugin_path()])
    shellbags = registry.get_tool("SBECmd")

    assert shellbags.enabled is True
    assert build_tool_command(
        shellbags,
        mount=Path("/unused"),
        output=Path("/cases/1/outputs/SBECmd"),
        artifacts={"registry_ntuser": Path("/cases/1/artifacts/registry/users/ntuser")},
    ) == [
        resolve_dotnet_runtime(),
        shellbags.executable,
        "-d",
        "/cases/1/artifacts/registry/users",
        "--csv",
        "/cases/1/outputs/SBECmd",
        "--csvf",
        "ShellBags.csv",
    ]


def test_mftecmd_usn_is_configured_with_mft_context():
    registry = ToolRegistry.from_files([default_plugin_path()])
    tool = registry.get_tool("MFTECmdUSN")

    assert [artifact.name for artifact in tool.artifacts] == ["MFT", "UsnJrnlJ"]
    assert tool.artifacts[1].source == "$Extend/$UsnJrnl:$J"
    assert build_tool_command(
        tool,
        mount=Path("/unused"),
        output=Path("/cases/1/outputs/MFTECmdUSN"),
        artifacts={
            "MFT": Path("/cases/1/artifacts/$MFT"),
            "UsnJrnlJ": Path("/cases/1/artifacts/$Extend/$J"),
        },
    ) == [
        resolve_dotnet_runtime(),
        tool.executable,
        "-f",
        "/cases/1/artifacts/$Extend/$J",
        "-m",
        "/cases/1/artifacts/$MFT",
        "--csv",
        "/cases/1/outputs/MFTECmdUSN",
        "--csvf",
        "USNJrnl.csv",
    ]


def test_usn_rewind_is_configured_with_mft_context():
    registry = ToolRegistry.from_files([default_plugin_path()])
    tool = registry.get_tool("USNRewind")

    assert tool.executable.endswith("usnjrnl-forensic")
    assert [artifact.name for artifact in tool.artifacts] == ["MFT", "UsnJrnlJ"]
    assert tool.artifacts[1].source == "$Extend/$UsnJrnl:$J"
    assert build_tool_command(
        tool,
        mount=Path("/unused"),
        output=Path("/cases/1/outputs/USNRewind"),
        artifacts={
            "MFT": Path("/cases/1/artifacts/$MFT"),
            "UsnJrnlJ": Path("/cases/1/artifacts/$Extend/$J"),
        },
    ) == [
        tool.executable,
        "-j",
        "/cases/1/artifacts/$Extend/$J",
        "-m",
        "/cases/1/artifacts/$MFT",
        "--csv",
        "/cases/1/outputs/USNRewind/usn_rewind.csv",
        "--stats",
    ]


def test_mftecmd_logfile_is_configured():
    registry = ToolRegistry.from_files([default_plugin_path()])
    tool = registry.get_tool("MFTECmdLogFile")

    assert [artifact.name for artifact in tool.artifacts] == ["LogFile"]
    assert tool.artifacts[0].source == "$LogFile"
    assert tool.artifacts[0].inode == "2"
    assert build_tool_command(
        tool,
        mount=Path("/unused"),
        output=Path("/cases/1/outputs/MFTECmdLogFile"),
        artifacts={"LogFile": Path("/cases/1/artifacts/$LogFile")},
    ) == [
        resolve_dotnet_runtime(),
        tool.executable,
        "-f",
        "/cases/1/artifacts/$LogFile",
        "--csv",
        "/cases/1/outputs/MFTECmdLogFile",
        "--csvf",
        "LogFile.csv",
    ]


def test_ntfsparse_logfile_is_configured():
    registry = ToolRegistry.from_files([default_plugin_path()])
    tool = registry.get_tool("NTFSParseLogFile")

    assert tool.type == "internal_ntfs_logfile_ntfsparse"
    assert [artifact.name for artifact in tool.artifacts] == ["LogFile"]
    assert tool.artifacts[0].source == "$LogFile"
    assert build_tool_command(
        tool,
        mount=Path("/unused"),
        output=Path("/cases/1/outputs/NTFSParseLogFile"),
        artifacts={"LogFile": Path("/cases/1/artifacts/$LogFile")},
    ) == [
        "python3",
        "logfileparse.py",
        "-f",
        "/cases/1/artifacts/$LogFile",
        "-t",
        "csv",
        "-e",
        "/cases/1/outputs/NTFSParseLogFile/LogFile.csv",
    ]


def test_srumecmd_is_configured_with_srudb_and_software_hive():
    registry = ToolRegistry.from_files([default_plugin_path()])
    tool = registry.get_tool("SrumECmd")

    assert [artifact.name for artifact in tool.artifacts] == ["srum_dir", "registry_software"]
    assert build_tool_command(
        tool,
        mount=Path("/unused"),
        output=Path("/cases/1/outputs/SrumECmd"),
        artifacts={
            "srum_dir": Path("/cases/1/artifacts/Windows/System32/sru"),
            "registry_software": Path("/cases/1/artifacts/registry/SOFTWARE"),
        },
    ) == [
        resolve_dotnet_runtime(),
        tool.executable,
        "-f",
        "/cases/1/artifacts/Windows/System32/sru/SRUDB.dat",
        "-r",
        "/cases/1/artifacts/registry/SOFTWARE",
        "--csv",
        "/cases/1/outputs/SrumECmd",
    ]


def test_internal_srum_parser_is_configured_for_linux_worker():
    registry = ToolRegistry.from_files([default_plugin_path()])
    tool = registry.get_tool("SrumParser")

    assert tool.type == "internal_srum"
    assert [artifact.name for artifact in tool.artifacts] == ["srum_dir", "registry_software", "ras_phonebooks"]
    assert build_tool_command(
        tool,
        mount=Path("/unused"),
        output=Path("/cases/1/outputs/SrumParser"),
        artifacts={"srum_dir": Path("/cases/1/artifacts/Windows/System32/sru")},
    ) == [
        "internal-srum-parser",
        "/cases/1/artifacts/Windows/System32/sru",
        "/cases/1/outputs/SrumParser",
    ]
    assert required_paths(
        tool,
        mount=Path("/unused"),
        output=Path("/cases/1/outputs/SrumParser"),
        artifacts={"srum_dir": Path("/cases/1/artifacts/Windows/System32/sru")},
    ) == [Path("/cases/1/artifacts/Windows/System32/sru/SRUDB.dat")]


def test_internal_ual_parser_is_configured_for_linux_worker():
    registry = ToolRegistry.from_files([default_plugin_path()])
    tool = registry.get_tool("UalParser")

    assert tool.type == "internal_ual"
    assert [artifact.name for artifact in tool.artifacts] == ["ual_sum_dir"]
    assert tool.artifacts[0].source == "Windows/System32/LogFiles/SUM"
    assert tool.artifacts[0].patterns == ("*.mdb",)
    assert build_tool_command(
        tool,
        mount=Path("/unused"),
        output=Path("/cases/1/outputs/UalParser"),
        artifacts={"ual_sum_dir": Path("/cases/1/artifacts/Windows/System32/LogFiles/SUM")},
    ) == [
        "internal-ual-parser",
        "/cases/1/artifacts/Windows/System32/LogFiles/SUM",
        "/cases/1/outputs/UalParser",
    ]
    assert required_paths(
        tool,
        mount=Path("/unused"),
        output=Path("/cases/1/outputs/UalParser"),
        artifacts={"ual_sum_dir": Path("/cases/1/artifacts/Windows/System32/LogFiles/SUM")},
    ) == []


def test_sidr_is_configured_for_windows_search_index_directory(monkeypatch):
    monkeypatch.delenv("SIDR_BIN", raising=False)
    registry = ToolRegistry.from_files([default_plugin_path()])
    tool = registry.get_tool("SIDR")

    assert tool.artifacts[0].source == "ProgramData/Microsoft/Search/Data/Applications/Windows"
    assert build_tool_command(
        tool,
        mount=Path("/unused"),
        output=Path("/cases/1/outputs/SIDR"),
        artifacts={
            "windows_search_index": Path("/cases/1/artifacts/WindowsSearch/Applications/Windows"),
        },
    ) == [
        tool.executable,
        "-f",
        "csv",
        "-o",
        "/cases/1/outputs/SIDR",
        "/cases/1/artifacts/WindowsSearch/Applications/Windows",
    ]
    assert [tool.name for tool in registry.profile_tools("windows-search")] == [
        "SIDR",
        "WindowsSearchESEParser",
        "WindowsSearchGatherParser",
    ]
    assert [tool.name for tool in registry.profile_tools("windows-search-ese")] == [
        "WindowsSearchESEParser",
    ]


def test_windows_wer_defender_profile_is_configured():
    registry = ToolRegistry.from_files([default_plugin_path()])

    wer = registry.get_tool("WindowsErrorReportingParser")
    defender = registry.get_tool("WindowsDefenderParser")
    assert wer.type == "internal_windows_error_reporting"
    assert wer.artifacts[0].source == "ProgramData/Microsoft/Windows/WER"
    assert defender.type == "internal_windows_defender"
    assert defender.artifacts[0].source == "ProgramData/Microsoft/Windows Defender/Scans/History/Service"
    assert [tool.name for tool in registry.profile_tools("windows-wer-defender")] == [
        "WindowsErrorReportingParser",
        "WindowsDefenderParser",
    ]
