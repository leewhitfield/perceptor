# windows-full Artifact Inventory

Source: `forensic_orchestrator/plugins/eztools.yaml`

Complete Windows profile with full event logs, file system metadata, cloud, email, messaging, and browser artifacts

## Profile Settings

- Includes Windows.old pass: `True`
- Tool count: `48`

## Coverage Categories

### Application Execution

- `AmcacheParser`
- `AppCompatCacheParser`
- `EtlParser`
- `EvtxECmd`
- `JLECmd`
- `LECmd`
- `PECmd`
- `PrefetchParser`
- `RegistryArtifactParser`
- `SrumParser`
- `WindowsActivitiesParser`

### File Folder Opening

- `JLECmd`
- `LECmd`
- `OfficeBackstageParser`
- `RegistryArtifactParser`
- `WebCacheParser`
- `WindowsSearchESEParser`
- `WindowsSearchGatherParser`
- `ZoneIdentifierParser`

### Web Derived File Download Activity

- `BrowserCacheParser`
- `ChromiumParser`
- `FirefoxParser`
- `WebCacheParser`

### Webcache File References

Note: `file:///` local file references are specifically WebCache-derived in the current pipeline.

- `WebCacheParser`

### Deleted Items File Existence

- `MFTECmd`
- `MFTECmdUSN`
- `MFTECmdLogFile`
- `MFTECmdI30`
- `NTFSParseLogFile`
- `RecycleParser`
- `RegistryArtifactParser`
- `ThumbcacheParser`
- `WindowsSearchESEParser`
- `WindowsSearchGatherParser`

### Browser Activity

- `BrowserCacheParser`
- `ChromiumParser`
- `FirefoxParser`
- `WebCacheParser`

### Cloud Storage

Note: native cloud parsers provide local sync evidence; browser and WebCache parsers provide web portal access context.

- `ChromiumParser`
- `CloudSyncParser`
- `EtlParser`
- `FirefoxParser`
- `OneDriveExplorer`
- `OneDriveOdlParser`
- `PackageArtifactsParser`
- `PackageCacheParser`
- `SQLECmd`
- `WebCacheParser`

### Account Usage

- `EvtxECmd`
- `RdpCacheParser`
- `RdpVisionReview`
- `RegistryArtifactParser`
- `SAMParser`

### Network Activity Location

- `EvtxECmd`
- `EtlParser`
- `LECmd`
- `RegistryArtifactParser`
- `SrumParser`

### System Information

- `SetupApiParser`
- `RegistryArtifactParser`
- `RegistryParser`
- `RECmd`
- `UalParser`
- `WindowsDefenderParser`
- `WindowsErrorReportingParser`

### Communications User Content

- `MailboxParser`
- `MessagingParser`
- `PackageArtifactsParser`
- `TelemetryParser`
- `UserDictionaryParser`
- `WindowsMailParser`

## Tools And Artifact Inputs

### MFTECmd

- Type: `dotnet`
- Executable: `/opt/eztools/MFTECmd/MFTECmd.dll`
- Outputs: `csv`
- Artifact inputs:
  - name=`MFT`; source=`$MFT`; destination=`$MFT`; inode=`0`
- Required paths:
  - `{artifact:MFT}`
- Command template:

```text
dotnet {executable} -f {artifact:MFT} --csv {output}
```

### MFTECmdUSN

- Type: `dotnet`
- Executable: `/opt/eztools/MFTECmd/MFTECmd.dll`
- Outputs: `csv`
- Artifact inputs:
  - name=`MFT`; source=`$MFT`; destination=`$MFT`; inode=`0`
  - name=`UsnJrnlJ`; source=`$Extend/$UsnJrnl:$J`; destination=`$Extend/$J`
- Required paths:
  - `{artifact:UsnJrnlJ}`
  - `{artifact:MFT}`
- Command template:

```text
dotnet {executable} -f {artifact:UsnJrnlJ} -m {artifact:MFT} --csv {output} --csvf USNJrnl.csv
```

### MFTECmdLogFile

- Type: `dotnet`
- Executable: `/opt/eztools/MFTECmd/MFTECmd.dll`
- Outputs: `csv`
- Artifact inputs:
  - name=`LogFile`; source=`$LogFile`; destination=`$LogFile`; inode=`2`
- Required paths:
  - `{artifact:LogFile}`
- Command template:

```text
dotnet {executable} -f {artifact:LogFile} --csv {output} --csvf LogFile.csv
```

### NTFSParseLogFile

- Type: `internal_ntfs_logfile_ntfsparse`
- Outputs: `csv`
- Artifact inputs:
  - name=`LogFile`; source=`$LogFile`; destination=`$LogFile`; inode=`2`
- Required paths:
  - `{artifact:LogFile}`
- Command template:

```text
python3 logfileparse.py -f {artifact:LogFile} -t csv -e {output}/LogFile.csv
```

### MFTECmdI30

- Type: `internal_ntfs_index_mftecmd`
- Executable: `/opt/eztools/MFTECmd/MFTECmd.dll`
- Outputs: `csv`
- Command template:

```text
dotnet {executable} $I30-targeted --csv {output}
```

### SrumParser

- Type: `internal_srum`
- Executable: `esedbexport`
- Outputs: `csv`
- Artifact inputs:
  - name=`srum_dir`; source=`Windows/System32/sru`; destination=`Windows/System32/sru`
  - name=`registry_software`; source=`WINDOWS/system32/config/SOFTWARE`; destination=`registry/SOFTWARE`
  - name=`ras_phonebooks`; source=`Users`; destination=`vpn_phonebooks`
- Required paths:
  - `{artifact:srum_dir}/SRUDB.dat`
- Command template:

```text
internal-srum-parser {artifact:srum_dir} {output}
```

### UalParser

- Type: `internal_ual`
- Executable: `esedbexport`
- Outputs: `csv`
- Artifact inputs:
  - name=`ual_sum_dir`; source=`Windows/System32/LogFiles/SUM`; destination=`Windows/System32/LogFiles/SUM`
- Command template:

```text
internal-ual-parser {artifact:ual_sum_dir} {output}
```

### SIDR

- Type: `binary`
- Executable: `sidr`
- Outputs: `csv`
- Artifact inputs:
  - name=`windows_search_index`; source=`ProgramData/Microsoft/Search/Data/Applications/Windows`; destination=`WindowsSearch/Applications/Windows`
- Required paths:
  - `{artifact:windows_search_index}`
- Command template:

```text
{executable} -f csv -o {output} {artifact:windows_search_index}
```

### WindowsSearchESEParser

- Type: `internal_windows_search_ese`
- Executable: `esedbexport`
- Outputs: `csv`
- Artifact inputs:
  - name=`windows_search_index`; source=`ProgramData/Microsoft/Search/Data/Applications/Windows`; destination=`WindowsSearch/Applications/Windows`
- Command template:

```text
internal-windows-search-ese-parser {artifact:windows_search_index} --csv {output}
```

### WindowsSearchGatherParser

- Type: `internal_windows_search_gather`
- Outputs: `csv`
- Artifact inputs:
  - name=`windows_search_gather_logs`; source=`ProgramData/Microsoft/Search/Data/Applications/Windows/GatherLogs/SystemIndex`; destination=`WindowsSearch/Applications/Windows/GatherLogs/SystemIndex`
- Command template:

```text
internal-windows-search-gather-parser {artifact:windows_search_gather_logs} --csv {output}
```

### WindowsErrorReportingParser

- Type: `internal_windows_error_reporting`
- Outputs: `csv`
- Artifact inputs:
  - name=`windows_error_reporting`; source=`ProgramData/Microsoft/Windows/WER`; destination=`Windows/WER`
- Command template:

```text
internal-windows-error-reporting-parser {artifact:windows_error_reporting} --csv {output}
```

### WindowsDefenderParser

- Type: `internal_windows_defender`
- Outputs: `csv`
- Artifact inputs:
  - name=`windows_defender_service_history`; source=`ProgramData/Microsoft/Windows Defender/Scans/History/Service`; destination=`WindowsDefender/Scans/History/Service`
  - name=`windows_defender_support_logs`; source=`ProgramData/Microsoft/Windows Defender/Support`; destination=`WindowsDefender/Support`
  - name=`windows_defender_cache_manager`; source=`ProgramData/Microsoft/Windows Defender/Scans/History/CacheManager`; destination=`WindowsDefender/Scans/History/CacheManager`
  - name=`windows_defender_scan_cache`; source=`ProgramData/Microsoft/Windows Defender/Scans`; destination=`WindowsDefender/Scans`
  - name=`windows_defender_engine_db`; source=`ProgramData/Microsoft/Windows Defender/Scans`; destination=`WindowsDefender/ScansEngineDb`
- Command template:

```text
internal-windows-defender-parser {artifact:windows_defender_service_history} --csv {output}
```

### EvtxECmd

- Type: `dotnet`
- Executable: `/opt/eztools/EvtxECmd/EvtxECmd.dll`
- Outputs: `csv`
- Artifact inputs:
  - name=`evtx_logs`; source=`Windows/System32/winevt/Logs`; destination=`Windows/System32/winevt/Logs`
- Required paths:
  - `{artifact:evtx_logs}`
- Command template:

```text
dotnet {executable} -d {artifact:evtx_logs} --csv {output}
```

### SAMParser

- Type: `internal_sam`
- Outputs: `csv`
- Artifact inputs:
  - name=`sam_hive`; source=`WINDOWS/system32/config/SAM`; destination=`registry/SAM`
- Required paths:
  - `{artifact:sam_hive}`
- Command template:

```text
internal-sam-parser {artifact:sam_hive} --csv {output}
```

### RegistryParser

- Type: `internal_registry`
- Outputs: `csv`
- Artifact inputs:
  - name=`registry_system`; source=`WINDOWS/system32/config/SYSTEM`; destination=`registry/SYSTEM`
  - name=`registry_software`; source=`WINDOWS/system32/config/SOFTWARE`; destination=`registry/SOFTWARE`
  - name=`registry_security`; source=`WINDOWS/system32/config/SECURITY`; destination=`registry/SECURITY`
  - name=`registry_sam`; source=`WINDOWS/system32/config/SAM`; destination=`registry/SAM`
  - name=`registry_amcache`; source=`Windows/AppCompat/Programs/Amcache.hve`; destination=`registry/Amcache.hve`
  - name=`registry_ntuser`; source=`Users`; destination=`registry/users`
- Command template:

```text
internal-registry-parser {artifact:registry_system} {artifact:registry_software} {artifact:registry_security} {artifact:registry_sam} {artifact:registry_amcache} {artifact:registry_ntuser} --csv {output}
```

### RECmd

- Type: `dotnet`
- Executable: `/opt/eztools/RECmd/RECmd.dll`
- Outputs: `csv`
- Artifact inputs:
  - name=`registry_system`; source=`WINDOWS/system32/config/SYSTEM`; destination=`registry/SYSTEM`
  - name=`registry_system_log1`; source=`WINDOWS/system32/config/SYSTEM.LOG1`; destination=`registry/SYSTEM.LOG1`
  - name=`registry_system_log2`; source=`WINDOWS/system32/config/SYSTEM.LOG2`; destination=`registry/SYSTEM.LOG2`
  - name=`registry_software`; source=`WINDOWS/system32/config/SOFTWARE`; destination=`registry/SOFTWARE`
  - name=`registry_software_log1`; source=`WINDOWS/system32/config/SOFTWARE.LOG1`; destination=`registry/SOFTWARE.LOG1`
  - name=`registry_software_log2`; source=`WINDOWS/system32/config/SOFTWARE.LOG2`; destination=`registry/SOFTWARE.LOG2`
  - name=`registry_security`; source=`WINDOWS/system32/config/SECURITY`; destination=`registry/SECURITY`
  - name=`registry_security_log1`; source=`WINDOWS/system32/config/SECURITY.LOG1`; destination=`registry/SECURITY.LOG1`
  - name=`registry_security_log2`; source=`WINDOWS/system32/config/SECURITY.LOG2`; destination=`registry/SECURITY.LOG2`
  - name=`registry_sam`; source=`WINDOWS/system32/config/SAM`; destination=`registry/SAM`
  - name=`registry_sam_log1`; source=`WINDOWS/system32/config/SAM.LOG1`; destination=`registry/SAM.LOG1`
  - name=`registry_sam_log2`; source=`WINDOWS/system32/config/SAM.LOG2`; destination=`registry/SAM.LOG2`
  - name=`registry_ntuser`; source=`Users`; destination=`registry/users`
  - name=`registry_user_logs`; source=`Users`; destination=`registry/users`
- Required paths:
  - `{artifact_parent:registry_system}`
  - `{plugins}/recmd_windows_activity.reb`
- Command template:

```text
dotnet {executable} -d {artifact_parent:registry_system} --bn {plugins}/recmd_windows_activity.reb --csv {output} --csvf RECmd_WindowsActivity.csv
```

### RegistryArtifactParser

- Type: `internal_registry_artifacts`
- Outputs: `csv`
- Artifact inputs:
  - name=`registry_system`; source=`WINDOWS/system32/config/SYSTEM`; destination=`registry/SYSTEM`
  - name=`registry_system_log1`; source=`WINDOWS/system32/config/SYSTEM.LOG1`; destination=`registry/SYSTEM.LOG1`
  - name=`registry_system_log2`; source=`WINDOWS/system32/config/SYSTEM.LOG2`; destination=`registry/SYSTEM.LOG2`
  - name=`registry_software`; source=`WINDOWS/system32/config/SOFTWARE`; destination=`registry/SOFTWARE`
  - name=`registry_software_log1`; source=`WINDOWS/system32/config/SOFTWARE.LOG1`; destination=`registry/SOFTWARE.LOG1`
  - name=`registry_software_log2`; source=`WINDOWS/system32/config/SOFTWARE.LOG2`; destination=`registry/SOFTWARE.LOG2`
  - name=`registry_sam`; source=`WINDOWS/system32/config/SAM`; destination=`registry/SAM`
  - name=`registry_sam_log1`; source=`WINDOWS/system32/config/SAM.LOG1`; destination=`registry/SAM.LOG1`
  - name=`registry_sam_log2`; source=`WINDOWS/system32/config/SAM.LOG2`; destination=`registry/SAM.LOG2`
  - name=`registry_amcache`; source=`Windows/AppCompat/Programs/Amcache.hve`; destination=`registry/Amcache.hve`
  - name=`registry_amcache_log1`; source=`Windows/AppCompat/Programs/Amcache.hve.LOG1`; destination=`registry/Amcache.hve.LOG1`
  - name=`registry_amcache_log2`; source=`Windows/AppCompat/Programs/Amcache.hve.LOG2`; destination=`registry/Amcache.hve.LOG2`
  - name=`registry_ntuser`; source=`Users`; destination=`registry/users/ntuser`
  - name=`registry_ntuser_logs`; source=`Users`; destination=`registry/users/ntuser`
  - name=`registry_usrclass`; source=`Users`; destination=`registry/users/usrclass`
  - name=`registry_usrclass_logs`; source=`Users`; destination=`registry/users/usrclass`
- Command template:

```text
internal-registry-artifact-parser {artifact:registry_system} {artifact:registry_software} {artifact:registry_sam} {artifact:registry_amcache} {artifact:registry_ntuser} {artifact:registry_usrclass} --csv {output}
```

### AmcacheParser

- Type: `dotnet`
- Executable: `/opt/eztools/AmcacheParser/AmcacheParser.dll`
- Outputs: `csv`
- Artifact inputs:
  - name=`amcache_hive`; source=`Windows/AppCompat/Programs/Amcache.hve`; destination=`registry/Amcache.hve`
  - name=`amcache_log1`; source=`Windows/AppCompat/Programs/Amcache.hve.LOG1`; destination=`registry/Amcache.hve.LOG1`
  - name=`amcache_log2`; source=`Windows/AppCompat/Programs/Amcache.hve.LOG2`; destination=`registry/Amcache.hve.LOG2`
- Required paths:
  - `{artifact:amcache_hive}`
- Command template:

```text
dotnet {executable} -f {artifact:amcache_hive} --csv {output}
```

### AppCompatCacheParser

- Type: `dotnet`
- Executable: `/opt/eztools/AppCompatCacheParser/AppCompatCacheParser.dll`
- Outputs: `csv`
- Artifact inputs:
  - name=`registry_system`; source=`WINDOWS/system32/config/SYSTEM`; destination=`registry/SYSTEM`
  - name=`registry_system_log1`; source=`WINDOWS/system32/config/SYSTEM.LOG1`; destination=`registry/SYSTEM.LOG1`
  - name=`registry_system_log2`; source=`WINDOWS/system32/config/SYSTEM.LOG2`; destination=`registry/SYSTEM.LOG2`
- Required paths:
  - `{artifact:registry_system}`
- Command template:

```text
dotnet {executable} -f {artifact:registry_system} --csv {output} --csvf AppCompatCache.csv
```

### PECmd

- Type: `dotnet`
- Executable: `/opt/eztools/PECmd/PECmd.dll`
- Outputs: `csv`
- Artifact inputs:
  - name=`prefetch_files`; source=`Windows/Prefetch`; destination=`Windows/Prefetch`
- Required paths:
  - `{artifact:prefetch_files}`
- Command template:

```text
dotnet {executable} -d {artifact:prefetch_files} --csv {output}
```

### PrefetchParser

- Type: `internal_prefetch`
- Outputs: `csv`
- Artifact inputs:
  - name=`prefetch_files`; source=`Windows/Prefetch`; destination=`Windows/Prefetch`
- Required paths:
  - `{artifact:prefetch_files}`
- Command template:

```text
internal-prefetch-parser {artifact:prefetch_files} --csv {output}
```

### RecycleParser

- Type: `internal_recycle`
- Outputs: `csv`
- Artifact inputs:
  - name=`recycle_modern`; source=`$Recycle.Bin`; destination=`RecycleBin/$Recycle.Bin`
  - name=`recycle_xp`; source=`RECYCLER`; destination=`RecycleBin/RECYCLER`
  - name=`recycled_xp`; source=`Recycled`; destination=`RecycleBin/Recycled`
- Command template:

```text
internal-recycle-parser {artifact:recycle_modern} {artifact:recycle_xp} {artifact:recycled_xp} --csv {output}
```

### FirefoxParser

- Type: `internal_firefox`
- Outputs: `csv`
- Artifact inputs:
  - name=`firefox_profiles`; source=`Users`; destination=`browser/Firefox`
- Required paths:
  - `{artifact:firefox_profiles}`
- Command template:

```text
internal-firefox-parser {artifact:firefox_profiles} --csv {output}
```

### ChromiumParser

- Type: `internal_chromium`
- Outputs: `csv`
- Artifact inputs:
  - name=`chromium_profiles`; source=`Users`; destination=`browser/Chromium`
- Required paths:
  - `{artifact:chromium_profiles}`
- Command template:

```text
internal-chromium-parser {artifact:chromium_profiles} --csv {output}
```

### OfficeBackstageParser

- Type: `internal_office_backstage`
- Outputs: `csv`
- Artifact inputs:
  - name=`office_backstage`; source=`Users`; destination=`OfficeBackstage`
- Command template:

```text
internal-office-backstage-parser {artifact:office_backstage} --csv {output}
```

### UserDictionaryParser

- Type: `internal_user_dictionary`
- Outputs: `csv`
- Artifact inputs:
  - name=`user_dictionaries`; source=`Users`; destination=`UserDictionaries`
- Command template:

```text
internal-user-dictionary-parser {artifact:user_dictionaries} --csv {output}
```

### ZoneIdentifierParser

- Type: `internal_zone_identifier`
- Outputs: `csv`
- Artifact inputs:
  - name=`zone_identifier_ads`; source=`Users`; destination=`ZoneIdentifierADS`
- Command template:

```text
internal-zone-identifier-parser {artifact:zone_identifier_ads} --csv {output}
```

### ThumbcacheParser

- Type: `internal_thumbcache`
- Outputs: `csv`
- Artifact inputs:
  - name=`thumbcache`; source=`Users`; destination=`Thumbcache`
- Command template:

```text
internal-thumbcache-parser {artifact:thumbcache} --csv {output}
```

### RdpCacheParser

- Type: `internal_rdp_cache`
- Outputs: `csv`
- Artifact inputs:
  - name=`rdp_cache_profiles`; source=`Users`; destination=`RdpBitmapCache`
- Command template:

```text
internal-rdp-cache-parser {artifact:rdp_cache_profiles} --csv {output}
```

### RdpVisionReview

- Type: `internal_rdp_vision_review`
- Outputs: `csv`
- Command template:

```text
internal-rdp-vision-review {output}
```

### WebCacheParser

- Type: `internal_webcache`
- Outputs: `csv`
- Artifact inputs:
  - name=`webcache`; source=`Users`; destination=`WebCache`
- Command template:

```text
internal-webcache-parser {artifact:webcache} --csv {output}
```

### BrowserCacheParser

- Type: `internal_browser_cache`
- Outputs: `csv`
- Artifact inputs:
  - name=`browser_cache_profiles`; source=`Users`; destination=`browser/Cache`
- Command template:

```text
internal-browser-cache-parser {artifact:browser_cache_profiles} --csv {output}
```

### PackageCacheParser

- Type: `internal_package_cache`
- Outputs: `csv`
- Artifact inputs:
  - name=`package_cache_profiles`; source=`Users`; destination=`packages/CacheStorage`
- Command template:

```text
internal-package-cache-parser {artifact:package_cache_profiles} --csv {output}
```

### PackageArtifactsParser

- Type: `internal_package_artifacts`
- Outputs: `csv`
- Artifact inputs:
  - name=`package_artifact_profiles`; source=``; destination=`packages/Artifacts`
- Command template:

```text
internal-package-artifacts-parser {artifact:package_artifact_profiles} --csv {output}
```

### TelemetryParser

- Type: `internal_telemetry`
- Outputs: `csv`
- Artifact inputs:
  - name=`telemetry_artifacts`; source=``; destination=`telemetry`
- Command template:

```text
internal-telemetry-parser {artifact:telemetry_artifacts} --csv {output}
```

### SQLECmd

- Type: `dotnet`
- Executable: `/opt/eztools/SQLECmd/SQLECmd.dll`
- Outputs: `csv`
- Artifact inputs:
  - name=`cloud_sqlite_candidates`; source=`Users`; destination=`CloudSQLite/Users`
- Required paths:
  - `{artifact:cloud_sqlite_candidates}`
- Command template:

```text
dotnet {executable} -d {artifact:cloud_sqlite_candidates} --hunt --csv {output}
```

### CloudSyncParser

- Type: `internal_cloud_sync`
- Outputs: `csv`
- Artifact inputs:
  - name=`cloud_sync_artifacts`; source=`Users`; destination=`CloudSync/Users`
- Command template:

```text
internal-cloud-sync-parser {artifact:cloud_sync_artifacts} --csv {output}
```

### OneDriveExplorer

- Type: `internal_onedrive_explorer`
- Outputs: `csv`
- Artifact inputs:
  - name=`onedrive_profiles`; source=`Users`; destination=`OneDriveExplorer/Users`
- Command template:

```text
internal-onedrive-explorer {artifact:onedrive_profiles} --csv {output}
```

### OneDriveOdlParser

- Type: `internal_onedrive_odl`
- Outputs: `csv`
- Artifact inputs:
  - name=`onedrive_logs`; source=`Users`; destination=`OneDriveLogs/Users`
- Command template:

```text
internal-onedrive-odl-parser {artifact:onedrive_logs} --csv {output}
```

### WindowsActivitiesParser

- Type: `internal_windows_activities`
- Outputs: `csv`
- Artifact inputs:
  - name=`windows_activities`; source=`Users`; destination=`WindowsActivities`
- Command template:

```text
internal-windows-activities-parser {artifact:windows_activities} --csv {output}
```

### EtlParser

- Type: `internal_etl`
- Outputs: `csv`
- Artifact inputs:
  - name=`etl_files`; source=`Windows/System32/LogFiles`; destination=`Windows/System32/LogFiles`
  - name=`etl_panther_files`; source=`Windows/Panther`; destination=`Windows/Panther`
- Command template:

```text
internal-etl-parser {artifact:etl_files} --csv {output}
```

### MailboxParser

- Type: `internal_mailbox`
- Outputs: `csv`
- Artifact inputs:
  - name=`mail_artifacts`; source=``; destination=`mail`
- Command template:

```text
internal-mailbox-parser {artifact:mail_artifacts} --csv {output}
```

### WindowsMailParser

- Type: `internal_windows_mail`
- Outputs: `csv`
- Artifact inputs:
  - name=`windows_mail_data`; source=`Users`; destination=`windows_mail`
- Command template:

```text
internal-windows-mail-parser {artifact:windows_mail_data} --csv {output}
```

### MessagingParser

- Type: `internal_messaging`
- Outputs: `csv`
- Artifact inputs:
  - name=`messaging_app_data`; source=`Users`; destination=`messaging`
- Command template:

```text
internal-messaging-parser {artifact:messaging_app_data} --csv {output}
```

### SetupApiParser

- Type: `internal_setupapi`
- Outputs: `csv`
- Artifact inputs:
  - name=`setupapi_logs`; source=`Windows/INF`; destination=`SetupAPI`
- Command template:

```text
internal-setupapi-parser {artifact:setupapi_logs} --csv {output}
```

### ArchiveInventoryParser

- Type: `internal_archive_inventory`
- Outputs: `csv`
- Artifact inputs:
  - name=`archive_inventory_root`; source=``; destination=`ArchiveInventory`
- Required paths:
  - `{artifact:archive_inventory_root}`
- Command template:

```text
internal-archive-inventory {artifact:archive_inventory_root} {output}
```

### JLECmd

- Type: `dotnet`
- Executable: `/opt/eztools/JLECmd/JLECmd.dll`
- Outputs: `csv`
- Artifact inputs:
  - name=`jumplists`; source=`Users`; destination=`jumplists`
- Required paths:
  - `{artifact:jumplists}`
- Command template:

```text
dotnet {executable} -d {artifact:jumplists} --csv {output}
```

### LECmd

- Type: `dotnet`
- Executable: `/opt/eztools/LECmd/LECmd.dll`
- Outputs: `csv`
- Artifact inputs:
  - name=`lnk_files`; source=`Users`; destination=`lnk_files`
- Required paths:
  - `{artifact:lnk_files}`
- Command template:

```text
dotnet {executable} -d {artifact:lnk_files} --csv {output}
```

### SBECmd

- Type: `dotnet`
- Executable: `/opt/eztools/SBECmd/SBECmd.dll`
- Outputs: `csv`
- Artifact inputs:
  - name=`registry_ntuser`; source=`Users`; destination=`registry/users/ntuser`
  - name=`registry_ntuser_logs`; source=`Users`; destination=`registry/users/ntuser`
  - name=`registry_usrclass`; source=`Users`; destination=`registry/users/usrclass`
  - name=`registry_usrclass_logs`; source=`Users`; destination=`registry/users/usrclass`
- Required paths:
  - `{artifact_parent:registry_ntuser}`
- Command template:

```text
dotnet {executable} -d {artifact_parent:registry_ntuser} --csv {output} --csvf ShellBags.csv
```
