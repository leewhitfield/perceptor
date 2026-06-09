# Custom Parsers

Perceptor includes native parsers in addition to third-party tools. These
parsers are implemented in the `forensic_orchestrator` package and usually emit
normalized rows that are then imported into SQLite, DuckDB, and, where
appropriate, OpenSearch.

## Windows Full Internal Parsers

These parser types are wired into the Windows processing profile.

| Parser | Type | Purpose |
| --- | --- | --- |
| NTFSParseLogFile | `internal_ntfs_logfile_ntfsparse` | Parses NTFS `$LogFile` data with the internal NTFS parser path where available. |
| MFTECmdI30 | `internal_ntfs_index_mftecmd` | Runs targeted `$I30` directory index parsing and normalizes directory index entries. |
| SrumParser | `internal_srum` | Parses SRUM ESE exports into application, network, and resource usage records. |
| UalParser | `internal_ual` | Parses User Access Logging/SUM records, using `ual-timeliner` when available and falling back internally when needed. |
| BITSParser | `internal_bits` | Parses BITS `qmgr.db` data and related timestamp context where available. |
| WindowsSearchESEParser | `internal_windows_search_ese` | Parses supported Windows Search ESE exports into file and indexed-content metadata rows. |
| WindowsSearchGatherParser | `internal_windows_search_gather` | Parses Windows Search gather logs and related file activity signals. |
| WindowsErrorReportingParser | `internal_windows_error_reporting` | Parses Windows Error Reporting files and metadata. |
| WindowsDefenderParser | `internal_windows_defender` | Parses Windows Defender logs, histories, and detection metadata. |
| FileMetadataOffice | `internal_file_metadata` | Extracts internal metadata from Office documents. |
| FileMetadataPictures | `internal_file_metadata` | Extracts embedded metadata from picture files. |
| FileMetadataPicturesUserContent | `internal_file_metadata` | Extracts embedded metadata from likely user-content picture files while excluding common system and cloud-cache paths. |
| FileMetadataVideos | `internal_file_metadata` | Extracts embedded metadata from video files. |
| FileMetadataExecutables | `internal_file_metadata` | Extracts embedded metadata from executable files. |
| FileMetadataDocuments | `internal_file_metadata` | Extracts embedded metadata from document files. |
| FileMetadataExtractor | `internal_file_metadata` | General file metadata extraction path for configured file sets. |
| UserFileContentParser | `internal_file_content` | Extracts readable content from supported user files and sends large text bodies to OpenSearch with source provenance. |
| PrefetchParser | `internal_prefetch` | Parses Prefetch files and normalizes execution and run-time records. |
| SAMParser | `internal_sam` | Parses SAM hive data for local users and related account metadata. |
| RegistryParser | `internal_registry` | Parses registry hives into general registry rows. |
| RegistryArtifactParser | `internal_registry_artifacts` | Extracts targeted registry artifacts such as user activity, NetworkList, MountPoints2, outbound RDP history, installed programs, Bluetooth devices, clipboard settings, and other high-value keys. |
| RecycleParser | `internal_recycle` | Parses Recycle Bin artifacts. |
| FirefoxParser | `internal_firefox` | Parses Firefox history, downloads, cookies, cache, session, and related browser artifacts. |
| ChromiumParser | `internal_chromium` | Parses Chromium-family browser history, downloads, cookies, site settings, notifications, sessions, and related metadata. |
| ArchiveInventoryParser | `internal_archive_inventory` | Inventories archive contents so archives can be searched and reviewed without being treated as opaque files. |
| OfficeBackstageParser | `internal_office_backstage` | Parses Office backstage and recent-document artifacts. |
| UserDictionaryParser | `internal_user_dictionary` | Parses user dictionary entries such as `RoamingCustom.dic`. |
| ZoneIdentifierParser | `internal_zone_identifier` | Parses `Zone.Identifier` alternate data streams. |
| ThumbcacheParser | `internal_thumbcache` | Parses centralized Windows thumbcache databases. |
| RdpCacheParser | `internal_rdp_cache` | Parses RDP bitmap cache fragments and creates contact-sheet references. |
| RdpVisionReview | `internal_rdp_vision_review` | Adds OCR or optional semantic observations for RDP bitmap cache contact sheets. |
| WebCacheParser | `internal_webcache` | Parses Windows WebCache artifacts. |
| BrowserCacheParser | `internal_browser_cache` | Parses browser cache metadata and candidate cached content references. |
| PackageCacheParser | `internal_package_cache` | Parses Windows package cache artifacts. |
| PackageArtifactsParser | `internal_package_artifacts` | Parses app package artifacts such as Sticky Notes, notification databases, credential/vault metadata, Token Broker cache metadata, WSL indicators, and related package stores. |
| SetupApiParser | `internal_setupapi` | Parses SetupAPI logs for device-install and USB context. |
| TelemetryParser | `internal_telemetry` | Parses telemetry artifacts including EventTranscript-style diagnostic data where present. |
| CloudSyncParser | `internal_cloud_sync` | Parses cloud sync metadata and virtual path/cache relationships. |
| OneDriveExplorer | `internal_onedrive_explorer` | Parses OneDrive metadata in a format similar to OneDriveExplorer output. |
| SpotifyParser | `internal_spotify` | Parses Spotify cache and application artifacts where present. |
| OneDriveOdlParser | `internal_onedrive_odl` | Parses OneDrive ODL logs. |
| WindowsActivitiesParser | `internal_windows_activities` | Parses Windows Activities/Timeline database artifacts. |
| ClipboardParser | `internal_clipboard` | Parses Windows clipboard history stores and clipboard registry settings. |
| EtlParser | `internal_etl` | Parses ETL/ETW-derived artifacts supported by Perceptor's internal parser path. |
| MailboxParser | `internal_mailbox` | Parses supported mailbox formats and routes message bodies and attachments into the content pipeline where appropriate. |
| WindowsMailParser | `internal_windows_mail` | Parses Windows Mail application artifacts. |
| MessagingParser | `internal_messaging` | Parses messaging and communication application artifacts. |

## Workflow and Support Parsers

These parsers are not all standalone Windows profile tools, but they support
imports, reports, and enrichment workflows.

| Parser or module | Purpose |
| --- | --- |
| Google Takeout parser | Detects and parses Google Takeout Drive and Mail exports. Drive files are inventoried and readable content is indexed; Mail exports are routed through the mailbox parser. |
| Memory string scanner | Scans memory images and memory-support files with `bstrings` when available and fallback string extraction otherwise. |
| Structured memory parser | Runs bounded Volatility and MemProcFS workflows and normalizes structured memory records. |
| Windows Search memory parser | Normalizes Windows Search memory carve results and related memory-backed content references. |
| USB parsers | Normalize USB device, partition diagnostic, connection, volume, and correlation details. |
| USP import parser | Imports and normalizes TZWorks USP USB Parser output. |
| File carving support | Provides helper logic for carving and recovered-file workflows. |
| Cloud server import parser | Normalizes imported cloud/server-side data for correlation with local artifacts. |
| Image analysis helpers | Provide image-oriented helper analysis for supported visual workflows. |
| Shortcut support helpers | Provide shortcut parsing and enrichment helpers used by LNK-related workflows. |
| Taskband parser | Parses taskbar/taskband-style registry data and feature usage context. |
| Prefetch hash lookup | Supports Prefetch path/hash enrichment and normalized Prefetch item handling. |
| Xpress Huffman support | Provides decompression support used by Windows compressed-data workflows. |

## Normalization and Import

| Component | Purpose |
| --- | --- |
| Normalized row builders | Map parser output into Perceptor's common artifact schemas. |
| Tool output ingest | Imports generated parser output into the case database, DuckDB analytics tables, and content indexing pipeline. |
| Report bundle import | Detects report bundle formats, including external tool exports and live-case ZIP structures, then routes files to the relevant parser or import path. |

## Notes

- The names above are Perceptor parser names or source modules, not always
  examiner-facing report names.
- Some parsers call external tools for a specific extraction step but still use
  Perceptor's internal normalization and correlation code.
- Large readable content is indexed in OpenSearch. DuckDB stores structured
  metadata, hashes, source references, and report-ready fields.
