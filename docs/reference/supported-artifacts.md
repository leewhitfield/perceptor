# Supported Artifacts

Perceptor normalizes artifact output into SQLite/DuckDB tables and indexes large
searchable content in OpenSearch. UTC is the default and authoritative timestamp
basis. Local timezone display is optional and display-only.

For implementation details, see [Custom Parsers](custom-parsers.md) and
[Third-Party Tools](third-party-tools.md).

## Filesystem and NTFS

- NTFS `$MFT`, USN Journal, `$LogFile`, `$I30`, namespace reconciliation.
- Mounted FAT and exFAT directory listings for removable volumes without `$MFT`.
- File metadata, file listings, deleted-folder indicators, deleted-file recovery
  candidates, archive inventory, nested evidence inventory.
- Zone.Identifier alternate data streams and non-standard ADS leads from MFT
  stream rows.
- `$Secure` security descriptor stream presence (`$SDS`, `$SII`, `$SDH`) from
  MFT ADS rows. Structured ACL decoding is a future parser item; current output
  is presence/metadata-only.

Primary reports include `files`, `filesystem-entries`, `filesystem-review`,
`file-history`, `file-dossier`, `ntfs-*`, `usn-*`, `deleted-folders`,
`non-standard-ads`, `ntfs-security-descriptors`, `recovery-coverage`,
`nested-evidence`, and `evidence-extractions`.

## Execution and Program Presence

- Prefetch, Amcache, Shimcache/AppCompatCache.
- BAM/DAM, UserAssist, RecentApps, RunMRU, LastVisitedPidlMRU.
- SRUM application usage and network usage context.
- Services, scheduled-task creation events, process creation event logs when
  command-line auditing exists.
- Interesting executables and suspicious execution correlation.

Primary reports include `execution`, `execution-correlation`, `prefetch`,
`amcache`, `shimcache`, `program-provenance`, `suspicious-executions`,
`software-footprint-review`, `interesting-executables`, `srum-context`, and
`event-interpretation`.

## User Activity and File References

- LNK shortcuts, Jump Lists, RecentDocs, Office MRU/backstage, TrustedDocs.
- Shellbags, Common Dialog MRU, TypedPaths, WordWheel queries.
- Shortcut DROID/object ID tracking and movement identity.
- Windows Activities/Timeline database and clipboard history.

Primary reports include `shortcuts`, `jumplists`, `shellbags`,
`office-backstage`, `office-trust`, `common-dialog-items`, `windows-activities`,
`clipboard`, `file-movement-identity`, `shortcut-droid-changes`,
`shortcut-object-tracking`, `opened-from-removable-media`, and
`opened-from-cloud-storage`.

## Examiner Edge Artifacts

- Sticky Notes `plum.sqlite` content and timestamps where present.
- Windows notification database rows and decoded notification text where
  available.
- Scheduled Task XML definitions under `Windows/System32/Tasks`.
- Hosts file mappings and modification time.
- CryptnetUrlCache metadata and cached URL/string indicators.
- Credential Manager and Windows Vault file metadata. Perceptor records presence,
  size, and timestamps; decrypted credential contents require DPAPI context.
- WSL `ext4.vhdx` presence/size and WSL shell-history files where present.
- Windows Update registry context and `DataStore.edb` presence metadata.
- Bluetooth paired-device registry rows.
- Installed application registry rows.
- SwiftKey/InputPersonalization settings and stored string fragments where
  present. Treat fragments as leads until corroborated.

Primary report: `examiner-edge-artifacts`.

## Browser and Web

- Chromium and Firefox history, downloads, cookies, cache, sessions, autofill,
  site settings, notifications, and profile activity.
- Browser cache URL/content indicators.
- Browser/cloud overlap and web-cloud correlations.

Primary reports include `browser`, `browser-history`, `browser-downloads`,
`browser-cache`, `browser-artifacts`, `browser-hosts`,
`browser-profile-activity`, `browser-deep-storage`, and
`web-cloud-correlations`.

## Communications, Mail, and Documents

- PST, OST, MSG, EML, MBOX, Windows Mail, mailbox attachments.
- Messaging/chat/application stores where supported.
- Indexed document/email/message bodies through OpenSearch references.
- Google Takeout Drive and Mail imports.

Primary reports include `email-artifacts`, `mailbox-messages`,
`mailbox-attachments`, `mailbox-attachment-coverage`,
`mailbox-attachment-copies`, `messaging-*`, `communications`,
`communication-review`, `cloud-server-events`, and `cloud-files`.

## Cloud Storage

- OneDrive configuration, ODL logs, OneDrive item metadata.
- Google Drive cache/Takeout, Dropbox, iCloud, browser cloud references.
- Cloud/removable overlap and cloud virtual mount detection.

Primary reports include `cloud-configuration`, `cloud-artifacts`,
`cloud-files`, `onedrive-*`, `cloud-mounts`, `cloud-removable-overlap`,
`opened-from-cloud-storage`, and `web-cloud-correlations`.

## USB and Devices

- USBSTOR, UASP/SCSI, WPDBUSENUM, HID/SWD, MountedDevices, MountPoints2.
- SetupAPI device install events, DeviceMigration, partition diagnostics.
- USB adapter/caddy summaries and distinct media instances behind the adapter.
- USB file/folder correlations from LNK, Jump Lists, Shellbags, MFT, and USN.
- Device inventory for storage and non-storage device classes.

Primary reports include `external-storage`, `usb`, `usb-files`,
`usb-timeline`, `usb-dossier`, `usb-verbose`, `device-inventory`,
`copied-usb-files`, and `copied-file-drilldown`.

## Event Logs and Network

- EVTX event rows from parsed logs.
- High-value interpretation for account manipulation, audit log clearing,
  PowerShell, scheduled tasks, WMI activity, print service, service installs,
  process creation, RDP/logon context.
- Wi-Fi/WLAN sessions, NetworkList registry context, SRUM network context.
- NetworkList registry profiles/signatures, outbound RDP client history, and
  MountPoints2 network-share/volume references.
- BITS qmgr database rows and BITS event-log correlation.

Primary reports include `evtx`, `event-interpretation`, `wifi-activity`,
`remote-access`, `remote-access-attribution`, `mapped-network-paths`, `rdp`,
`bits-activity`, `srum-networks`, `network-activity`, and
`examiner-edge-artifacts`.

## Memory and Support Files

- Full memory images and process/crash dumps through string scanning.
- Structured full-memory attempts through Volatility and MemProcFS, including
  process, command-line, network, module, handle, file-object, and suspicious
  memory-region views when the tool can resolve the image.
- Pagefile, hiberfil, swapfile, crash dumps, and memory-adjacent support files.
  Hiberfil processing reports whether decompressed structured-memory output is
  available, scanned only, failed gracefully, or not processed.
- Memory/disk correlations, memory credentials, Windows Search memory carves.

Primary reports include `memory-artifacts`, `memory-support-files`,
`memory-string-hits`, `memory-credentials`, `memory-disk-correlations`,
`structured-memory`, `memory-analysis`, `crash-dump-analysis`, and
`windows-search-combined`.

## Windows Search

- Windows Search ESE database where readable.
- Windows Search gather logs.
- Windows Search memory carves and indexed-content references.
- OpenSearch indexes extracted bodies/content from supported parser outputs.

Primary reports include `windows-search`, `windows-search-combined`,
`search-index-runs`, `search-content`, and `indexed-content`.

## Persistence, Anti-Forensics, and Other Windows Artifacts

- Run keys, services, scheduled tasks, startup folders, WMI event-log indicators.
- Defender, WER, RDP bitmap cache, thumbcache, legacy `Thumbs.db`, recycle bin,
  telemetry, EventTranscript.db, TokenBroker cache metadata, virtualization,
  Phone Link, package caches, CD/DVD burning indicators.
- SDelete/evidence destruction and timestamp anomaly indicators.

Primary reports include `autostarts`, `persistence`, `malware-hiding-places`,
`windows-defender`, `windows-error-reporting`, `rdp-cache`,
`rdp-visual-observations`, `thumbcache`, `recycle`, `telemetry-artifacts`,
`virtualization`, `phone-link`, `package-artifacts`, `package-cache`,
`examiner-edge-artifacts`, `non-standard-ads`, `ntfs-security-descriptors`,
`remote-access-tool-logs`,
`cd-burning`, `sdelete`, and `timestamp-anomalies`.

## Search Coverage

Use both search layers:

- `report artifact-search`: searches parsed artifact fields such as file paths,
  shortcut targets, browser URLs, registry values, usernames, device IDs, and
  event-log text.
- `search query` / MCP `perceptor_search_content`: searches OpenSearch indexed
  content such as email bodies, attachment text, document text, messaging text,
  selected temporary Office content, and imported Takeout content.

Search output is limited by the requested `--limit`. A limit warning means the
result is a preview, not evidence that no additional rows exist.
