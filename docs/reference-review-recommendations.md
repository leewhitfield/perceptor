# Reference Review Recommendations

Date: 2026-05-20

Source material reviewed from `/home/lee/reference`, including SANS posters, FOR500 slide decks with speaker notes, registry guides, Shell Link documentation, CD burning notes, command-line references, and sample/reporting material.

No code changes were made as part of this review.

## High-Level Takeaway

The reference material strongly supports moving from artifact lists toward evidence-led reporting.

Instead of only showing "we parsed X artifact", reports should answer questions such as:

- Was this application executed?
- Was this file opened, created, copied, deleted, or transferred?
- Did this activity involve USB, cloud storage, email, browser activity, RDP, VPN, or persistence?
- Which artifact supports that conclusion?
- What are the caveats for that artifact?

The current project already covers many important artifacts, but the material highlights several places where reports should become more source-aware and where some parsers should be deepened.

## Recommended Priorities

## 1. Build an Artifact Coverage Matrix

Create a coverage matrix that maps investigative questions to:

- artifact sources
- parser coverage
- DuckDB tables
- OpenSearch content, where applicable
- report coverage
- confidence/caveats

Suggested categories:

- execution
- file opening / file knowledge
- deletion / wiping
- cloud sync / SharePoint / Teams / OneDrive / Dropbox / Google Drive
- USB and removable device use
- RDP / logon / VPN
- email attachment provenance
- browser and web app activity
- persistence / autostart / scheduled tasks
- malware hiding places

This should become the control document for deciding what `windows-full` covers and what each report can legitimately claim.

## 2. Improve Outlook and Email Handling

Email is one of the biggest areas to improve.

The references emphasize that PST/OST data is not just message body text. Useful fields include:

- message headers
- sender / recipient metadata
- attachment metadata
- conversation threading
- `PR_Conversation_Index`
- `PR_Message_Flags`
- read/unread/replied/forwarded state
- Outlook Secure Temp folder locations

Recommended additions:

- Improve PST/OST attachment provenance.
- Tie email attachments into file history reports.
- Parse Outlook Secure Temp folder registry paths.
- Correlate files found on disk with mailbox attachments where possible.
- Keep body/content in OpenSearch and structured metadata in DuckDB.

Implementation note:

`MailboxParser` now preserves bounded thread/header metadata, including `Thread-Index`/conversation index, thread topic, References, Reply-To, importance/priority, sensitivity, and originating IP where present. Attachments also retain source message conversation fields for provenance. Body and attachment text remain outside DuckDB and are routed through OpenSearch/content references.

## 3. Expand Cloud Storage Context

The registry guides contain useful cloud-storage keys that should be checked against current parser coverage.

Important OneDrive areas:

- `NTUSER\Software\Microsoft\OneDrive\Accounts`
- `Personal`
- `Business1`
- `Tenants`
- `UserFolder`
- `UserEmail`
- `UserCid`
- `LastSignInTime`
- `ClientFirstSignInTimestamp`
- `SPOResourceID`
- `NTUSER\Software\SyncEngines\Providers\OneDrive`
- `MountPoint`
- `UrlNamespace`
- `CID`

Other cloud sources:

- Google DriveFS mount/share data
- Dropbox `SyncRootManager`
- Dropbox `aggregation.dbx`
- Dropbox `sync_history.db`
- iCloud Drive and Photos databases

Reports should clearly identify whether activity relates to:

- local OneDrive
- SharePoint
- Teams
- Google Drive
- Dropbox
- iCloud

Implementation note:

Registry artifact coverage now includes OneDrive account and SyncEngines keys, Google DriveFS, Dropbox SyncRootManager, and iCloud registry context. `report cloud-configuration` exposes these values separately from cloud file/log rows so account, mount, tenant, SharePoint/Teams URL namespace, and sync-root context can be cited directly.

## 4. Treat SRUM as a Major Correlation Source

SRUM is useful for tying together application, network, VPN, and cloud activity.

Important SRUM tables include:

- Network Connectivity Usage
- Network Data Usage
- Application Resource Usage

Recommended report usage:

- Show application network usage near relevant events.
- Show VPN/network names near RDP sessions.
- Show cloud client transfer activity near file events.
- Show application activity windows near execution/file-use events.

Caveat:

SRUM times are often approximate, commonly grouped into hourly or near-hourly windows. Reports should explicitly state that uncertainty.

Implementation note: `report srum-context` now exposes SRUM rows that are most useful as context around VPN, RDP, browser/network and cloud-sync activity. It keeps the SRUM caveat in the report summary so downstream UI/report views can display the uncertainty consistently.

## 5. Preserve Rich Shell Artifact Detail

LNK files, Jump Lists, and ShellBags should not be reduced to only path and timestamp.

Useful LNK fields:

- target path
- target created/modified/accessed timestamps
- source LNK created/modified/accessed timestamps
- drive type
- command-line arguments, working directory, network path, machine name and
  Jump List AppID metadata where available from LECmd/JLECmd
- volume label
- volume serial
- network share
- NetBIOS name
- MAC address
- arguments
- working directory
- MFT entry information

Useful Jump List fields:

- AppID
- AppID description
- DestList version
- MRU order
- target timestamps
- volume data

Useful ShellBag fields:

- first interacted
- last interacted
- has explored
- file system type
- MFT information
- folder path

Important caveat:

ShellBags are evidence of folder interaction, not file opening by themselves. Windows feature updates may also affect ShellBag registry timestamps.

## 6. Add Better Device Dossiers

USB analysis should go beyond `USBSTOR`.

Relevant device categories:

- USB mass storage
- UASP / SCSI storage
- HID devices
- MTP/PTP devices
- Bluetooth devices
- printers
- audio devices
- phones/cameras/media devices

Useful sources:

- `USB`
- `USBSTOR`
- `SCSI`
- `MountedDevices`
- `Windows Portable Devices`
- `MountPoints2`
- `setupapi.dev.log`
- event logs
- LNK volume data
- Jump List volume data
- ShellBag volume data

Recommended report:

Create a device dossier that answers:

- What was connected?
- Which user interacted with it?
- Which drive letter or volume identity was used?
- What files/folders were accessed from it?
- What timestamps support first connect, last connect, last removal, and user interaction?

## 7. Deepen Browser and Web App Parsing

Existing browser parsing appears useful, but the material highlights deeper areas worth checking.

Important sources:

- browser history
- downloads
- cookies
- cache
- bookmarks
- form history
- login databases
- preferences
- site settings
- Local Storage
- Session Storage
- IndexedDB
- Origin Private File System
- LevelDB
- session restore
- browser sync data
- extensions
- Electron/WebView2 app storage
- Tor Browser profile data

Apps likely to use browser-like storage:

- Teams
- Slack
- Discord
- Signal
- Skype
- WhatsApp
- ChatGPT
- Claude
- Codex
- Notion
- Obsidian
- OneNote
- Zoom
- Telegram
- Mattermost
- Viber
- Yammer
- Asana

Policy reminder:

Structured metadata belongs in DuckDB. Body text, message content, note content, AI assistant conversation text, file content, and searchable large text belong in OpenSearch.

## 8. Add CD Burning Detection

The CD burning reference identifies useful Windows burn artifacts.

Important locations/patterns:

- `C:\Users\<user>\AppData\Local\Microsoft\Windows\Burn\Burn`
- `%LocalAppData%\Temp`
- `DAT*.tmp`
- `FIL*.tmp`
- `POST*.tmp`
- `$LogFile`
- `$UsnJrnl`
- `$MFT`

Recommended report:

Create a CD/DVD burning activity report showing:

- staged files
- temp burn artifacts
- filesystem transaction evidence
- relevant user/profile
- timeline of staging and deletion

Implementation note:

`report cd-burning` now provides a first-pass CD/DVD burning activity report from existing MFT, USN Journal, and NTFS `$LogFile` rows.

## 9. Use the Prefetch Hash Lookup as Reference Data

The `prefetch_hashes_lookup.txt` file is useful, but should not be bulk-loaded into case data.

Recommended use:

- optional resolver/reference lookup
- validation corpus for Prefetch parser behavior
- enrichment when a Prefetch filename/hash matches known entries
- expanded reference set for resolving more Prefetch hashes back to likely paths

Avoid:

- importing the whole lookup into every case database
- treating lookup rows as evidence from the image

Additional recommendation:

Look for more public, reliable Prefetch hash/path reference sets and build a local resolver from them. This resolver should be clearly separated from case evidence and should label matches as reference-based enrichment, not as proof that the resolved path existed on the examined system unless the image itself supports it.

Implementation note:

The local resolver now supports `FORENSIC_PREFETCH_HASH_LOOKUP_PATHS` and the FOR500 lookup file path under `/home/lee/reference`. It enriches `prefetch_items` with `resolved_reference_*` fields without importing the lookup as case evidence.

## 10. Keep Server-Side Cloud Logs as Future Imports

The material references cloud/server-side sources such as:

- Microsoft Purview
- Microsoft Unified Audit Logs
- Exchange audit logs
- Recoverable Items
- Google Vault
- Google Workspace logs

These are valuable, but they are not local disk image artifacts.

Recommended approach:

- support them later as separate imports/connectors
- keep them source-labeled
- correlate them with local artifacts after import

## Reporting Recommendations

Reports should include:

- source artifact
- source table or registry key
- parsed value
- normalized path where possible
- original recorded path available in detail views
- timestamp source
- confidence/caveat
- related artifacts

Examples:

- Execution report should distinguish execution evidence from file-existence evidence.
- File history should show whether a file was opened via LNK, Jump List, RecentDocs, Office MRU, Prefetch, browser download, cloud sync, or email attachment.
- RDP reports should show whether a fact came from event logs, SRUM, VPN/network data, RDP cache, registry, or visual interpretation.
- Malware hiding reports should cross-reference autostart locations, scheduled tasks, unusual paths, encoded registry values, and known legitimate parser outputs.

## Specific Caveats to Encode in Reports

- Amcache is not execution evidence by itself.
- ShimCache is not execution evidence by itself.
- ShellBags are folder interaction evidence, not file opening evidence by themselves.
- SRUM timing is approximate.
- UserAssist paths may need GUID resolution to become human-readable.
- Jump List file activity implies application use, but should be reported as file/application interaction rather than pure execution.
- LNK source created/modified timestamps can indicate first/last interaction, but Windows 10+ behavior can complicate interpretation.
- Browser and web app content should be separated from structured metadata.

## Suggested Next Step

Before adding more parsers, create the artifact coverage matrix and compare it against `windows-full`.

After that, recommended implementation order:

1. Email attachment provenance and Outlook/MAPI improvements.
2. Cloud storage registry/report enrichment.
3. SRUM correlation improvements.
4. Device dossier report.
5. Shell artifact detail/drilldown improvements.
6. CD burning activity report.
7. Browser deep storage review.
8. Expanded Prefetch hash resolver/reference set.
