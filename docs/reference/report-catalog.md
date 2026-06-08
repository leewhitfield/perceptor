# Report Catalog

Run reports with:

```bash
uv run perceptor --root ROOT report REPORT_NAME --case CASE_ID --format table
```

Most reports support `json`, `table`, `csv`, and `md`, but some specialized
reports have narrower options. Use `uv run perceptor report REPORT_NAME --help` for
the exact switches.

This catalog is generated from the current `report --help` command set and
groups all 228 report subcommands by topic.

## Core Case Review

- `summary`
- `dashboard`
- `triage-dashboard`
- `case-review`
- `executive-summary`
- `case-overview`
- `activity-digest`
- `activity-summary`
- `next-actions`
- `runbook`
- `review-status`
- `handoff-package`
- `case-comparison`
- `evidence-gaps`
- `evidence-quality`
- `artifact-summary`
- `artifact-completeness`
- `artifact-processing-status`
- `combined-artifacts`
- `operation-manifest`
- `evidence-extractions`

## Validation, Specs, and Storage

- `validate`
- `validate-outputs`
- `specs`
- `spec`
- `storage-policy`
- `issues`
- `sqlite-inventory`
- `db-storage`
- `regression-smoke`
- `workspace-health`
- `processing-estimate`
- `workspace-map`
- `unmapped-imports`
- `progress`
- `progress-manifests`
- `resume-plan`
- `processing-decisions`
- `processing-readiness`
- `readiness-gate`
- `tool-runs`
- `process-timings`
- `cleanup-candidates`

## Execution and Threat Activity

- `execution`
- `execution-correlation`
- `persistence`
- `autostarts`
- `brute-force`
- `malware-hiding-places`
- `interesting-executables`
- `suspicious-executions`
- `suspicious-timeline-windows`
- `data-exfiltration`
- `account-compromise`
- `bits-activity`
- `examiner-edge-artifacts`
- `program-provenance`
- `cd-burning`
- `prefetch`
- `amcache`
- `shimcache`
- `sdelete`
- `tor-usage`
- `uninstalled-app-artifacts`
- `encrypted-volumes`
- `phone-link`
- `virtualization`

## Accounts, Sessions, and Computers

- `accounts`
- `sessions`
- `session`
- `computer-inventory`
- `users`
- `user-activity`
- `user-timeline`
- `user-intent`

## Filesystems, NTFS, and Recovery

- `mft`
- `filesystem-entries`
- `ntfs-index`
- `ntfs-logfile`
- `ntfs-namespace`
- `non-standard-ads`
- `ntfs-security-descriptors`
- `filesystem-review`
- `user-file-references`
- `user-file-reference-source`
- `recycle`
- `deleted-folders`
- `recovery-coverage`
- `carve-coverage`
- `deep-recovery-status`
- `files`
- `file-names`
- `file-name-drilldown`
- `file-dossier`
- `file-intelligence`
- `file-history`
- `copied-files`
- `copied-file-indicators`
- `copied-file-groups`
- `copied-file-drilldown`
- `copied-usb-files`

## File Metadata and User Documents

- `file-metadata`
- `file-metadata-skipped`
- `file-metadata-unresolved`
- `file-metadata-skipped-deleted`
- `file-metadata-skipped-orphans`
- `file-metadata-folders`
- `file-metadata-summary`
- `office-backstage`
- `office-trust`
- `user-dictionaries`
- `downloaded-files`
- `thumbcache`
- `image-analysis`

## Browser, WebCache, and Windows Activity

- `firefox`
- `browser`
- `browser-artifacts`
- `browser-downloads`
- `browser-cache`
- `browser-hosts`
- `browser-activity`
- `browser-profile-activity`
- `browser-deep-storage`
- `browser-cache-correlations`
- `windows-activities`
- `webcache`
- `webcache-files`

## Cloud Storage

- `cloud-artifacts`
- `cloud-mounts`
- `cloud-removable-overlap`
- `cloud-files`
- `cloud-configuration`
- `web-cloud-correlations`
- `cloud-server-events`
- `opened-from-cloud-storage`

## Email, Messaging, and Communications

- `email-artifacts`
- `mailbox-messages`
- `mailbox-attachments`
- `mailbox-attachment-coverage`
- `mailbox-attachment-copies`
- `mailbox-copies`
- `communications`
- `communication-groups`
- `communication-review`
- `messaging-artifacts`
- `messaging-messages`

## Timeline and Correlation

- `timeline`
- `timeline-sources`
- `timeline-review`
- `derived-timeline-events`
- `event-interpretation`
- `clipboard`
- `artifact-sources`
- `artifact-correlations`
- `correlation-groups`
- `correlation-group`
- `correlations`

## Registry and Shell Artifacts

- `registry`
- `registry-artifacts`
- `registry-activity`
- `shellbags`
- `shellbag-external-storage`
- `taskbar-feature-usage`
- `taskbar-pins`
- `common-dialog-items`
- `shortcuts`
- `shortcut-droid-changes`
- `shortcut-object-tracking`

## USN, SRUM, UAL, and Event Logs

- `evtx`
- `evtx-recovery`
- `telemetry-artifacts`
- `usn`
- `usn-summary`
- `usn-path`
- `usn-user`
- `usn-reasons`
- `usn-timeline`
- `usn-suspicious`
- `usn-user-files`
- `usn-renames`
- `usn-lifecycle`
- `usn-bursts`
- `usn-usb-candidates`
- `srum`
- `srum-networks`
- `srum-app-usage`
- `srum-context`
- `ual`

## Remote Access, RDP, and VPN

- `rdp`
- `rdp-cache`
- `rdp-visual-observations`
- `remote-access`
- `remote-access-attribution`
- `mapped-network-paths`
- `remote-access-tool-logs`
- `vpn-activity`
- `vpn-local-activity`
- `vpn-connections`
- `vpn-config`
- `vpn-execution`
- `vpn-sessions`

## Windows Search

- `windows-search`
- `windows-search-combined`
- `search-index-runs`

## USB and External Storage

- `usb`
- `external-storage`
- `device-inventory`
- `usb-files`
- `usb-timeline`
- `usb-verbose`
- `usb-dossier`
- `opened-from-removable-media`

## Memory

- `memory-artifacts`
- `memory-support-files`
- `memory-analysis`
- `memory-credentials`
- `memory-credential-review`
- `memory-disk-correlations`
- `memory-string-hits`
- `structured-memory`
- `crash-dump-analysis`

## Artifact Search

- `artifact-search`
- `artifact-search-sources`
- `lead-search`
- `rerun-search-packet`
- `changed-search-packets`

## File Movement Identity

- `file-movement-identity`
- `shortcut-droid-changes`
- `shortcut-object-tracking`
- `opened-from-removable-media`
- `opened-from-cloud-storage`

## Export

- `export`
- `write-bundle`
