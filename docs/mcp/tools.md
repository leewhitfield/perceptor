# MCP Tool Reference

Use `relic_mcp_tool_reference` for the live tool list exposed by the running
server.

## Result Limits

MCP tools intentionally return bounded result sets. A bounded response is not
evidence of absence.

- `result_limit` means a limit was active.
- `result_limit_warning` means the returned rows reached or appear to have hit a
  limit.
- Increase the tool `limit`, read an existing generated report/export, or ask
  for a dossier/full context before relying on absence.

## Routing and Discovery

- `relic_route_question`
- `relic_mcp_workflow_guide`
- `relic_mcp_tool_reference`
- `relic_workspace_summary`
- `relic_workspace_map`
- `relic_workspace_health`
- `relic_case_evidence_map`
- `relic_case_readiness`
- `relic_list_cases`
- `relic_list_computers`
- `relic_list_images`
- `relic_list_jobs`
- `relic_get_job`
- `relic_processing_progress`
- `relic_resume_plan`
- `relic_profile_preview`
- `relic_doctor`
- `relic_discover_reports`
- `relic_discover_report_exports`
- `relic_read_existing_report`

## Case Review

- `relic_case_dashboard`
- `relic_case_review`
- `relic_case_activity_digest`
- `relic_case_next_actions`
- `relic_case_runbook`
- `relic_timeline`
- `relic_timeline_window`
- `relic_activity_windows`

## Artifact Queries

- `relic_query_evidence_contents`
- `relic_query_filesystem_listings`
- `relic_search_artifacts`
- `relic_search_content`
- `relic_get_indexed_content`
- `relic_lead_search`
- `relic_artifact_search_sources`
- `relic_file_dossier`
- `relic_usb_dossier`
- `relic_user_activity`
- `relic_query_suspicious_executions`
- `relic_query_external_storage`
- `relic_query_usb_files`
- `relic_query_usb_contents`
- `relic_query_file_movement_identity`
- `relic_query_opened_from_removable_media`
- `relic_query_opened_from_cloud_storage`
- `relic_query_cloud_artifacts`
- `relic_query_memory_artifacts`
- `relic_query_browser_activity`
- `relic_query_registry_activity`
- `relic_query_shortcuts`
- `relic_query_communications`
- `relic_query_system_users`

## Packets and Jobs

- `relic_write_review_packet`
- `relic_list_review_packets`
- `relic_read_review_packet`
- `relic_write_search_packet`
- `relic_list_search_packets`
- `relic_read_search_packet`
- `relic_rerun_search_packet`
- `relic_list_mcp_jobs`
- `relic_get_mcp_job`
- `relic_get_mcp_job_output`
- `relic_get_mcp_job_progress`
- `relic_list_progress_manifests`
- `relic_cancel_mcp_job`

## Gated Processing

These require `--allow-processing`:

- `relic_import_triage_zip`
- `relic_import_report_bundle`
- `relic_process_image`
- `relic_run_profile`
- `relic_recover_deleted_files`

`relic_recover_deleted_files` starts a tracked MCP job. The job record stores the
Relic CLI command, and the recovery output manifest stores the exact `icat`
command used for each recovered or failed candidate.

## Reports

- `relic_list_report_types`
- `relic_generate_report`
- `relic_write_report_bundle`
- `relic_report_bundle_coverage`
- `relic_ingest_triage_zip_preflight`

Use `relic_generate_report` with `report_name: "bits-activity"` for BITS,
qmgr, OneDrive updater, component updater, or transfer-job questions. The report
uses timestamped BITS Client EVTX rows and shows qmgr database/carved
correlations when exact job ID or URL matches are available.

Use `relic_generate_report` with `report_name: "examiner-edge-artifacts"` for
Sticky Notes, Windows notifications, NetworkList, outbound RDP history,
MountPoints2, Scheduled Task XML, CryptnetUrlCache, hosts, WSL, Windows Update,
Credential/Vault metadata, Bluetooth paired devices, installed applications, or
SwiftKey/InputPersonalization questions.

Use `relic_generate_report` with `report_name: "mapped-network-paths"` for
mapped network drives, UNC shares, or MountPoints2 keys that look like
`##host#share#path`. Relic decodes those keys into `\\host\share\path` and
returns the user profile plus first/last observed registry timestamps.

Use `relic_generate_report` with `report_name: "non-standard-ads"` for hidden
or alternate data stream questions. This report filters common
`Zone.Identifier` streams and classifies Cloud Files/OneDrive metadata, WOF
compression, SmartScreen, and NTFS metadata streams separately from
high-priority unclassified ADS rows.

Use `relic_generate_report` with `report_name: "ntfs-security-descriptors"` for
`$Secure`, `$SDS`, ACL, or NTFS permission-change questions. This report
inventories security descriptor streams from MFT ADS rows and clearly marks that
current output is presence/metadata-only, not decoded ACL content.

Use `relic_generate_report` with `report_name: "remote-access-tool-logs"` for
AnyDesk, TeamViewer, LogMeIn, ConnectWise Control, Splashtop, RustDesk, VNC, and
similar remote-support application log questions. Parsed log lines are
categorized into connection, authentication, transfer, and identity/routing
leads when possible.

Use `relic_generate_report` with `report_name: "structured-memory"` for
Volatility and MemProcFS structured memory questions. The report returns parsed
rows when available and also lists tool run attempts, failures, and no-row
results so analysts can distinguish "not run" from "run but unsupported for this
dump."

Use `relic_generate_report` with `report_name: "event-interpretation"` for
high-value EVTX questions involving account manipulation, log clearing,
PowerShell, scheduled tasks, WMI persistence indicators, print-service history,
service installs, or 4688 process creation.

Use `relic_generate_report` with `report_name: "clipboard"` for clipboard
history, copied/pasted content, or cloud clipboard sync questions. The report
uses the dedicated Windows clipboard store where available; Windows Activities
is secondary context.

MCP interactive query tools keep row limits for model usability. Direct
generated-report responses remain bounded, while saved report bundles default to
broader exports. If an MCP response contains `result_limit_warning` or a
generated report contains `limited: true`, read or regenerate the saved export
with a higher limit before making a negative finding.
