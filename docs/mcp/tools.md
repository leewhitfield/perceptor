# MCP Tool Reference

Use `perceptor_mcp_tool_reference` for the live tool list exposed by the running
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

- `perceptor_route_question`
- `perceptor_mcp_workflow_guide`
- `perceptor_mcp_tool_reference`
- `perceptor_workspace_summary`
- `perceptor_workspace_map`
- `perceptor_workspace_health`
- `perceptor_case_evidence_map`
- `perceptor_case_readiness`
- `perceptor_list_cases`
- `perceptor_list_computers`
- `perceptor_list_images`
- `perceptor_list_jobs`
- `perceptor_get_job`
- `perceptor_processing_progress`
- `perceptor_resume_plan`
- `perceptor_profile_preview`
- `perceptor_doctor`
- `perceptor_discover_reports`
- `perceptor_discover_report_exports`
- `perceptor_read_existing_report`

## Case Review

- `perceptor_case_dashboard`
- `perceptor_case_review`
- `perceptor_case_activity_digest`
- `perceptor_case_next_actions`
- `perceptor_case_runbook`
- `perceptor_timeline`
- `perceptor_timeline_window`
- `perceptor_activity_windows`

## Artifact Queries

- `perceptor_query_evidence_contents`
- `perceptor_query_filesystem_listings`
- `perceptor_search_artifacts`
- `perceptor_search_content`
- `perceptor_get_indexed_content`
- `perceptor_lead_search`
- `perceptor_artifact_search_sources`
- `perceptor_file_dossier`
- `perceptor_usb_dossier`
- `perceptor_user_activity`
- `perceptor_query_suspicious_executions`
- `perceptor_query_external_storage`
- `perceptor_query_usb_files`
- `perceptor_query_usb_contents`
- `perceptor_query_file_movement_identity`
- `perceptor_query_opened_from_removable_media`
- `perceptor_query_opened_from_cloud_storage`
- `perceptor_query_cloud_artifacts`
- `perceptor_query_memory_artifacts`
- `perceptor_query_browser_activity`
- `perceptor_query_registry_activity`
- `perceptor_query_shortcuts`
- `perceptor_query_communications`
- `perceptor_query_system_users`

## Packets and Jobs

- `perceptor_write_review_packet`
- `perceptor_list_review_packets`
- `perceptor_read_review_packet`
- `perceptor_write_search_packet`
- `perceptor_list_search_packets`
- `perceptor_read_search_packet`
- `perceptor_rerun_search_packet`
- `perceptor_list_mcp_jobs`
- `perceptor_get_mcp_job`
- `perceptor_get_mcp_job_output`
- `perceptor_get_mcp_job_progress`
- `perceptor_list_progress_manifests`
- `perceptor_cancel_mcp_job`

## Gated Processing

These require `--allow-processing`:

- `perceptor_import_triage_zip`
- `perceptor_import_report_bundle`
- `perceptor_process_image`
- `perceptor_run_profile`
- `perceptor_recover_deleted_files`

`perceptor_recover_deleted_files` starts a tracked MCP job. The job record stores the
Perceptor CLI command, and the recovery output manifest stores the exact `icat`
command used for each recovered or failed candidate.

## Reports

- `perceptor_list_report_types`
- `perceptor_generate_report`
- `perceptor_write_report_bundle`
- `perceptor_report_bundle_coverage`
- `perceptor_ingest_triage_zip_preflight`

Use `perceptor_generate_report` with `report_name: "bits-activity"` for BITS,
qmgr, OneDrive updater, component updater, or transfer-job questions. The report
uses timestamped BITS Client EVTX rows and shows qmgr database/carved
correlations when exact job ID or URL matches are available.

Use `perceptor_generate_report` with `report_name: "examiner-edge-artifacts"` for
Sticky Notes, Windows notifications, NetworkList, outbound RDP history,
MountPoints2, Scheduled Task XML, CryptnetUrlCache, hosts, WSL, Windows Update,
Credential/Vault metadata, Bluetooth paired devices, installed applications, or
SwiftKey/InputPersonalization questions.

Use `perceptor_generate_report` with `report_name: "mapped-network-paths"` for
mapped network drives, UNC shares, or MountPoints2 keys that look like
`##host#share#path`. Perceptor decodes those keys into `\\host\share\path` and
returns the user profile plus first/last observed registry timestamps.

Use `perceptor_generate_report` with `report_name: "non-standard-ads"` for hidden
or alternate data stream questions. This report filters common
`Zone.Identifier` streams and classifies Cloud Files/OneDrive metadata, WOF
compression, SmartScreen, and NTFS metadata streams separately from
high-priority unclassified ADS rows.

Use `perceptor_generate_report` with `report_name: "ntfs-security-descriptors"` for
`$Secure`, `$SDS`, ACL, or NTFS permission-change questions. This report
inventories security descriptor streams from MFT ADS rows and clearly marks that
current output is presence/metadata-only, not decoded ACL content.

Use `perceptor_generate_report` with `report_name: "remote-access-tool-logs"` for
AnyDesk, TeamViewer, LogMeIn, ConnectWise Control, Splashtop, RustDesk, VNC, and
similar remote-support application log questions. Parsed log lines are
categorized into connection, authentication, transfer, and identity/routing
leads when possible.

Use `perceptor_generate_report` with `report_name: "structured-memory"` for
Volatility and MemProcFS structured memory questions. The report returns parsed
rows when available and also lists tool run attempts, failures, and no-row
results so analysts can distinguish "not run" from "run but unsupported for this
dump."

Use `perceptor_generate_report` with `report_name: "event-interpretation"` for
high-value EVTX questions involving account manipulation, log clearing,
PowerShell, scheduled tasks, WMI persistence indicators, print-service history,
service installs, or 4688 process creation.

Use `perceptor_generate_report` with `report_name: "clipboard"` for clipboard
history, copied/pasted content, or cloud clipboard sync questions. The report
uses the dedicated Windows clipboard store where available; Windows Activities
is secondary context.

MCP interactive query tools keep row limits for model usability. Direct
generated-report responses remain bounded, while saved report bundles default to
broader exports. If an MCP response contains `result_limit_warning` or a
generated report contains `limited: true`, read or regenerate the saved export
with a higher limit before making a negative finding.
