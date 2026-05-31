# MCP Tool Reference

Use `relic_mcp_tool_reference` for the live tool list exposed by the running
server.

## Routing and Discovery

- `relic_route_question`
- `relic_mcp_workflow_guide`
- `relic_workspace_map`
- `relic_case_evidence_map`
- `relic_case_readiness`
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

## Artifact Queries

- `relic_query_evidence_contents`
- `relic_query_filesystem_listings`
- `relic_search_artifacts`
- `relic_lead_search`
- `relic_artifact_search_sources`
- `relic_file_dossier`
- `relic_usb_dossier`
- `relic_user_activity`
- `relic_query_suspicious_executions`
- `relic_query_external_storage`
- `relic_query_usb_files`
- `relic_query_file_movement_identity`
- `relic_query_opened_from_removable_media`
- `relic_query_opened_from_cloud_storage`
- `relic_query_cloud_artifacts`
- `relic_query_memory_artifacts`
- `relic_query_browser_activity`
- `relic_query_registry_activity`
- `relic_query_shortcuts`
- `relic_query_communications`

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
