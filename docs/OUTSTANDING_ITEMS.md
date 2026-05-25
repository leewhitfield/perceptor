# Outstanding Development Items

This list captures the project-level work identified for the memory, recovery, reporting, and parallel-processing workflow. Items marked complete have code or report coverage in the application; items marked monitor are operational follow-ups that depend on future evidence images, external tools, or examiner policy.

| # | Item | Status |
|---:|---|---|
| 1 | Serialize same-case DuckDB analytics writes for parallel workers. | Complete |
| 2 | Preserve parallel scan/read work while serializing database mutation. | Complete |
| 3 | Add case-level readiness reporting for mounts, memory, carve, recovery, and parallel state. | Complete |
| 4 | Include readiness output in the standard report bundle. | Complete |
| 5 | Keep deep recovery separate from `windows-full`. | Complete |
| 6 | Add a full Windows deep-recovery profile for analyst-selected exhaustive recovery. | Complete |
| 7 | Keep carve workflows explicit and separate from mounted-image parser profiles. | Complete |
| 8 | Track chunked carve scan ranges even when no candidates are found. | Complete |
| 9 | Track next offsets and coverage for resumable SQLite/ESE carving. | Complete |
| 10 | Inventory staged SQLite carves with table and schema summaries. | Complete |
| 11 | Route recognized carved SQLite databases into artifact importers where supported. | Complete |
| 12 | Route Windows Search SQLite memory carves into dedicated memory-carve tables. | Complete |
| 13 | Add memory-support artifacts to the overall timeline via memory string hits. | Complete |
| 14 | Inventory `pagefile.sys`, `swapfile.sys`, and `hiberfil.sys` from mounted volumes. | Complete |
| 15 | Assess `hiberfil.sys` status without crashing on compressed or unsupported content. | Complete |
| 16 | Scan memory-support files with `bstrings` when available and `strings` fallback otherwise. | Complete |
| 17 | Add crash dump, process dump, and full memory dump discovery to memory reports. | Complete |
| 18 | Distinguish process dumps from crash dumps in memory artifact reporting. | Complete |
| 19 | Scan crash/process dumps through the memory string workflow. | Complete |
| 20 | Correlate crash dumps to WER context where available. | Complete |
| 21 | Produce combined memory/disk correlation reports. | Complete |
| 22 | Produce combined artifact family reports across disk and memory-backed evidence. | Complete |
| 23 | Produce combined Windows Search reports containing disk and memory carve artifacts. | Complete |
| 24 | Add processing decision reports for failed, partial, unprocessed, and credential-review states. | Complete |
| 25 | Report recovery guardrails and partial-limited extraction results. | Complete |
| 26 | Prefer mounted-volume extraction and require explicit opt-in for broad recursive TSK fallback. | Complete |
| 27 | Record profile worker requests and effective parallel scope in process timings. | Complete |
| 28 | Surface source scopes such as live, Windows.old, memory, pagefile, hiberfil, swapfile, and crash dump in reports. | Complete |
| 29 | Keep file-content and content-heavy storage policy explicit. | Complete |
| 30 | Continue validating external decompressor availability for compressed hiberfil payloads per workstation. | Monitor |

