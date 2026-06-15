# Perceptor

![Perceptor Logo](docs/assets/perceptor.png)

Perceptor connects disparate forensic artifacts to provide a more comprehensive view of an investigation. Some relationships between artifacts are obvious. Others are not immediately apparent, especially when there is too much data for an examiner to review one artifact or system at a time.

Perceptor ingests full forensic images, report exports from tools such as Eric Zimmerman's tools, virtual machines, triage collections, and other relevant data sources. Once the data is loaded, Perceptor uses its own algorithms to identify, score, and report links between artifacts so an examiner can understand how different pieces of evidence relate to each other.

Perceptor operates independently and does not require artificial intelligence. It also provides an optional MCP connector. The MCP connector lets an examiner attach an agent of their choice and query multiple artifact families at once, with source-of-truth routing and guardrails intended to keep the agent grounded in generated reports, indexed content, and parsed evidence. The goal is to speed up investigations and help reveal links that may otherwise remain buried.

The full manual can be found here: [Perceptor Manual](https://leewhitfield.github.io/perceptor/)

## Why It Exists

Perceptor exists for two main reasons.

First, many forensic tools have become locked down in ways that can mean higher prices and poorer service for the field.

Second, there is substantial opposition to AI being used in forensics. The MCP interface is an answer to that: it shows what an agent can do when it has the right guardrails, evidence routing, and direction. Give it a try. If it does not impress you, say why. If it does, say that too.

## How It Works

Perceptor leverages existing open-source software, including Eric Zimmerman's tools and Sleuth Kit, together with custom parsers created for this project. That combination is intended to streamline processing, indexing, reporting, and cross-artifact review.

Three databases form the back end:

1. SQLite stores case data, evidence images, data sources, jobs, processing metadata, audit records, and other orchestration state.
2. DuckDB stores extracted and normalized rows from parsed forensic artifacts.
3. OpenSearch stores readable content from files, emails, messages, and other text-bearing sources so it can be searched and tied back to the originating evidence.

## Current Status

This is just the start. Perceptor is not complete and still has some way to go.

Current support boundary:

- Windows analysis only.
- Ubuntu 24.04 LTS x86_64 is the supported runtime target.
- Bare metal or VM is recommended for full processing.
- Native macOS, native Windows, WSL, Docker, ARM64, and non-Ubuntu Linux are not primary support targets for full mounted-image workflows.
- macOS analysis is planned, and Linux analysis should eventually be added.

This is not a validated forensic product yet. Validate behavior, logging, mounts, and tool output handling before using it on real evidence.

## Quick Start

Operator documentation is organized for MkDocs under [`docs/`](docs/). Start with:

- [Documentation Home](docs/index.md)
- [Ubuntu Install](docs/getting-started/ubuntu-install.md)
- [Dependency Management](docs/getting-started/dependencies.md)
- [First Run Checks](docs/getting-started/first-run.md)
- [Command Reference](docs/reference/commands.md)
- [MCP Overview](docs/mcp/overview.md)
- [Supported Artifacts](docs/reference/supported-artifacts.md)

Quick Ubuntu bootstrap from a source checkout:

```bash
scripts/bootstrap-ubuntu.sh
```

Then verify the install:

```bash
uv run perceptor standalone doctor --smoke --format table
```

Perceptor installs the preferred command name and the existing long-form CLI alias:

```bash
perceptor
forensic-orchestrator
```

## MCP

Perceptor can expose a local MCP stdio server for MCP-capable clients:

```bash
uv run perceptor --root /path/to/workspace mcp serve
```

Processing tools require explicit opt-in:

```bash
uv run perceptor --root /path/to/workspace mcp serve --allow-processing
```

See [MCP Overview](docs/mcp/overview.md), [MCP Client Setup](docs/mcp/client-setup.md), and [Source-of-Truth Routing](docs/mcp/source-of-truth.md) for the intended workflow and guardrails.

## Help Wanted

I need help. What is missing? What does not work as well as it should?

Please take it, test it, break it, and come back with findings so I can fix them. Even better, fix them yourself and send a pull request.
