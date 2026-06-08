# MCP Client Setup

Use stdio when the MCP client runs a command over SSH to the Ubuntu Perceptor host.

## Local Ubuntu Client

Command:

```bash
uv
```

Arguments:

```text
run perceptor --root /path/to/workspace mcp serve
```

Working directory:

```text
/opt/perceptor
```

## Mac GUI Client to Ubuntu Host

Use an SSH command as the stdio launcher.

Command:

```bash
ssh
```

Arguments:

```text
-i ~/.ssh/id_ed25519_relic analyst@UBUNTU_HOST cd /opt/perceptor && uv run perceptor --root /path/to/workspace mcp serve
```

For processing:

```text
-i ~/.ssh/id_ed25519_relic analyst@UBUNTU_HOST cd /opt/perceptor && uv run perceptor --root /path/to/workspace mcp serve --allow-processing
```

Use the private key path, not the `.pub` file. The public key must be installed
in `~/.ssh/authorized_keys` on the Ubuntu host.

## Workspace Scope

The MCP server is rooted to one Perceptor workspace at startup. To use a different
workspace, start another MCP server configuration with a different `--root`.

## Restarting

Restart the MCP server after code changes or after adding new tools. MCP clients
usually cache tool definitions for a running server.
