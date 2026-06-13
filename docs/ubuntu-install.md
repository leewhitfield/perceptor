# Ubuntu Installation Guide

There are two primary ways to install Perceptor on Ubuntu 24.04: Bare-Metal and Docker.

## Docker Installation (Recommended)
Docker isolates Perceptor and its dependencies, avoiding conflicts with your system packages.

1. Clone the repository.
2. Run the deployment script:
   ```bash
   sudo ./scripts/deploy-vps-docker.sh
   ```
3. This will install Docker (if missing), build the `ghcr.io/leewhitfield/perceptor:latest` image, and start the stack (Perceptor MCP, Upload Server, OpenSearch, Nginx).

## Bare-Metal Installation
If you prefer to run Perceptor directly on the host system:

1. Clone the repository.
2. Run the bare-metal deployment script:
   ```bash
   sudo ./scripts/deploy-vps-bare.sh
   ```
3. This script will:
   - Create a `perceptor` service user.
   - Install all system dependencies via `apt-get`.
   - Configure systemd units for the background services.
   - Set up Nginx as a reverse proxy.

## Development Workstation
If you are developing Perceptor locally on Ubuntu 24.04 without deploying it as a server:
```bash
sudo ./scripts/bootstrap-ubuntu.sh
uv sync
```
