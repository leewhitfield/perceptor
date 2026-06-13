# VPS Deployment Guide

Deploying Perceptor to a standard VPS gives you a centralized forensic server accessible via the MCP protocol.

## Prerequisites
- **OS**: Ubuntu 24.04 LTS
- **RAM**: Minimum 8GB (required for OpenSearch + Perceptor in multi-tenant mode)
- **Disk**: 100GB+ SSD recommended (evidence storage scales quickly)

## Option 1: Docker Deployment (Recommended)
This path is the easiest to maintain and isolates dependencies.

1. Clone the repository to `/opt/perceptor`.
2. Run the Docker deployment script:
   ```bash
   sudo ./scripts/deploy-vps-docker.sh
   ```
3. The script will generate tokens in `deploy/.env` and start the Docker Compose stack.
4. Verify deployment:
   ```bash
   curl -sf http://localhost/health
   ```

## Option 2: Bare-Metal Deployment
This path installs Perceptor directly on the Ubuntu host. Useful if you cannot run Docker.

1. Clone the repository to `/opt/perceptor`.
2. Run the bare-metal deployment script:
   ```bash
   sudo ./scripts/deploy-vps-bare.sh
   ```
3. Check the status of systemd services:
   ```bash
   systemctl status perceptor-mcp perceptor-upload nginx
   ```

## Next Steps
- Secure the server with TLS using Let's Encrypt (`certbot`).
- Set up your first tenant (see [Multi-Tenant Operations](../operations/multi-tenant.md)).
- Upload evidence (see [Evidence Upload](../operations/evidence-upload.md)).
