#!/usr/bin/env bash
set -euo pipefail

echo "Deploying Perceptor via Docker Compose..."

# Generate tokens
if [ ! -f "deploy/.env" ]; then
  echo "Copying deploy/.env.example to deploy/.env..."
  cp deploy/.env.example deploy/.env
  
  ADMIN_TOKEN=$(openssl rand -hex 32)
  sed -i "s/PERCEPTOR_ADMIN_TOKEN=.*/PERCEPTOR_ADMIN_TOKEN=${ADMIN_TOKEN}/g" deploy/.env
  
  OS_PASSWORD=$(openssl rand -hex 16)
  sed -i "s/FORENSIC_OPENSEARCH_PASSWORD=.*/FORENSIC_OPENSEARCH_PASSWORD=${OS_PASSWORD}/g" deploy/.env
  
  echo "Generated new admin token and OpenSearch password."
fi

# Ensure docker is installed
if ! command -v docker &> /dev/null; then
    echo "Docker not found. Installing..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    rm get-docker.sh
fi

# Create directories with proper permissions for containers
sudo mkdir -p /var/lib/perceptor /opt/perceptor-tools /evidence /tmp/perceptor-uploads
sudo chown -R 1000:1000 /var/lib/perceptor /opt/perceptor-tools /evidence /tmp/perceptor-uploads

# Pull images and start
docker compose --env-file deploy/.env pull
docker compose --env-file deploy/.env up -d

echo "Docker compose stack started."
echo "Wait a few seconds, then verify health:"
echo "  curl -sf http://localhost:80/health"
