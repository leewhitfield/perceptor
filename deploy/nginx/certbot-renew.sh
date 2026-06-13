#!/usr/bin/env bash
set -euo pipefail

# This script can be run via cron to renew Let's Encrypt certificates automatically.
# Example cron entry (runs at 3:15 AM every day):
# 15 3 * * * /opt/perceptor/deploy/nginx/certbot-renew.sh >> /var/log/certbot-renew.log 2>&1

docker run --rm \
  -v "perceptor_certs:/etc/letsencrypt" \
  -p 80:80 \
  certbot/certbot renew --quiet

# Reload Nginx to pick up the new certs
docker compose -f /opt/perceptor/docker-compose.yml exec nginx nginx -s reload
