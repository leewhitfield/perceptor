#!/usr/bin/env bash
set -euo pipefail

# In a real multi-tenant scenario, rsyncd passes RSYNC_MODULE_NAME, RSYNC_USER_NAME
# RSYNC_REQUEST etc. We can inspect RSYNC_REQUEST to ensure the tenant is uploading
# only into their authorized subdirectory.

# For this MVP, if tenant mode is active, you'd configure per-tenant auth users
# or validate the path here. We'll simply allow it for now and log it.

echo "Rsync transfer initiated: module=${RSYNC_MODULE_NAME} req=${RSYNC_REQUEST}" >> /var/log/rsync-pre-xfer.log
exit 0
