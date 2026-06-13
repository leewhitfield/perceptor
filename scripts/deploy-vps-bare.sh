#!/usr/bin/env bash
set -euo pipefail

echo "Deploying Perceptor bare-metal..."

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)." 
   exit 1
fi

# 1. Create user
if ! id "perceptor" &>/dev/null; then
    useradd -m -r -s /bin/bash perceptor
    echo "Created perceptor user."
fi

mkdir -p /var/lib/perceptor /opt/perceptor-tools /evidence /tmp/perceptor-uploads
chown -R perceptor:perceptor /var/lib/perceptor /opt/perceptor-tools /evidence /tmp/perceptor-uploads

# 2. Install system dependencies (similar to bootstrap)
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    curl git python3 python3-venv python3-dev build-essential \
    pkg-config libleveldb-dev sleuthkit ewf-tools qemu-utils ntfs-3g cryptsetup util-linux \
    libesedb-utils exiftool poppler-utils tesseract-ocr \
    libfsntfs-utils python3-libfsntfs libvshadow-utils dislocker libbde-utils nginx rsync

# 3. Install OpenSearch if not present (simplified for script, usually requires apt repository)
# Assuming it is installed or will be configured manually if omitted here for brevity.

# 4. Environment and Auth
mkdir -p /etc/perceptor
if [ ! -f "/etc/perceptor/perceptor.env" ]; then
    cp deploy/.env.example /etc/perceptor/perceptor.env
    
    ADMIN_TOKEN=$(openssl rand -hex 32)
    sed -i "s/PERCEPTOR_ADMIN_TOKEN=.*/PERCEPTOR_ADMIN_TOKEN=${ADMIN_TOKEN}/g" /etc/perceptor/perceptor.env
    
    echo "Generated admin token in /etc/perceptor/perceptor.env"
fi

# 5. Systemd setup
cp deploy/systemd/perceptor-mcp.service /etc/systemd/system/
cp deploy/systemd/perceptor-upload.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable perceptor-mcp perceptor-upload
systemctl restart perceptor-mcp perceptor-upload

# 6. Nginx setup
cp deploy/nginx/perceptor.conf /etc/nginx/sites-available/
ln -sf /etc/nginx/sites-available/perceptor.conf /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
systemctl restart nginx

echo "Bare-metal deployment configured."
echo "Check status with: systemctl status perceptor-mcp perceptor-upload nginx"
