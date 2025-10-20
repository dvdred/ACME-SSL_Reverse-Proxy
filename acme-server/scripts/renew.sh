#!/bin/bash
set -e

echo "=========================================="
echo "Certificate Renewal Check - $(date)"
echo "=========================================="

# Verifica nginx
if ! pgrep nginx > /dev/null; then
    echo "WARNING: Nginx not running, restarting..."
    nginx
fi

# Esegui rinnovo
python3 /scripts/zerossl-cert.py renew

echo "=========================================="
echo "Renewal check completed - $(date)"
echo "=========================================="