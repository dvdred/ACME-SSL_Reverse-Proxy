#!/bin/bash
set -e

echo "=========================================="
echo "ACME Server - ZeroSSL Certificate Manager"
echo "=========================================="
echo "Public IP: ${PUBLIC_IP}"
echo "API Key: ${ZEROSSL_API_KEY:0:10}..."
echo ""

# Verifica variabili obbligatorie
if [ -z "$PUBLIC_IP" ]; then
    echo "ERROR: PUBLIC_IP environment variable is required"
    exit 1
fi

if [ -z "$ZEROSSL_API_KEY" ]; then
    echo "ERROR: ZEROSSL_API_KEY environment variable is required"
    echo "Get your API key from: https://app.zerossl.com/developer"
    exit 1
fi

# Avvia nginx per servire le challenge
echo "Starting nginx for ACME challenges..."
nginx -t && nginx || {
    echo "ERROR: Failed to start nginx"
    exit 1
}

echo "✓ Nginx started on port 80"
echo ""

# Test che nginx risponda
sleep 2
curl -s http://localhost/health > /dev/null && echo "✓ Nginx health check passed" || echo "✗ Nginx health check failed"
echo ""

# Lista certificati esistenti
echo "Current certificates in account:"
python3 /scripts/manage-certs.py list || echo "Could not list certificates"
echo ""

# Auto-cleanup se abilitato
if [ "$AUTO_CLEANUP_CERTS" = "true" ]; then
    echo "Auto-cleanup enabled, removing old certificates..."
    python3 /scripts/manage-certs.py cleanup
    echo ""
fi

# Emetti certificato all'avvio
echo "Starting certificate issuance..."
python3 /scripts/zerossl-cert.py issue || {
    EXIT_CODE=$?
    echo ""
    echo "WARNING: Certificate issuance failed"
    
    if [ $EXIT_CODE -eq 1 ]; then
        echo ""
        echo "Troubleshooting:"
        echo "  1. Check that port 80 is accessible from internet"
        echo "  2. Verify firewall allows incoming connections on port 80"
        echo "  3. Check certificate limit: docker exec acme-server python3 /scripts/manage-certs.py list"
        echo "  4. Cleanup old certs: docker exec acme-server python3 /scripts/manage-certs.py cleanup"
        echo ""
    fi
    
    echo "The system will retry during scheduled renewal at 3:00 AM daily"
    echo ""
}

echo ""
echo "=========================================="
echo "Starting cron daemon for automatic renewal"
echo "Renewal schedule: Daily at 3:00 AM"
echo "=========================================="
echo ""

# Avvia cron in foreground (sintassi corretta per Alpine)
exec crond -f