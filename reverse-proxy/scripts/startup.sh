#!/bin/bash
set -e

echo "=========================================="
echo "Reverse Proxy - Starting"
echo "=========================================="

envsubst '$$PUBLIC_IP $$BACKEND1_HOST $$BACKEND1_PORT' < /etc/nginx/templates/default.conf.template > /etc/nginx/conf.d/default.conf

CERT_DIR="/etc/nginx/certs/${PUBLIC_IP}"

# Aspetta che i certificati siano disponibili
echo "Waiting for SSL certificates..."
for i in {1..60}; do
    if [ -f "${CERT_DIR}/fullchain.pem" ] && [ -f "${CERT_DIR}/privkey.pem" ]; then
        echo "✓ Certificates found"
        break
    fi
    
    if [ $i -eq 60 ]; then
        echo "✗ Certificates not found after 60 seconds"
        echo "Creating temporary self-signed certificate..."
        
        mkdir -p "${CERT_DIR}"
        openssl req -x509 -nodes -days 1 -newkey rsa:2048 \
            -keyout "${CERT_DIR}/privkey.pem" \
            -out "${CERT_DIR}/fullchain.pem" \
            -subj "/CN=${PUBLIC_IP}" 2>/dev/null
    fi
    
    echo "  Waiting... ($i/60)"
    sleep 1
done

# Verifica certificato
openssl x509 -in "${CERT_DIR}/fullchain.pem" -noout -dates

echo ""
echo "Testing configuration..."
nginx -t

echo ""
echo "Starting cron..."
crond

echo ""
echo "=========================================="
echo "Starting nginx on port 443 (HTTPS)"
echo "=========================================="
echo ""

exec nginx -g 'daemon off;'