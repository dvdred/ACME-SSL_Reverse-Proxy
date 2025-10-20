#!/bin/bash

echo "=========================================="
echo "Nginx Reload - $(date)"
echo "=========================================="

if nginx -t 2>&1; then
    nginx -s reload
    echo "✓ Nginx reloaded"
else
    echo "✗ Configuration test failed"
    exit 1
fi