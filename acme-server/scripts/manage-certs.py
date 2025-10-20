#!/usr/bin/env python3
"""
Manage ZeroSSL certificates
"""

import os
import sys
import requests

API_KEY = os.getenv('ZEROSSL_API_KEY')
BASE_URL = 'https://api.zerossl.com'

def make_request(method, endpoint, data=None):
    url = f"{BASE_URL}/{endpoint}"
    params = {'access_key': API_KEY}
    
    try:
        if method == 'GET':
            response = requests.get(url, params=params, timeout=30)
        elif method == 'POST':
            response = requests.post(url, params=params, data=data, timeout=30)
        else:
            raise ValueError(f"Unsupported method: {method}")
        
        return response.json()
    except Exception as e:
        print(f"API Error: {e}")
        sys.exit(1)

def list_certificates():
    print("Fetching certificates...")
    result = make_request('GET', 'certificates')
    
    if 'results' not in result:
        print(f"Error: {result}")
        return
    
    certs = result['results']
    print(f"\nTotal certificates: {result.get('total_count', len(certs))}")
    print("=" * 80)
    
    for cert in certs:
        print(f"ID: {cert.get('id')}")
        print(f"  Domain: {cert.get('common_name', 'N/A')}")
        print(f"  Status: {cert.get('status', 'N/A')}")
        print(f"  Created: {cert.get('created', 'N/A')}")
        print(f"  Expires: {cert.get('expires', 'N/A')}")
        print("-" * 80)

def delete_certificate(cert_id):
    print(f"Deleting certificate {cert_id}...")
    result = make_request('POST', f'certificates/{cert_id}/cancel')
    
    if result.get('success'):
        print(f"✓ Certificate {cert_id} deleted")
    else:
        print(f"✗ Failed: {result}")

def cleanup():
    print("Fetching certificates...")
    result = make_request('GET', 'certificates')
    
    if 'results' not in result:
        print(f"Error: {result}")
        return
    
    deleted = 0
    for cert in result['results']:
        if cert.get('status') in ['draft', 'cancelled', 'expired']:
            cert_id = cert.get('id')
            print(f"Deleting {cert.get('status')} certificate {cert_id}...")
            delete_certificate(cert_id)
            deleted += 1
    
    print(f"\n✓ Deleted {deleted} certificate(s)")

def main():
    if not API_KEY:
        print("Error: ZEROSSL_API_KEY required")
        sys.exit(1)
    
    if len(sys.argv) < 2:
        print("Usage: manage-certs.py [list|delete <id>|cleanup]")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == 'list':
        list_certificates()
    elif command == 'delete' and len(sys.argv) >= 3:
        delete_certificate(sys.argv[2])
    elif command == 'cleanup':
        cleanup()
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)

if __name__ == '__main__':
    main()