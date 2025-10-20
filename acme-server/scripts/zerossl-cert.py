#!/usr/bin/env python3
"""
ZeroSSL Certificate Manager for IP addresses using REST API
"""

import os
import sys
import time
import json
import requests
from pathlib import Path
from datetime import datetime

class ZeroSSLManager:
    def __init__(self):
        self.api_key = os.getenv('ZEROSSL_API_KEY')
        self.public_ip = os.getenv('PUBLIC_IP')
        self.base_url = 'https://api.zerossl.com'
        self.cert_dir = Path(f'/certs/{self.public_ip}')
        self.webroot = Path('/var/www/acme-challenge')
        
        if not self.api_key:
            raise ValueError("ZEROSSL_API_KEY environment variable is required")
        if not self.public_ip:
            raise ValueError("PUBLIC_IP environment variable is required")
        
        self.cert_dir.mkdir(parents=True, exist_ok=True)
        self.webroot.mkdir(parents=True, exist_ok=True)

    def log(self, message):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp}] {message}", flush=True)

    def make_request(self, method, endpoint, data=None):
        """Make API request to ZeroSSL"""
        url = f"{self.base_url}/{endpoint}"
        params = {'access_key': self.api_key}
        
        try:
            if method == 'GET':
                response = requests.get(url, params=params, timeout=30)
            elif method == 'POST':
                response = requests.post(url, params=params, data=data, timeout=30)
            else:
                raise ValueError(f"Unsupported method: {method}")
            
            result = response.json()
            
            if response.status_code >= 400:
                self.log(f"API Error ({response.status_code}): {result}")
                raise Exception(f"API Error: {result.get('error', result)}")
            
            return result
            
        except requests.exceptions.RequestException as e:
            self.log(f"API request failed: {e}")
            raise

    def generate_csr(self):
        """Generate CSR using cryptography library"""
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        import ipaddress
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )
        
        # Parse IP address
        ip_addr = ipaddress.ip_address(self.public_ip)
        
        # Create CSR
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.public_ip),
        ])).add_extension(
            x509.SubjectAlternativeName([
                x509.IPAddress(ip_addr)
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())
        
        # Serialize to PEM
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        return csr_pem, private_key_pem

    def create_certificate(self):
        """Create a new certificate"""
        self.log(f"Generating CSR for IP: {self.public_ip}")
        csr, private_key = self.generate_csr()
        
        # Save private key
        key_file = self.cert_dir / 'privkey.pem'
        key_file.write_text(private_key)
        key_file.chmod(0o600)
        self.log(f"✓ Private key saved to {key_file}")
        
        # Create certificate
        self.log("Creating certificate via ZeroSSL API...")
        
        data = {
            'certificate_domains': self.public_ip,
            'certificate_validity_days': '90',
            'certificate_csr': csr
        }
        
        result = self.make_request('POST', 'certificates', data=data)
        
        # Check if result contains error
        if 'success' in result and not result['success']:
            error_msg = result.get('error', {}).get('type', 'Unknown error')
            raise Exception(f"Certificate creation failed: {error_msg}")
        
        if 'id' not in result:
            raise Exception(f"Unexpected API response: {result}")
        
        cert_id = result['id']
        self.log(f"✓ Certificate created with ID: {cert_id}")
        
        # Save certificate ID
        (self.cert_dir / 'cert_id.txt').write_text(cert_id)
        
        return cert_id, result

    def verify_domain(self, cert_id, validation_data):
        """Complete HTTP validation"""
        self.log("Setting up HTTP validation...")
        
        # Get validation details
        validation = validation_data.get('validation', {})
        other_methods = validation.get('other_methods', {})
        
        if self.public_ip not in other_methods:
            self.log(f"Available validation methods: {list(other_methods.keys())}")
            raise Exception(f"No validation method found for IP: {self.public_ip}")
        
        http_validation = other_methods[self.public_ip]
        
        # ZeroSSL può usare sia acme-challenge che pki-validation
        file_validation_url = http_validation.get('file_validation_url_http', '')
        
        # Estrai il nome del file dall'URL
        filename = file_validation_url.split('/')[-1]
        content = http_validation['file_validation_content']
        
        # Content is a list of strings
        if isinstance(content, list):
            file_content = '\n'.join(content)
        else:
            file_content = str(content)
        
        # Create validation file
        validation_file = self.webroot / filename
        validation_file.write_text(file_content)
        validation_file.chmod(0o644)
        
        self.log(f"✓ Validation file created: {filename}")
        self.log(f"  URL: {file_validation_url}")
        self.log(f"  Local path: {validation_file}")
        self.log(f"  Content length: {len(file_content)} bytes")
        
        # Verify file locally
        if validation_file.exists():
            local_content = validation_file.read_text()
            self.log(f"✓ File exists, content matches: {local_content == file_content}")
        
        # Test local access
        try:
            import subprocess
            result = subprocess.run(
                ['curl', '-s', f'http://localhost/.well-known/acme-challenge/{filename}'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                self.log(f"✓ File accessible locally via HTTP")
            else:
                self.log(f"✗ File NOT accessible locally: {result.stderr}")
        except Exception as e:
            self.log(f"⚠ Could not test local HTTP access: {e}")
        
        # Wait for file to be available
        time.sleep(3)
        
        # Trigger validation
        self.log("Triggering validation...")
        verify_data = {
            'validation_method': 'HTTP_CSR_HASH'
        }
        
        result = self.make_request('POST', f'certificates/{cert_id}/challenges', data=verify_data)
        self.log(f"✓ Validation triggered")
        
        return True

    def wait_for_validation(self, cert_id, max_attempts=60):
        """Wait for certificate to be validated and issued"""
        self.log("Waiting for certificate validation and issuance...")
        self.log("This may take a few minutes...")
        
        for attempt in range(max_attempts):
            time.sleep(10)
            
            result = self.make_request('GET', f'certificates/{cert_id}')
            status = result.get('status')
            
            self.log(f"[{attempt + 1}/{max_attempts}] Status: {status}")
            
            if status == 'issued':
                self.log("✓ Certificate issued successfully!")
                return result
            elif status == 'cancelled':
                raise Exception("Certificate was cancelled")
            elif status == 'expired':
                raise Exception("Certificate expired")
            elif status == 'draft':
                self.log("  → Validation in progress...")
            elif status == 'pending_validation':
                self.log("  → Waiting for validation...")
        
        raise Exception("Validation timeout - certificate was not issued in time")

    def download_certificate(self, cert_id):
        """Download and save certificate"""
        self.log("Downloading certificate...")
        
        result = self.make_request('GET', f'certificates/{cert_id}/download/return')
        
        if 'certificate.crt' not in result:
            raise Exception("Certificate download failed - unexpected response format")
        
        # Save certificates
        (self.cert_dir / 'cert.pem').write_text(result['certificate.crt'])
        (self.cert_dir / 'chain.pem').write_text(result['ca_bundle.crt'])
        
        # Create fullchain
        fullchain = result['certificate.crt'] + '\n' + result['ca_bundle.crt']
        (self.cert_dir / 'fullchain.pem').write_text(fullchain)
        
        # Set permissions
        for cert_file in self.cert_dir.glob('*.pem'):
            if cert_file.name != 'privkey.pem':
                cert_file.chmod(0o644)
        
        self.log(f"✓ Certificates saved to {self.cert_dir}")
        self.verify_certificate()

    def verify_certificate(self):
        """Verify certificate is valid"""
        cert_file = self.cert_dir / 'fullchain.pem'
        
        import subprocess
        result = subprocess.run(
            ['openssl', 'x509', '-in', str(cert_file), '-noout', '-dates', '-subject'],
            capture_output=True,
            text=True
        )
        
        self.log("Certificate information:")
        for line in result.stdout.strip().split('\n'):
            self.log(f"  {line}")

    def check_certificate_validity(self):
        """Check if certificate exists and is valid"""
        cert_file = self.cert_dir / 'fullchain.pem'
        
        if not cert_file.exists():
            self.log("No existing certificate found")
            return False
        
        try:
            import subprocess
            result = subprocess.run(
                ['openssl', 'x509', '-in', str(cert_file), '-noout', '-checkend', str(30 * 86400)],
                capture_output=True
            )
            
            if result.returncode == 0:
                self.log("✓ Certificate is valid for more than 30 days")
                return True
            else:
                self.log("! Certificate expires in less than 30 days")
                return False
        except Exception as e:
            self.log(f"Error checking certificate: {e}")
            return False

    def issue_certificate(self):
        """Main function to issue certificate"""
        try:
            if self.check_certificate_validity():
                return True
            
            self.log("=" * 60)
            self.log("Starting new certificate issuance")
            self.log("=" * 60)
            
            cert_id, validation_data = self.create_certificate()
            self.verify_domain(cert_id, validation_data)
            self.wait_for_validation(cert_id)
            self.download_certificate(cert_id)
            
            self.log("=" * 60)
            self.log("✓ Certificate issuance completed successfully!")
            self.log("=" * 60)
            return True
            
        except Exception as e:
            self.log("=" * 60)
            self.log(f"✗ Certificate issuance failed: {e}")
            self.log("=" * 60)
            import traceback
            traceback.print_exc()
            return False

    def renew_certificate(self):
        """Renew certificate if needed"""
        self.log("Certificate renewal check...")
        
        if self.check_certificate_validity():
            self.log("Certificate is still valid, no renewal needed")
            return True
        
        return self.issue_certificate()


def main():
    if len(sys.argv) < 2:
        print("Usage: zerossl-cert.py [issue|renew|check]")
        sys.exit(1)
    
    command = sys.argv[1]
    manager = ZeroSSLManager()
    
    if command == 'issue':
        success = manager.issue_certificate()
    elif command == 'renew':
        success = manager.renew_certificate()
    elif command == 'check':
        success = manager.check_certificate_validity()
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()