#!/bin/bash

# Generate SSL certificates for Attack Surface Discovery
# This script creates self-signed certificates for development/testing

echo "Generating SSL certificates for Attack Surface Discovery..."

# Create SSL directory if it doesn't exist
mkdir -p nginx/ssl

# Generate private key
openssl genrsa -out nginx/ssl/key.pem 2048

# Generate certificate signing request
openssl req -new -key nginx/ssl/key.pem -out nginx/ssl/cert.csr -subj "/C=US/ST=State/L=City/O=Organization/OU=OrgUnit/CN=localhost"

# Generate self-signed certificate
openssl x509 -req -days 365 -in nginx/ssl/cert.csr -signkey nginx/ssl/key.pem -out nginx/ssl/cert.pem

# Remove CSR file
rm nginx/ssl/cert.csr

# Set proper permissions
chmod 600 nginx/ssl/key.pem
chmod 644 nginx/ssl/cert.pem

echo "SSL certificates generated successfully!"
echo "Certificate: nginx/ssl/cert.pem"
echo "Private Key: nginx/ssl/key.pem"
echo ""
echo "Note: These are self-signed certificates for development use only."
echo "For production, replace with certificates from a trusted CA."
