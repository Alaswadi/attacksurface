# Generate SSL certificates for Attack Surface Discovery
# PowerShell script for Windows

Write-Host "Generating SSL certificates for Attack Surface Discovery..." -ForegroundColor Green

# Create SSL directory if it doesn't exist
if (!(Test-Path "nginx\ssl")) {
    New-Item -ItemType Directory -Path "nginx\ssl" -Force
}

# Check if OpenSSL is available
try {
    $null = Get-Command openssl -ErrorAction Stop
    Write-Host "OpenSSL found, generating certificates..." -ForegroundColor Yellow
    
    # Generate private key
    & openssl genrsa -out nginx\ssl\key.pem 2048
    
    # Generate certificate signing request
    & openssl req -new -key nginx\ssl\key.pem -out nginx\ssl\cert.csr -subj "/C=US/ST=State/L=City/O=Organization/OU=OrgUnit/CN=localhost"
    
    # Generate self-signed certificate
    & openssl x509 -req -days 365 -in nginx\ssl\cert.csr -signkey nginx\ssl\key.pem -out nginx\ssl\cert.pem
    
    # Remove CSR file
    Remove-Item nginx\ssl\cert.csr -Force
    
    Write-Host "SSL certificates generated successfully!" -ForegroundColor Green
    Write-Host "Certificate: nginx\ssl\cert.pem" -ForegroundColor Cyan
    Write-Host "Private Key: nginx\ssl\key.pem" -ForegroundColor Cyan
    
} catch {
    Write-Host "OpenSSL not found. Creating placeholder certificates..." -ForegroundColor Yellow
    Write-Host "Please install OpenSSL or manually create SSL certificates." -ForegroundColor Red
    
    # Create placeholder files
    "# Placeholder certificate file" | Out-File -FilePath "nginx\ssl\cert.pem" -Encoding ASCII
    "# Placeholder key file" | Out-File -FilePath "nginx\ssl\key.pem" -Encoding ASCII
    
    Write-Host "Placeholder files created. Replace with real certificates before deployment." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Note: These are self-signed certificates for development use only." -ForegroundColor Yellow
Write-Host "For production, replace with certificates from a trusted CA." -ForegroundColor Yellow
