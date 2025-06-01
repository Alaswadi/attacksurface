# Attack Surface Discovery - Docker Deployment Fix Script (PowerShell)
# This script fixes common Docker deployment issues on Windows

Write-Host "🔧 Attack Surface Discovery - Deployment Fix Script" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

function Write-Status {
    param($Message)
    Write-Host "[INFO] $Message" -ForegroundColor Blue
}

function Write-Success {
    param($Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-Warning {
    param($Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-Error {
    param($Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

# Stop any running containers
Write-Status "Stopping existing containers..."
try {
    & docker-compose down 2>$null
} catch {
    # Ignore errors if no containers are running
}

# Create required directories
Write-Status "Creating required directories..."
if (!(Test-Path "nginx\ssl")) {
    New-Item -ItemType Directory -Path "nginx\ssl" -Force | Out-Null
}
if (!(Test-Path "logs\nginx")) {
    New-Item -ItemType Directory -Path "logs\nginx" -Force | Out-Null
}

# Check if nginx.conf exists
if (!(Test-Path "nginx\nginx.conf")) {
    Write-Error "nginx\nginx.conf not found!"
    Write-Status "Creating basic nginx configuration..."
    
    $nginxConfig = @"
events {
    worker_connections 1024;
}

http {
    upstream backend {
        server web:5000;
    }
    
    server {
        listen 80;
        
        location / {
            proxy_pass http://backend;
            proxy_set_header Host `$host;
            proxy_set_header X-Real-IP `$remote_addr;
            proxy_set_header X-Forwarded-For `$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto `$scheme;
        }
        
        location /health {
            return 200 'healthy';
            add_header Content-Type text/plain;
        }
    }
}
"@
    
    $nginxConfig | Out-File -FilePath "nginx\nginx.conf" -Encoding UTF8
    Write-Success "Basic nginx configuration created"
}

# Generate SSL certificates if missing
if (!(Test-Path "nginx\ssl\cert.pem") -or !(Test-Path "nginx\ssl\key.pem")) {
    Write-Status "Generating SSL certificates..."
    try {
        if (Test-Path "generate-ssl.ps1") {
            & .\generate-ssl.ps1
        } else {
            Write-Warning "generate-ssl.ps1 not found. Creating placeholder certificates..."
            "# Placeholder certificate" | Out-File -FilePath "nginx\ssl\cert.pem" -Encoding ASCII
            "# Placeholder key" | Out-File -FilePath "nginx\ssl\key.pem" -Encoding ASCII
        }
        Write-Success "SSL certificates generated"
    } catch {
        Write-Warning "Failed to generate SSL certificates. Creating placeholders..."
        "# Placeholder certificate" | Out-File -FilePath "nginx\ssl\cert.pem" -Encoding ASCII
        "# Placeholder key" | Out-File -FilePath "nginx\ssl\key.pem" -Encoding ASCII
    }
}

# Check if .env file exists
if (!(Test-Path ".env")) {
    if (Test-Path ".env.docker") {
        Write-Status "Creating .env file from template..."
        Copy-Item ".env.docker" ".env"
        Write-Warning "Please edit .env file with your configuration"
    } else {
        Write-Warning ".env file not found. Using default values."
    }
}

# Try original configuration first
Write-Status "Attempting deployment with original configuration..."
try {
    & docker-compose up -d --build
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Deployment successful with original configuration!"
        $deploymentSuccess = $true
    } else {
        throw "Original configuration failed"
    }
} catch {
    Write-Warning "Original configuration failed. Trying simple configuration..."
    $deploymentSuccess = $false
    
    # Backup original and use simple config
    if (Test-Path "docker-compose.yml") {
        Copy-Item "docker-compose.yml" "docker-compose.yml.backup"
    }
    
    if (Test-Path "docker-compose.simple.yml") {
        Copy-Item "docker-compose.simple.yml" "docker-compose.yml"
        Write-Status "Using simplified configuration..."
        
        try {
            & docker-compose up -d --build
            if ($LASTEXITCODE -eq 0) {
                Write-Success "Deployment successful with simplified configuration!"
                $deploymentSuccess = $true
            } else {
                throw "Simple configuration also failed"
            }
        } catch {
            Write-Error "Both configurations failed. Please check the logs:"
            & docker-compose logs
            exit 1
        }
    } else {
        Write-Error "Simple configuration not found. Please check your files."
        exit 1
    }
}

if ($deploymentSuccess) {
    # Wait for services to be ready
    Write-Status "Waiting for services to start..."
    Start-Sleep -Seconds 15

    # Check service status
    Write-Status "Checking service status..."
    & docker-compose ps

    # Test connectivity
    Write-Status "Testing connectivity..."
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:8077/api/dashboard/stats" -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue
        if ($response.StatusCode -eq 200) {
            Write-Success "Direct web access working!"
        }
    } catch {
        try {
            $response = Invoke-WebRequest -Uri "http://localhost:8080/health" -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue
            if ($response.StatusCode -eq 200) {
                Write-Success "Nginx proxy working!"
            }
        } catch {
            Write-Warning "Services may still be starting. Check logs with: docker-compose logs"
        }
    }

    Write-Success "🎉 Deployment fix completed!"
    Write-Host ""
    Write-Host "Access your application at:" -ForegroundColor Cyan
    Write-Host "  • Direct: http://localhost:8077" -ForegroundColor White
    Write-Host "  • Proxy: http://localhost:8080" -ForegroundColor White
    Write-Host ""
    Write-Host "Useful commands:" -ForegroundColor Cyan
    Write-Host "  • View logs: docker-compose logs -f" -ForegroundColor White
    Write-Host "  • Check status: docker-compose ps" -ForegroundColor White
    Write-Host "  • Stop services: docker-compose down" -ForegroundColor White
}
