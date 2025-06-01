# Attack Surface Discovery - Clean Redeploy Script (PowerShell)
# This script stops existing containers and redeploys with new port configuration

Write-Host "🔄 Attack Surface Discovery - Clean Redeploy" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

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

# Stop and remove existing containers
Write-Status "Stopping and removing existing containers..."
try {
    & docker-compose down --remove-orphans 2>$null
} catch {
    # Ignore errors if no containers are running
}

# Remove any containers that might be using the ports
Write-Status "Checking for containers using ports 8088, 8443, 8077..."
$ports = @(8088, 8443, 8077)
foreach ($port in $ports) {
    try {
        $containers = & docker ps --filter "publish=$port" -q 2>$null
        if ($containers) {
            Write-Warning "Found containers using port $port. Stopping..."
            foreach ($container in $containers) {
                & docker stop $container 2>$null
                & docker rm $container 2>$null
            }
        }
    } catch {
        # Continue if command fails
    }
}

# Clean up Docker system
Write-Status "Cleaning up Docker system..."
try {
    & docker system prune -f >$null 2>&1
} catch {
    # Ignore cleanup errors
}

# Check if .env file exists
if (!(Test-Path ".env")) {
    if (Test-Path ".env.docker") {
        Write-Status "Creating .env file from template..."
        Copy-Item ".env.docker" ".env"
        Write-Success ".env file created"
    } else {
        Write-Warning ".env file not found. Using default values."
    }
}

# Ensure required directories exist
Write-Status "Creating required directories..."
if (!(Test-Path "nginx\ssl")) {
    New-Item -ItemType Directory -Path "nginx\ssl" -Force | Out-Null
}
if (!(Test-Path "logs\nginx")) {
    New-Item -ItemType Directory -Path "logs\nginx" -Force | Out-Null
}

# Generate SSL certificates if missing
if (!(Test-Path "nginx\ssl\cert.pem") -or !(Test-Path "nginx\ssl\key.pem")) {
    Write-Status "Generating SSL certificates..."
    if (Test-Path "generate-ssl.ps1") {
        try {
            & .\generate-ssl.ps1 >$null 2>&1
        } catch {
            # Continue if SSL generation fails
        }
    }
}

# Build and start services
Write-Status "Building and starting services with new port configuration..."
Write-Status "Ports: HTTP=8088, HTTPS=8443, Direct=8077"

try {
    & docker-compose up -d --build
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Deployment successful!"
        
        # Wait for services to start
        Write-Status "Waiting for services to start..."
        Start-Sleep -Seconds 15
        
        # Check service status
        Write-Status "Service status:"
        & docker-compose ps
        
        # Test connectivity
        Write-Status "Testing connectivity..."
        try {
            $response = Invoke-WebRequest -Uri "http://localhost:8077/api/dashboard/stats" -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue
            if ($response.StatusCode -eq 200) {
                Write-Success "✅ Direct web access working on port 8077"
            }
        } catch {
            Write-Warning "⚠️  Direct web access not responding yet"
        }
        
        try {
            $response = Invoke-WebRequest -Uri "http://localhost:8088/health" -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue
            if ($response.StatusCode -eq 200) {
                Write-Success "✅ Nginx proxy working on port 8088"
            }
        } catch {
            Write-Warning "⚠️  Nginx proxy not responding yet"
        }
        
        Write-Host ""
        Write-Success "🎉 Redeployment completed!"
        Write-Host ""
        Write-Host "Access your application at:" -ForegroundColor Cyan
        Write-Host "  • HTTPS: https://localhost:8443" -ForegroundColor White
        Write-Host "  • HTTP:  http://localhost:8088 (redirects to HTTPS)" -ForegroundColor White
        Write-Host "  • Direct: http://localhost:8077" -ForegroundColor White
        Write-Host ""
        Write-Host "Default credentials:" -ForegroundColor Cyan
        Write-Host "  • Username: admin" -ForegroundColor White
        Write-Host "  • Password: password" -ForegroundColor White
        Write-Host ""
        Write-Host "Useful commands:" -ForegroundColor Cyan
        Write-Host "  • View logs: docker-compose logs -f" -ForegroundColor White
        Write-Host "  • Check status: docker-compose ps" -ForegroundColor White
        Write-Host "  • Stop services: docker-compose down" -ForegroundColor White
        
    } else {
        throw "Docker compose failed"
    }
} catch {
    Write-Error "Deployment failed!"
    Write-Status "Checking logs..."
    & docker-compose logs --tail=20
    exit 1
}
