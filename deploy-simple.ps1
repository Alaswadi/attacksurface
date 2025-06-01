# Attack Surface Discovery - Simple Deployment (No SSL)
# This script deploys the application without SSL certificates

Write-Host "🚀 Attack Surface Discovery - Simple Deployment (No SSL)" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

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

# Stop any existing containers
Write-Status "Stopping existing containers..."
try {
    & docker-compose down --remove-orphans 2>$null
} catch {
    # Ignore errors if no containers are running
}

# Remove containers using our target ports
Write-Status "Checking for port conflicts..."
$ports = @(8090, 8077)
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

# Create required directories
Write-Status "Creating required directories..."
if (!(Test-Path "logs\nginx")) {
    New-Item -ItemType Directory -Path "logs\nginx" -Force | Out-Null
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

# Deploy without SSL
Write-Status "Deploying application without SSL..."
Write-Status "Ports: HTTP=8090, Direct=8077"

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
            $response = Invoke-WebRequest -Uri "http://localhost:8090/health" -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue
            if ($response.StatusCode -eq 200) {
                Write-Success "✅ Nginx proxy working on port 8090"
            }
        } catch {
            Write-Warning "⚠️  Nginx proxy not responding yet"
        }
        
        Write-Host ""
        Write-Success "🎉 Simple deployment completed!"
        Write-Host ""
        Write-Host "Access your application at:" -ForegroundColor Cyan
        Write-Host "  • HTTP Proxy: http://localhost:8090" -ForegroundColor White
        Write-Host "  • Direct Web: http://localhost:8077" -ForegroundColor White
        Write-Host ""
        Write-Host "Default credentials:" -ForegroundColor Cyan
        Write-Host "  • Username: admin" -ForegroundColor White
        Write-Host "  • Password: password" -ForegroundColor White
        Write-Host ""
        Write-Host "Useful commands:" -ForegroundColor Cyan
        Write-Host "  • View logs: docker-compose logs -f" -ForegroundColor White
        Write-Host "  • Check status: docker-compose ps" -ForegroundColor White
        Write-Host "  • Stop services: docker-compose down" -ForegroundColor White
        Write-Host ""
        Write-Warning "Note: This deployment uses HTTP only (no SSL/HTTPS)"
        
    } else {
        throw "Docker compose failed"
    }
} catch {
    Write-Error "Deployment failed!"
    Write-Status "Checking logs..."
    & docker-compose logs --tail=20
    exit 1
}
