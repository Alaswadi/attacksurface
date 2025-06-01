# Attack Surface Discovery - Deployment Script (PowerShell)
# This script automates the deployment process on Windows

param(
    [switch]$SkipSSL,
    [switch]$Force
)

Write-Host "🚀 Attack Surface Discovery - Deployment Script" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan

# Function to print colored output
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

# Check prerequisites
function Test-Prerequisites {
    Write-Status "Checking prerequisites..."
    
    try {
        $null = Get-Command docker -ErrorAction Stop
        Write-Success "Docker found"
    } catch {
        Write-Error "Docker is not installed. Please install Docker Desktop first."
        exit 1
    }
    
    try {
        $null = Get-Command docker-compose -ErrorAction Stop
        Write-Success "Docker Compose found"
    } catch {
        Write-Error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    }
    
    Write-Success "Prerequisites check passed"
}

# Setup environment
function Set-Environment {
    Write-Status "Setting up environment..."
    
    if (!(Test-Path ".env")) {
        if (Test-Path ".env.docker") {
            Copy-Item ".env.docker" ".env"
            Write-Success "Environment file created from template"
            Write-Warning "Please edit .env file with your configuration before continuing"
            
            if (!$Force) {
                Read-Host "Press Enter to continue after editing .env file"
            }
        } else {
            Write-Error ".env.docker template not found"
            exit 1
        }
    } else {
        Write-Success "Environment file already exists"
    }
}

# Generate SSL certificates
function New-SSLCertificates {
    if ($SkipSSL) {
        Write-Warning "Skipping SSL certificate generation"
        return
    }
    
    Write-Status "Checking SSL certificates..."
    
    if (!(Test-Path "nginx\ssl\cert.pem") -or !(Test-Path "nginx\ssl\key.pem")) {
        Write-Status "Generating SSL certificates..."
        
        try {
            & .\generate-ssl.ps1
            Write-Success "SSL certificates generated"
        } catch {
            Write-Error "Failed to generate SSL certificates. Run generate-ssl.ps1 manually."
            exit 1
        }
    } else {
        Write-Success "SSL certificates already exist"
    }
}

# Create directories
function New-Directories {
    Write-Status "Creating required directories..."
    
    $directories = @("logs", "logs\nginx", "nginx\ssl")
    
    foreach ($dir in $directories) {
        if (!(Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
    }
    
    Write-Success "Directories created"
}

# Build and start services
function Start-Services {
    Write-Status "Building and starting services..."
    
    try {
        # Build images
        Write-Status "Building Docker images..."
        & docker-compose build --no-cache
        
        if ($LASTEXITCODE -ne 0) {
            throw "Docker build failed"
        }
        
        # Start services
        Write-Status "Starting services..."
        & docker-compose up -d
        
        if ($LASTEXITCODE -ne 0) {
            throw "Docker compose up failed"
        }
        
        Write-Success "Services started"
    } catch {
        Write-Error "Failed to start services: $_"
        exit 1
    }
}

# Wait for services to be ready
function Wait-ForServices {
    Write-Status "Waiting for services to be ready..."
    
    # Wait for database
    Write-Status "Waiting for database..."
    $timeout = 60
    do {
        Start-Sleep -Seconds 2
        $timeout -= 2
        $dbReady = & docker-compose exec -T db pg_isready -U attacksurface_user -d attacksurface 2>$null
        if ($timeout -le 0) {
            Write-Error "Database failed to start within 60 seconds"
            exit 1
        }
    } while ($LASTEXITCODE -ne 0)
    Write-Success "Database is ready"
    
    # Wait for web application
    Write-Status "Waiting for web application..."
    $timeout = 60
    do {
        Start-Sleep -Seconds 2
        $timeout -= 2
        try {
            $response = Invoke-WebRequest -Uri "http://localhost:8077/api/dashboard/stats" -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue
            if ($response.StatusCode -eq 200) {
                break
            }
        } catch {
            # Continue waiting
        }
        if ($timeout -le 0) {
            Write-Error "Web application failed to start within 60 seconds"
            exit 1
        }
    } while ($true)
    Write-Success "Web application is ready"
}

# Show deployment status
function Show-Status {
    Write-Status "Deployment Status:"
    Write-Host ""
    & docker-compose ps
    Write-Host ""
    Write-Success "🎉 Deployment completed successfully!"
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
    Write-Host "  • Stop services: docker-compose down" -ForegroundColor White
    Write-Host "  • Restart: docker-compose restart" -ForegroundColor White
}

# Main deployment process
function Start-Deployment {
    try {
        Write-Host ""
        Test-Prerequisites
        Write-Host ""
        Set-Environment
        Write-Host ""
        New-Directories
        Write-Host ""
        New-SSLCertificates
        Write-Host ""
        Start-Services
        Write-Host ""
        Wait-ForServices
        Write-Host ""
        Show-Status
    } catch {
        Write-Error "Deployment failed: $_"
        exit 1
    }
}

# Handle Ctrl+C
$null = Register-EngineEvent PowerShell.Exiting -Action {
    Write-Error "Deployment interrupted"
}

# Run main function
Start-Deployment
