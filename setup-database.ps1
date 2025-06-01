# Attack Surface Discovery - Database Setup Script (PowerShell)
# This script initializes the database tables and creates sample data

Write-Host "🔄 Attack Surface Discovery - Database Setup" -ForegroundColor Cyan
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

# Check if services are running
Write-Status "Checking if services are running..."
try {
    $services = & docker-compose ps
    if (-not ($services -match "Up")) {
        Write-Error "Docker services are not running. Please start them first:"
        Write-Host "  docker-compose up -d" -ForegroundColor White
        exit 1
    }
} catch {
    Write-Error "Failed to check Docker services. Make sure Docker is running."
    exit 1
}

# Wait for database to be ready
Write-Status "Waiting for database to be ready..."
$timeout = 60
do {
    Start-Sleep -Seconds 2
    $timeout -= 2
    try {
        $result = & docker-compose exec -T db pg_isready -U attacksurface_user -d attacksurface 2>$null
        if ($LASTEXITCODE -eq 0) {
            break
        }
    } catch {
        # Continue waiting
    }
    if ($timeout -le 0) {
        Write-Error "Database failed to start within 60 seconds"
        exit 1
    }
} while ($true)
Write-Success "Database is ready"

# Initialize database
Write-Status "Initializing database tables and sample data..."
try {
    & docker-compose exec -T web python init_db.py
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Database initialization completed!"
        Write-Host ""
        Write-Host "🎉 Setup completed successfully!" -ForegroundColor Green
        Write-Host ""
        Write-Host "You can now access your application at:" -ForegroundColor Cyan
        Write-Host "  • HTTP: http://localhost:8090" -ForegroundColor White
        Write-Host "  • Direct: http://localhost:8077" -ForegroundColor White
        Write-Host ""
        Write-Host "Default login credentials:" -ForegroundColor Cyan
        Write-Host "  • Username: admin" -ForegroundColor White
        Write-Host "  • Password: password" -ForegroundColor White
        Write-Host ""
        Write-Host "Useful commands:" -ForegroundColor Cyan
        Write-Host "  • View logs: docker-compose logs -f web" -ForegroundColor White
        Write-Host "  • Check database: docker-compose exec db psql -U attacksurface_user -d attacksurface" -ForegroundColor White
        Write-Host "  • Reset database: docker-compose exec web python init_db.py" -ForegroundColor White
    } else {
        throw "Database initialization failed"
    }
} catch {
    Write-Error "Database initialization failed!"
    Write-Status "Checking web container logs..."
    & docker-compose logs --tail=20 web
    exit 1
}
