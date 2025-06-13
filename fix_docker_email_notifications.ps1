# Fix Email Notification Settings for Docker Deployment (PowerShell)
# This script applies the database migration to existing Docker containers

Write-Host "🚀 Fixing Email Notification Settings for Docker Deployment" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green

# Check if docker-compose is available
try {
    docker-compose --version | Out-Null
} catch {
    Write-Host "❌ docker-compose not found. Please install docker-compose first." -ForegroundColor Red
    exit 1
}

# Check if the web container is running
$containerStatus = docker-compose ps | Select-String "attacksurface_web.*Up"
if (-not $containerStatus) {
    Write-Host "❌ AttackSurface web container is not running." -ForegroundColor Red
    Write-Host "Please start the application first with: docker-compose up -d" -ForegroundColor Yellow
    exit 1
}

Write-Host "📋 Found running AttackSurface web container" -ForegroundColor Green

# Copy the migration script to the container
Write-Host "📁 Copying migration script to container..." -ForegroundColor Yellow
docker cp docker_migration_email_notifications.py attacksurface_web:/app/

# Run the migration inside the container
Write-Host "🔄 Running email notification settings migration..." -ForegroundColor Yellow
$migrationResult = docker exec attacksurface_web python docker_migration_email_notifications.py

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Migration completed successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "🔄 Restarting web container to apply changes..." -ForegroundColor Yellow
    docker-compose restart web
    
    Write-Host ""
    Write-Host "🎉 Email notification settings have been fixed!" -ForegroundColor Green
    Write-Host ""
    Write-Host "The consolidated notification settings should now work correctly." -ForegroundColor Cyan
    Write-Host "You can test by:" -ForegroundColor Cyan
    Write-Host "1. Going to Settings → Notifications" -ForegroundColor White
    Write-Host "2. Configuring both email settings and alert thresholds" -ForegroundColor White
    Write-Host "3. Clicking 'Save Notification Settings'" -ForegroundColor White
    Write-Host "4. Verifying that all settings are saved together" -ForegroundColor White
} else {
    Write-Host "❌ Migration failed!" -ForegroundColor Red
    Write-Host "Please check the container logs for more details:" -ForegroundColor Yellow
    Write-Host "docker-compose logs web" -ForegroundColor White
    exit 1
}
