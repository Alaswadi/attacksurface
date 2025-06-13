#!/bin/bash

# Fix Email Notification Settings for Docker Deployment
# This script applies the database migration to existing Docker containers

echo "🚀 Fixing Email Notification Settings for Docker Deployment"
echo "============================================================"

# Check if docker-compose is available
if ! command -v docker-compose &> /dev/null; then
    echo "❌ docker-compose not found. Please install docker-compose first."
    exit 1
fi

# Check if the web container is running
if ! docker-compose ps | grep -q "attacksurface_web.*Up"; then
    echo "❌ AttackSurface web container is not running."
    echo "Please start the application first with: docker-compose up -d"
    exit 1
fi

echo "📋 Found running AttackSurface web container"

# Copy the migration script to the container
echo "📁 Copying migration script to container..."
docker cp docker_migration_email_notifications.py attacksurface_web:/app/

# Run the migration inside the container
echo "🔄 Running email notification settings migration..."
docker exec attacksurface_web python docker_migration_email_notifications.py

if [ $? -eq 0 ]; then
    echo "✅ Migration completed successfully!"
    echo ""
    echo "🔄 Restarting web container to apply changes..."
    docker-compose restart web
    
    echo ""
    echo "🎉 Email notification settings have been fixed!"
    echo ""
    echo "The consolidated notification settings should now work correctly."
    echo "You can test by:"
    echo "1. Going to Settings → Notifications"
    echo "2. Configuring both email settings and alert thresholds"
    echo "3. Clicking 'Save Notification Settings'"
    echo "4. Verifying that all settings are saved together"
else
    echo "❌ Migration failed!"
    echo "Please check the container logs for more details:"
    echo "docker-compose logs web"
    exit 1
fi
