#!/bin/bash

echo "🚀 Deploying vulnerability validation updates to Docker..."

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

# Find the Flask app container
CONTAINER_NAME=$(docker ps --format "table {{.Names}}" | grep -E "(app|flask|web|attacksurface)" | head -1)

if [ -z "$CONTAINER_NAME" ]; then
    echo "❌ Could not find Flask app container. Available containers:"
    docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}"
    echo ""
    echo "Please specify your container name manually:"
    echo "export CONTAINER_NAME=your_container_name"
    echo "Then run this script again."
    exit 1
fi

echo "📦 Found container: $CONTAINER_NAME"

# Copy the migration script to the container
echo "📋 Copying migration script to container..."
docker cp docker_migration.py $CONTAINER_NAME:/app/

# Copy updated files to container
echo "📋 Copying updated application files..."
docker cp app.py $CONTAINER_NAME:/app/
docker cp models.py $CONTAINER_NAME:/app/
docker cp tasks.py $CONTAINER_NAME:/app/
docker cp templates/vulnerabilities.html $CONTAINER_NAME:/app/templates/
docker cp routes/api.py $CONTAINER_NAME:/app/routes/

# Run the migration
echo "🔄 Running database migration in container..."
docker exec $CONTAINER_NAME python /app/docker_migration.py

# Check the result
if [ $? -eq 0 ]; then
    echo "✅ Migration completed successfully!"
    
    # Restart the application to load new code
    echo "🔄 Restarting application..."
    docker restart $CONTAINER_NAME
    
    echo ""
    echo "🎉 Deployment completed successfully!"
    echo ""
    echo "✨ What's now available:"
    echo "- All Nuclei scan results are stored (validated and unvalidated)"
    echo "- Vulnerabilities page shows validation status badges"
    echo "- Confidence scores are displayed for each vulnerability"
    echo "- New validation filter to distinguish findings"
    echo "- Enhanced statistics showing validated vs unvalidated counts"
    echo ""
    echo "🔍 The specific vulnerabilities from your scan should now be visible:"
    echo "- 'Web Configuration File - Detect' (confidence: 63%, severity: info)"
    echo "- 'Clockwork PHP page exposure' (confidence: 90%, severity: high)"
    echo ""
    echo "📱 Visit your vulnerabilities page to see the new features!"
    
else
    echo "❌ Migration failed!"
    echo "Please check the error messages above."
    echo ""
    echo "You can try running the migration manually:"
    echo "docker exec -it $CONTAINER_NAME python /app/docker_migration.py"
    exit 1
fi
