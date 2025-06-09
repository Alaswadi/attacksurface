#!/bin/bash

echo "🔧 FIXING: Domain format validation and Celery exception handling"

# Find the Flask app container
CONTAINER_NAME=$(docker ps --format "table {{.Names}}" | grep -E "(app|flask|web|attacksurface)" | head -1)

if [ -z "$CONTAINER_NAME" ]; then
    echo "❌ Could not find Flask app container. Available containers:"
    docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}"
    echo ""
    echo "Please specify your container name:"
    read -p "Enter container name: " CONTAINER_NAME
fi

echo "📦 Using container: $CONTAINER_NAME"

# Copy the fixed files
echo "📋 Copying fixed Subfinder (auto-cleans domain format)..."
docker cp tools/subfinder.py $CONTAINER_NAME:/app/tools/

echo "📋 Copying fixed tasks (better Celery exception handling)..."
docker cp tasks.py $CONTAINER_NAME:/app/

echo "📋 Copying simplified models (no confidence_score)..."
docker cp models.py $CONTAINER_NAME:/app/

echo "📋 Copying simplified migration script..."
docker cp docker_migration.py $CONTAINER_NAME:/app/

# Run the migration to ensure database is ready
echo "🔄 Running simplified database migration..."
docker exec $CONTAINER_NAME python /app/docker_migration.py

# Restart the application to load all fixes
echo "🔄 Restarting application to load all fixes..."
docker restart $CONTAINER_NAME

echo ""
echo "✅ Domain format and Celery exception fixes applied!"
echo ""
echo "🔧 What was fixed:"
echo "1. Domain Format Issues:"
echo "   - Subfinder now auto-cleans URLs: https://pwp2.vns.agency → pwp2.vns.agency"
echo "   - Removes protocol, path, port, www prefix automatically"
echo "   - No more 'Invalid domain format' errors"
echo ""
echo "2. Celery Exception Handling:"
echo "   - Fixed 'Exception information must include the exception type' error"
echo "   - Better error formatting and state management"
echo "   - Tasks return failure results instead of raising exceptions"
echo ""
echo "3. Vulnerability Storage:"
echo "   - Simplified validation (no confidence scoring)"
echo "   - All vulnerabilities stored successfully"
echo "   - Critical/High/Medium = auto-validated"
echo "   - Low/Info = manual review"
echo ""
echo "🧪 Test by running a scan with:"
echo "- Domain with protocol: https://pwp2.vns.agency (should work now)"
echo "- Should complete without Celery errors"
echo "- Should store all vulnerabilities found"
