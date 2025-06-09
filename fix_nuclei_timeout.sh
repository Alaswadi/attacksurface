#!/bin/bash

echo "🔧 FIXING: Nuclei timeout and Celery exception issues"

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
echo "📋 Copying fixed Nuclei scanner (no timeout)..."
docker cp tools/nuclei.py $CONTAINER_NAME:/app/tools/

echo "📋 Copying fixed tasks (conservative Nuclei params + better error handling)..."
docker cp tasks.py $CONTAINER_NAME:/app/

# Restart the application to load changes
echo "🔄 Restarting application to load fixes..."
docker restart $CONTAINER_NAME

echo ""
echo "✅ Nuclei timeout and Celery fixes applied!"
echo ""
echo "🔧 What was fixed:"
echo "- Removed timeout limit from Nuclei scans (prevents process killing)"
echo "- Reduced Nuclei scan parameters for better stability:"
echo "  * Rate limit: 150 → 50 requests/sec"
echo "  * Concurrency: 25 → 10 threads"
echo "  * Bulk size: 20 → 5"
echo "  * Timeout: 15 → 10 seconds per request"
echo "- Improved Celery exception handling"
echo ""
echo "🧪 Test by running a new Nuclei scan:"
echo "- Should complete without return code -9"
echo "- Should store vulnerabilities successfully"
echo "- Should not show Celery exception errors"
