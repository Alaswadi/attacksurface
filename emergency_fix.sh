#!/bin/bash

echo "🚨 EMERGENCY FIX: Stopping infinite migration loop and fixing database"

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

# Step 1: Stop the container to stop the infinite loop
echo "🛑 Stopping container to break the infinite loop..."
docker stop $CONTAINER_NAME

# Step 2: Copy the fixed app.py (without auto-migration)
echo "📋 Copying fixed app.py (without auto-migration)..."
docker cp app.py $CONTAINER_NAME:/app/

# Step 3: Start the container
echo "🚀 Starting container..."
docker start $CONTAINER_NAME

# Wait a moment for it to start
echo "⏳ Waiting for container to start..."
sleep 10

# Step 4: Run the migration ONCE manually
echo "🔄 Running database migration manually (one time only)..."
docker exec $CONTAINER_NAME python /app/docker_migration.py

# Step 5: Copy all the updated files
echo "📋 Copying updated application files..."
docker cp models.py $CONTAINER_NAME:/app/
docker cp tasks.py $CONTAINER_NAME:/app/
docker cp templates/vulnerabilities.html $CONTAINER_NAME:/app/templates/
docker cp routes/api.py $CONTAINER_NAME:/app/routes/

# Step 6: Restart the application one final time
echo "🔄 Final restart to load all changes..."
docker restart $CONTAINER_NAME

echo ""
echo "✅ Emergency fix completed!"
echo ""
echo "🔍 What was fixed:"
echo "- Stopped the infinite migration loop"
echo "- Applied database migration once"
echo "- Updated all application files"
echo "- Restarted with clean state"
echo ""
echo "📱 Your application should now be accessible without 504 errors"
echo "🎯 Vulnerability storage should now work properly"
echo ""
echo "🧪 To test:"
echo "1. Visit your application (should load without 504)"
echo "2. Go to vulnerabilities page (should load without database errors)"
echo "3. Run a new Nuclei scan (should store all vulnerabilities)"
