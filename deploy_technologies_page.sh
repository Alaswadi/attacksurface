#!/bin/bash

echo "🚀 DEPLOYING: New Technologies Page (replacing Real Scanning)"

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

# Copy the new Technologies files
echo "📋 Copying new Technologies API route..."
docker cp routes/technologies.py $CONTAINER_NAME:/app/routes/

echo "📋 Copying new Technologies template..."
docker cp templates/technologies.html $CONTAINER_NAME:/app/templates/

echo "📋 Copying updated app.py (Technologies route)..."
docker cp app.py $CONTAINER_NAME:/app/

echo "📋 Copying updated navigation templates..."
docker cp templates/dashboard.html $CONTAINER_NAME:/app/templates/
docker cp templates/assets.html $CONTAINER_NAME:/app/templates/
docker cp templates/vulnerabilities.html $CONTAINER_NAME:/app/templates/

# Remove old real_scanning files from container
echo "🗑️ Removing old real-scanning files..."
docker exec $CONTAINER_NAME rm -f /app/routes/real_scanning.py
docker exec $CONTAINER_NAME rm -f /app/templates/real_scanning.html

# Copy the domain and Celery fixes as well
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

# Restart the application to load all changes
echo "🔄 Restarting application to load Technologies page..."
docker restart $CONTAINER_NAME

echo ""
echo "✅ Technologies Page deployment completed!"
echo ""
echo "🎯 What's New:"
echo "1. Technologies Page Features:"
echo "   - 📊 Technology discovery dashboard with summary statistics"
echo "   - 🔍 Advanced filtering by technology name, category, and version"
echo "   - 📱 Interactive technology cards showing usage counts"
echo "   - 🔗 Click-through to detailed asset information per technology"
echo "   - 📈 Strategic analysis capabilities for attack surface assessment"
echo ""
echo "2. Technology Intelligence:"
echo "   - 🌐 Web servers (Apache, Nginx, IIS)"
echo "   - ⚛️ JavaScript frameworks (React, Vue, Angular)"
echo "   - 🔧 Backend frameworks (Django, Laravel, Spring)"
echo "   - 📝 CMS platforms (WordPress, Drupal, Joomla)"
echo "   - 💾 Databases (MySQL, PostgreSQL, MongoDB)"
echo "   - ☁️ Cloud services and CDNs"
echo ""
echo "3. Navigation Updates:"
echo "   - ❌ Removed 'Real Scanning' page"
echo "   - ✅ Added 'Technologies' page to all navigation menus"
echo "   - 🆕 NEW badge on Technologies menu item"
echo ""
echo "4. Additional Fixes:"
echo "   - 🔧 Fixed domain format validation (auto-cleans URLs)"
echo "   - 🔧 Fixed Celery exception handling"
echo "   - 🔧 Simplified vulnerability storage (no confidence scoring)"
echo ""
echo "🌟 Key Benefits:"
echo "- Transform raw scanning data into actionable technology intelligence"
echo "- Identify attack surfaces based on technology stacks"
echo "- Find assets running outdated/vulnerable software versions"
echo "- Discover technology patterns across infrastructure"
echo "- Plan security assessments based on technology inventory"
echo ""
echo "📱 Access the new Technologies page at: /technologies"
echo "🎉 The page will automatically populate with technology data from your existing asset scans!"
