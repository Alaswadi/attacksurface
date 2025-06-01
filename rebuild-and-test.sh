#!/bin/bash

echo "🔧 Rebuilding with tool path fixes..."

# Stop containers
docker-compose down

# Rebuild web container
docker-compose build --no-cache web

# Start containers
docker-compose up -d

# Wait for startup
echo "⏳ Waiting for services to start..."
sleep 30

# Check logs for tool availability
echo "📊 Checking tool availability in logs..."
docker-compose logs web | grep -E "(Found|availability|tools:|Initialized scanning service)"

echo ""
echo "✅ Rebuild complete! Check the logs above for tool status."
echo "🌐 Access: http://localhost:8090"
