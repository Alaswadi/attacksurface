#!/bin/bash

# Quick fix for PyYAML dependency

echo "🔧 Fixing PyYAML dependency issue..."

# Stop containers
echo "⏹️  Stopping containers..."
docker-compose down

# Rebuild with updated requirements
echo "🔨 Rebuilding with PyYAML..."
docker-compose build --no-cache web

# Start containers
echo "🚀 Starting containers..."
docker-compose up -d

echo ""
echo "✅ Fix complete! PyYAML dependency added."
echo "🎯 Navigate to 'Real Scanning' to test security tools!"
