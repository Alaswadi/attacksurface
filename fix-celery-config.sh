#!/bin/bash

# Fix Celery Configuration for Docker VPS
# This script updates the Celery configuration to use the new format

echo "🔧 Fixing Celery configuration for Docker VPS..."

# Stop existing containers
echo "⏹️  Stopping containers..."
docker-compose down

# Rebuild containers with updated configuration
echo "🔨 Rebuilding containers with new Celery configuration..."
docker-compose build --no-cache

# Start containers
echo "🚀 Starting containers with fixed configuration..."
docker-compose up -d

echo ""
echo "✅ Celery configuration fix complete!"
echo ""
echo "📊 Check container status:"
echo "docker-compose ps"
echo ""
echo "📋 Check Celery worker logs:"
echo "docker-compose logs -f celery"
echo ""
echo "🌐 Access application:"
echo "http://your-vps-ip:8077"
echo ""
echo "🎯 Test large-scale scanning:"
echo "http://your-vps-ip:8077/large-scale-scanning"
