#!/bin/bash

# Migration script to switch from PostgreSQL to SQLite in Docker

echo "🔄 Migrating Docker deployment from PostgreSQL to SQLite..."

# Check if docker-compose is available
if ! command -v docker-compose &> /dev/null; then
    echo "❌ docker-compose not found. Please install docker-compose first."
    exit 1
fi

# Stop current deployment
echo "🛑 Stopping current deployment..."
docker-compose down

# Remove PostgreSQL volumes (optional - uncomment if you want to clean up)
# echo "🗑️  Removing PostgreSQL volumes..."
# docker volume rm attacksurface_postgres_data 2>/dev/null || echo "PostgreSQL volume not found"

# Build new images with SQLite support
echo "🔨 Building new Docker images..."
docker-compose build --no-cache

# Start new deployment with SQLite
echo "🚀 Starting new deployment with SQLite..."
docker-compose up -d

# Wait for services to start
echo "⏳ Waiting for services to start..."
sleep 30

# Test SQLite connection
echo "🔗 Testing SQLite connection..."
docker-compose exec web python test_sqlite_connection.py

# Check service health
echo "🔍 Checking service health..."
docker-compose ps

# Test the application
echo "🧪 Testing application..."
if curl -f http://localhost:8077/api/dashboard/stats &>/dev/null; then
    echo "✅ Application is responding correctly"
else
    echo "⚠️  Application may still be starting up. Check logs with: docker-compose logs"
fi

# Show logs
echo "📋 Recent logs:"
docker-compose logs --tail=20

# Install email_validator if needed
echo "📦 Ensuring email_validator is installed..."
docker-compose exec web pip install email-validator==2.1.0 || echo "⚠️  email_validator may already be installed"

echo ""
echo "🎉 Migration to SQLite completed!"
echo ""
echo "📋 Next steps:"
echo "1. Visit http://localhost:8077 to access the application"
echo "2. Register a new user account if this is a fresh installation"
echo "3. Check the enhanced settings page at http://localhost:8077/settings"
echo ""
echo "📊 Useful commands:"
echo "  View logs: docker-compose logs -f"
echo "  Restart:   docker-compose restart"
echo "  Stop:      docker-compose down"
echo ""
echo "✅ Your attack surface management application is now running with SQLite!"
