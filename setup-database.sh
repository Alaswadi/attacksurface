#!/bin/bash

# Attack Surface Discovery - Database Setup Script
# This script initializes the database tables and creates sample data

echo "🔄 Attack Surface Discovery - Database Setup"
echo "============================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if services are running
print_status "Checking if services are running..."
if ! docker-compose ps | grep -q "Up"; then
    print_error "Docker services are not running. Please start them first:"
    echo "  docker-compose up -d"
    exit 1
fi

# Wait for database to be ready
print_status "Waiting for database to be ready..."
timeout=60
while ! docker-compose exec -T db pg_isready -U attacksurface_user -d attacksurface >/dev/null 2>&1; do
    sleep 2
    timeout=$((timeout - 2))
    if [ $timeout -le 0 ]; then
        print_error "Database failed to start within 60 seconds"
        exit 1
    fi
done
print_success "Database is ready"

# Initialize database
print_status "Initializing database tables and sample data..."
if docker-compose exec -T web python init_db.py; then
    print_success "Database initialization completed!"
    echo ""
    echo "🎉 Setup completed successfully!"
    echo ""
    echo "You can now access your application at:"
    echo "  • HTTP: http://localhost:8090"
    echo "  • Direct: http://localhost:8077"
    echo ""
    echo "Default login credentials:"
    echo "  • Username: admin"
    echo "  • Password: password"
    echo ""
    echo "Useful commands:"
    echo "  • View logs: docker-compose logs -f web"
    echo "  • Check database: docker-compose exec db psql -U attacksurface_user -d attacksurface"
    echo "  • Reset database: docker-compose exec web python init_db.py"
else
    print_error "Database initialization failed!"
    print_status "Checking web container logs..."
    docker-compose logs --tail=20 web
    exit 1
fi
