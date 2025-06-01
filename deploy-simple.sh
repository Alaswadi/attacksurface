#!/bin/bash

# Attack Surface Discovery - Simple Deployment (No SSL)
# This script deploys the application without SSL certificates

echo "🚀 Attack Surface Discovery - Simple Deployment (No SSL)"
echo "========================================================"

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

# Stop any existing containers
print_status "Stopping existing containers..."
docker-compose down --remove-orphans 2>/dev/null || true

# Remove containers using our target ports
print_status "Checking for port conflicts..."
for port in 8090 8077; do
    container_id=$(docker ps --filter "publish=$port" -q 2>/dev/null)
    if [ ! -z "$container_id" ]; then
        print_warning "Found container $container_id using port $port. Stopping..."
        docker stop $container_id 2>/dev/null || true
        docker rm $container_id 2>/dev/null || true
    fi
done

# Clean up Docker system
print_status "Cleaning up Docker system..."
docker system prune -f >/dev/null 2>&1 || true

# Create required directories
print_status "Creating required directories..."
mkdir -p logs/nginx

# Check if .env file exists
if [ ! -f .env ]; then
    if [ -f .env.docker ]; then
        print_status "Creating .env file from template..."
        cp .env.docker .env
        print_success ".env file created"
    else
        print_warning ".env file not found. Using default values."
    fi
fi

# Deploy without SSL
print_status "Deploying application with real security scanning tools..."
print_status "Ports: HTTP=8090, Direct=8077"
print_status "Installing: Subfinder, Naabu, Nuclei"

if docker-compose up -d --build; then
    print_success "Deployment successful!"

    # Wait for services to start
    print_status "Waiting for services to start..."
    sleep 20

    # Wait for database to be ready
    print_status "Waiting for database to be ready..."
    timeout=60
    while ! docker-compose exec -T db pg_isready -U attacksurface_user -d attacksurface >/dev/null 2>&1; do
        sleep 2
        timeout=$((timeout - 2))
        if [ $timeout -le 0 ]; then
            print_warning "Database took longer than expected to start"
            break
        fi
    done
    
    # Check service status
    print_status "Service status:"
    docker-compose ps
    
    # Test connectivity
    print_status "Testing connectivity..."
    
    if curl -f http://localhost:8077/api/dashboard/stats >/dev/null 2>&1; then
        print_success "✅ Direct web access working on port 8077"
    else
        print_warning "⚠️  Direct web access not responding yet"
    fi
    
    if curl -f http://localhost:8090/health >/dev/null 2>&1; then
        print_success "✅ Nginx proxy working on port 8090"
    else
        print_warning "⚠️  Nginx proxy not responding yet"
    fi
    
    echo ""
    print_success "🎉 Simple deployment completed!"
    echo ""
    echo "Access your application at:"
    echo "  • HTTP Proxy: http://localhost:8090"
    echo "  • Direct Web: http://localhost:8077"
    echo ""
    echo "Default credentials:"
    echo "  • Username: admin"
    echo "  • Password: password"
    echo ""
    echo "🎯 NEW: Real Security Scanning Available!"
    echo "  • Navigate to 'Real Scanning' in the sidebar"
    echo "  • Test tools: Subfinder, Naabu, Nuclei"
    echo "  • Perform real domain scans"
    echo ""
    echo "Useful commands:"
    echo "  • View logs: docker-compose logs -f"
    echo "  • Check status: docker-compose ps"
    echo "  • Stop services: docker-compose down"
    echo ""
    print_warning "Note: This deployment uses HTTP only (no SSL/HTTPS)"
    
else
    print_error "Deployment failed!"
    print_status "Checking logs..."
    docker-compose logs --tail=20
    exit 1
fi
