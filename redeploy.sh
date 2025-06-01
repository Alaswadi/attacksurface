#!/bin/bash

# Attack Surface Discovery - Clean Redeploy Script
# This script stops existing containers and redeploys with new port configuration

echo "🔄 Attack Surface Discovery - Clean Redeploy"
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

# Stop and remove existing containers
print_status "Stopping and removing existing containers..."
docker-compose down --remove-orphans 2>/dev/null || true

# Remove any containers that might be using the ports
print_status "Checking for containers using ports 8088, 8443, 8077..."
for port in 8088 8443 8077; do
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

# Ensure required directories exist
print_status "Creating required directories..."
mkdir -p nginx/ssl logs/nginx

# Generate SSL certificates if missing
if [ ! -f nginx/ssl/cert.pem ] || [ ! -f nginx/ssl/key.pem ]; then
    print_status "Generating SSL certificates..."
    if [ -f generate-ssl.sh ]; then
        ./generate-ssl.sh >/dev/null 2>&1 || true
    fi
fi

# Build and start services
print_status "Building and starting services with new port configuration..."
print_status "Ports: HTTP=8088, HTTPS=8443, Direct=8077"

if docker-compose up -d --build; then
    print_success "Deployment successful!"
    
    # Wait for services to start
    print_status "Waiting for services to start..."
    sleep 15
    
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
    
    if curl -f http://localhost:8088/health >/dev/null 2>&1; then
        print_success "✅ Nginx proxy working on port 8088"
    else
        print_warning "⚠️  Nginx proxy not responding yet"
    fi
    
    echo ""
    print_success "🎉 Redeployment completed!"
    echo ""
    echo "Access your application at:"
    echo "  • HTTPS: https://localhost:8443"
    echo "  • HTTP:  http://localhost:8088 (redirects to HTTPS)"
    echo "  • Direct: http://localhost:8077"
    echo ""
    echo "Default credentials:"
    echo "  • Username: admin"
    echo "  • Password: password"
    echo ""
    echo "Useful commands:"
    echo "  • View logs: docker-compose logs -f"
    echo "  • Check status: docker-compose ps"
    echo "  • Stop services: docker-compose down"
    
else
    print_error "Deployment failed!"
    print_status "Checking logs..."
    docker-compose logs --tail=20
    exit 1
fi
