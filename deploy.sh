#!/bin/bash

# Attack Surface Discovery - Deployment Script
# This script automates the deployment process

set -e

echo "🚀 Attack Surface Discovery - Deployment Script"
echo "================================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
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

# Check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    print_success "Prerequisites check passed"
}

# Setup environment
setup_environment() {
    print_status "Setting up environment..."
    
    if [ ! -f .env ]; then
        if [ -f .env.docker ]; then
            cp .env.docker .env
            print_success "Environment file created from template"
            print_warning "Please edit .env file with your configuration before continuing"
            read -p "Press Enter to continue after editing .env file..."
        else
            print_error ".env.docker template not found"
            exit 1
        fi
    else
        print_success "Environment file already exists"
    fi
}

# Generate SSL certificates
generate_ssl() {
    print_status "Checking SSL certificates..."
    
    if [ ! -f nginx/ssl/cert.pem ] || [ ! -f nginx/ssl/key.pem ]; then
        print_status "Generating SSL certificates..."
        
        if command -v openssl &> /dev/null; then
            ./generate-ssl.sh
            print_success "SSL certificates generated"
        else
            print_error "OpenSSL not found. Please install OpenSSL or manually create SSL certificates"
            exit 1
        fi
    else
        print_success "SSL certificates already exist"
    fi
}

# Create directories
create_directories() {
    print_status "Creating required directories..."
    
    mkdir -p logs/nginx
    mkdir -p nginx/ssl
    
    print_success "Directories created"
}

# Build and start services
deploy_services() {
    print_status "Building and starting services..."
    
    # Build images
    docker-compose build --no-cache
    
    # Start services
    docker-compose up -d
    
    print_success "Services started"
}

# Wait for services to be ready
wait_for_services() {
    print_status "Waiting for services to be ready..."
    
    # Wait for database
    print_status "Waiting for database..."
    timeout=60
    while ! docker-compose exec -T db pg_isready -U attacksurface_user -d attacksurface &> /dev/null; do
        sleep 2
        timeout=$((timeout - 2))
        if [ $timeout -le 0 ]; then
            print_error "Database failed to start within 60 seconds"
            exit 1
        fi
    done
    print_success "Database is ready"
    
    # Wait for web application
    print_status "Waiting for web application..."
    timeout=60
    while ! curl -f http://localhost:8077/api/dashboard/stats &> /dev/null; do
        sleep 2
        timeout=$((timeout - 2))
        if [ $timeout -le 0 ]; then
            print_error "Web application failed to start within 60 seconds"
            exit 1
        fi
    done
    print_success "Web application is ready"
}

# Show deployment status
show_status() {
    print_status "Deployment Status:"
    echo ""
    docker-compose ps
    echo ""
    print_success "🎉 Deployment completed successfully!"
    echo ""
    echo "Access your application at:"
    echo "  • HTTPS: https://localhost:443"
    echo "  • HTTP:  http://localhost:8088 (redirects to HTTPS)"
    echo "  • Direct: http://localhost:8077"
    echo ""
    echo "Default credentials:"
    echo "  • Username: admin"
    echo "  • Password: password"
    echo ""
    echo "Useful commands:"
    echo "  • View logs: docker-compose logs -f"
    echo "  • Stop services: docker-compose down"
    echo "  • Restart: docker-compose restart"
}

# Main deployment process
main() {
    echo ""
    check_prerequisites
    echo ""
    setup_environment
    echo ""
    create_directories
    echo ""
    generate_ssl
    echo ""
    deploy_services
    echo ""
    wait_for_services
    echo ""
    show_status
}

# Handle script interruption
trap 'print_error "Deployment interrupted"; exit 1' INT TERM

# Run main function
main
