#!/bin/bash

# Attack Surface Discovery - Docker Deployment Fix Script
# This script fixes common Docker deployment issues

set -e

echo "🔧 Attack Surface Discovery - Deployment Fix Script"
echo "=================================================="

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

# Stop any running containers
print_status "Stopping existing containers..."
docker-compose down 2>/dev/null || true

# Create required directories
print_status "Creating required directories..."
mkdir -p nginx/ssl logs/nginx

# Check if nginx.conf exists
if [ ! -f nginx/nginx.conf ]; then
    print_error "nginx/nginx.conf not found!"
    print_status "Creating basic nginx configuration..."
    
    cat > nginx/nginx.conf << 'EOF'
events {
    worker_connections 1024;
}

http {
    upstream backend {
        server web:5000;
    }
    
    server {
        listen 80;
        
        location / {
            proxy_pass http://backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
        
        location /health {
            return 200 'healthy';
            add_header Content-Type text/plain;
        }
    }
}
EOF
    print_success "Basic nginx configuration created"
fi

# Generate SSL certificates if missing
if [ ! -f nginx/ssl/cert.pem ] || [ ! -f nginx/ssl/key.pem ]; then
    print_status "Generating SSL certificates..."
    if command -v openssl >/dev/null 2>&1; then
        if [ -f generate-ssl.sh ]; then
            ./generate-ssl.sh
        else
            # Generate certificates inline
            openssl genrsa -out nginx/ssl/key.pem 2048
            openssl req -new -key nginx/ssl/key.pem -out nginx/ssl/cert.csr -subj "/C=US/ST=State/L=City/O=Organization/OU=OrgUnit/CN=localhost"
            openssl x509 -req -days 365 -in nginx/ssl/cert.csr -signkey nginx/ssl/key.pem -out nginx/ssl/cert.pem
            rm nginx/ssl/cert.csr
        fi
        print_success "SSL certificates generated"
    else
        print_warning "OpenSSL not found. Creating placeholder certificates..."
        echo "# Placeholder certificate" > nginx/ssl/cert.pem
        echo "# Placeholder key" > nginx/ssl/key.pem
    fi
fi

# Set proper permissions
print_status "Setting file permissions..."
chmod 644 nginx/nginx.conf 2>/dev/null || true
chmod -R 755 nginx/ 2>/dev/null || true
chmod 600 nginx/ssl/key.pem 2>/dev/null || true

# Check if .env file exists
if [ ! -f .env ]; then
    if [ -f .env.docker ]; then
        print_status "Creating .env file from template..."
        cp .env.docker .env
        print_warning "Please edit .env file with your configuration"
    else
        print_warning ".env file not found. Using default values."
    fi
fi

# Try original configuration first
print_status "Attempting deployment with original configuration..."
if docker-compose up -d --build; then
    print_success "Deployment successful with original configuration!"
else
    print_warning "Original configuration failed. Trying simple configuration..."
    
    # Backup original and use simple config
    if [ -f docker-compose.yml ]; then
        cp docker-compose.yml docker-compose.yml.backup
    fi
    
    if [ -f docker-compose.simple.yml ]; then
        cp docker-compose.simple.yml docker-compose.yml
        print_status "Using simplified configuration..."
        
        if docker-compose up -d --build; then
            print_success "Deployment successful with simplified configuration!"
        else
            print_error "Both configurations failed. Please check the logs:"
            docker-compose logs
            exit 1
        fi
    else
        print_error "Simple configuration not found. Please check your files."
        exit 1
    fi
fi

# Wait for services to be ready
print_status "Waiting for services to start..."
sleep 15

# Check service status
print_status "Checking service status..."
docker-compose ps

# Test connectivity
print_status "Testing connectivity..."
if curl -f http://localhost:8077/api/dashboard/stats >/dev/null 2>&1; then
    print_success "Direct web access working!"
elif curl -f http://localhost:8080/health >/dev/null 2>&1; then
    print_success "Nginx proxy working!"
else
    print_warning "Services may still be starting. Check logs with: docker-compose logs"
fi

print_success "🎉 Deployment fix completed!"
echo ""
echo "Access your application at:"
echo "  • Direct: http://localhost:8077"
echo "  • Proxy: http://localhost:8080"
echo ""
echo "Useful commands:"
echo "  • View logs: docker-compose logs -f"
echo "  • Check status: docker-compose ps"
echo "  • Stop services: docker-compose down"
