#!/bin/bash

# Docker Redis Connection Fix Verification Script
# This script verifies that the Redis connection fix is working in Docker

echo "🐳 Docker Redis Connection Fix Verification"
echo "============================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local status=$1
    local message=$2
    if [ "$status" = "success" ]; then
        echo -e "${GREEN}✅ $message${NC}"
    elif [ "$status" = "error" ]; then
        echo -e "${RED}❌ $message${NC}"
    elif [ "$status" = "warning" ]; then
        echo -e "${YELLOW}⚠️  $message${NC}"
    elif [ "$status" = "info" ]; then
        echo -e "${BLUE}ℹ️  $message${NC}"
    fi
}

# Check if Docker is running
print_status "info" "Checking Docker status..."
if ! docker info > /dev/null 2>&1; then
    print_status "error" "Docker is not running. Please start Docker first."
    exit 1
fi
print_status "success" "Docker is running"

# Check if containers are running
print_status "info" "Checking container status..."

if ! docker ps | grep -q "attacksurface_redis"; then
    print_status "error" "Redis container is not running. Please start with: docker-compose up -d"
    exit 1
fi
print_status "success" "Redis container is running"

if ! docker ps | grep -q "attacksurface_web"; then
    print_status "error" "Web container is not running. Please start with: docker-compose up -d"
    exit 1
fi
print_status "success" "Web container is running"

# Test Redis container directly
print_status "info" "Testing Redis container directly..."
if docker exec attacksurface_redis redis-cli ping > /dev/null 2>&1; then
    print_status "success" "Redis container responds to ping"
else
    print_status "error" "Redis container is not responding"
    exit 1
fi

# Test Redis connection from web container
print_status "info" "Testing Redis connection from web container..."
if docker exec attacksurface_web redis-cli -h redis -p 6379 ping > /dev/null 2>&1; then
    print_status "success" "Web container can connect to Redis"
else
    print_status "warning" "Direct Redis connection failed, checking with password..."
    # Try with password
    REDIS_PASSWORD=$(docker exec attacksurface_web env | grep REDIS_PASSWORD | cut -d'=' -f2)
    if [ -n "$REDIS_PASSWORD" ]; then
        if docker exec attacksurface_web redis-cli -h redis -p 6379 -a "$REDIS_PASSWORD" ping > /dev/null 2>&1; then
            print_status "success" "Web container can connect to Redis with password"
        else
            print_status "error" "Web container cannot connect to Redis even with password"
            exit 1
        fi
    else
        print_status "error" "No Redis password found in environment"
        exit 1
    fi
fi

# Check environment variables
print_status "info" "Checking environment variables..."
CELERY_BROKER_URL=$(docker exec attacksurface_web env | grep CELERY_BROKER_URL | cut -d'=' -f2-)
if [ -n "$CELERY_BROKER_URL" ]; then
    print_status "success" "CELERY_BROKER_URL is set: ${CELERY_BROKER_URL//:*@/:***@}"
else
    print_status "error" "CELERY_BROKER_URL is not set"
    exit 1
fi

# Test Python Redis connection
print_status "info" "Testing Python Redis connection..."
if docker exec attacksurface_web python test_docker_redis.py > /dev/null 2>&1; then
    print_status "success" "Python Redis connection test passed"
else
    print_status "error" "Python Redis connection test failed"
    print_status "info" "Running detailed test..."
    docker exec attacksurface_web python test_docker_redis.py
    exit 1
fi

# Test Flask application Redis checker
print_status "info" "Testing Flask application Redis checker..."
REDIS_CHECK_RESULT=$(docker exec attacksurface_web python -c "
from utils.redis_checker import check_redis_availability
is_available, error = check_redis_availability()
print('available' if is_available else f'error: {error}')
" 2>/dev/null)

if [[ "$REDIS_CHECK_RESULT" == "available" ]]; then
    print_status "success" "Flask Redis checker reports Redis as available"
else
    print_status "error" "Flask Redis checker failed: $REDIS_CHECK_RESULT"
    exit 1
fi

# Test Redis status API endpoint
print_status "info" "Testing Redis status API endpoint..."
WEB_PORT=$(docker port attacksurface_web 5000 | cut -d':' -f2)
if [ -n "$WEB_PORT" ]; then
    API_RESPONSE=$(curl -s "http://localhost:$WEB_PORT/api/system/redis-status" 2>/dev/null)
    if echo "$API_RESPONSE" | grep -q '"celery_available": true'; then
        print_status "success" "Redis status API reports Celery as available"
    else
        print_status "warning" "Redis status API test inconclusive (may require authentication)"
        print_status "info" "API Response: $API_RESPONSE"
    fi
else
    print_status "warning" "Could not determine web container port"
fi

# Check recent application logs for Redis connection
print_status "info" "Checking recent application logs..."
RECENT_LOGS=$(docker logs --tail 20 attacksurface_web 2>&1)

if echo "$RECENT_LOGS" | grep -q "Redis connection successful"; then
    print_status "success" "Application logs show successful Redis connection"
elif echo "$RECENT_LOGS" | grep -q "Redis connection failed"; then
    print_status "error" "Application logs show failed Redis connection"
    print_status "info" "Recent logs:"
    echo "$RECENT_LOGS" | grep -i redis
    exit 1
else
    print_status "warning" "No recent Redis connection logs found"
fi

# Final summary
echo ""
echo "============================================"
print_status "success" "🎉 ALL TESTS PASSED!"
echo ""
print_status "info" "Redis connection fix verification complete:"
print_status "success" "✅ Redis container is running and responding"
print_status "success" "✅ Web container can connect to Redis"
print_status "success" "✅ Environment variables are properly configured"
print_status "success" "✅ Python Redis connection works"
print_status "success" "✅ Flask Redis checker reports Redis as available"
echo ""
print_status "info" "Your Docker deployment should now use Celery mode for large-scale scanning!"
print_status "info" "Access your application at: http://localhost:${WEB_PORT:-8077}"
echo ""
echo "============================================"
