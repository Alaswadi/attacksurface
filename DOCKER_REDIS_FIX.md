# 🐳 Docker Redis Connection Fix

## 🎯 **Problem Identified**

Your Docker logs show:
```
WARNING:utils.redis_checker:❌ Redis connection failed: Error 111 connecting to localhost:6379. Connection refused.
```

**Root Cause**: The Flask application is trying to connect to `localhost:6379` instead of `redis:6379` (the Docker service name).

## ✅ **Solution Applied**

I've updated the Redis connection logic to automatically use environment variables in Docker:

### **1. Updated Redis Checker (`utils/redis_checker.py`)**
```python
def check_redis_availability(redis_url=None):
    import os
    
    # Use environment variable if available (Docker), otherwise default to localhost
    if redis_url is None:
        redis_url = os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379/0')
    
    checker = RedisChecker(redis_url)
    is_available = checker.check_connection()
    return is_available, checker.error_message
```

### **2. Updated App Configuration (`app.py`)**
```python
# Initialize Redis checker with environment-aware URL
import os
broker_url = (
    app.config.get('broker_url') or 
    os.environ.get('CELERY_BROKER_URL') or 
    'redis://localhost:6379/0'
)
redis_available = initialize_redis_checker(broker_url)
```

## 🔧 **Docker Configuration Verification**

Your `docker-compose.yml` is correctly configured:

### **Redis Service**
```yaml
redis:
  image: redis:7-alpine
  container_name: attacksurface_redis
  command: redis-server --appendonly yes --requirepass ${REDIS_PASSWORD:-redis_password_change_me}
```

### **Web Service Environment**
```yaml
web:
  environment:
    - CELERY_BROKER_URL=redis://:${REDIS_PASSWORD:-redis_password_change_me}@redis:6379/0
    - CELERY_RESULT_BACKEND=redis://:${REDIS_PASSWORD:-redis_password_change_me}@redis:6379/0
```

### **Celery Worker Environment**
```yaml
celery:
  environment:
    - CELERY_BROKER_URL=redis://:${REDIS_PASSWORD:-redis_password_change_me}@redis:6379/0
    - CELERY_RESULT_BACKEND=redis://:${REDIS_PASSWORD:-redis_password_change_me}@redis:6379/0
```

## 🧪 **Testing the Fix**

### **1. Test Redis Connection in Docker**
```bash
# Run the Docker Redis test
docker exec attacksurface_web python test_docker_redis.py

# Expected output:
# ✅ Redis ping successful!
# ✅ All Redis tests passed!
# 🎉 ALL TESTS PASSED - Redis is ready for large-scale scanning!
```

### **2. Test Large-Scale Scanning**
```bash
# Access the application
http://localhost:8077/large-scale-scanning

# Try scanning a domain
# Should now use Celery mode instead of fallback mode
```

### **3. Check Application Logs**
```bash
# Check web container logs
docker logs attacksurface_web

# Should see:
# ✅ Redis connection successful: redis://:***@redis:6379/0
# (instead of connection failed)
```

## 🔍 **Troubleshooting Commands**

### **Check Redis Container Status**
```bash
# Check if Redis is running
docker ps | grep redis

# Check Redis logs
docker logs attacksurface_redis

# Test Redis directly
docker exec attacksurface_redis redis-cli ping
# Should return: PONG
```

### **Check Network Connectivity**
```bash
# Test network connectivity from web to redis
docker exec attacksurface_web ping redis

# Test Redis connection from web container
docker exec attacksurface_web redis-cli -h redis -p 6379 ping
```

### **Check Environment Variables**
```bash
# Check environment variables in web container
docker exec attacksurface_web env | grep CELERY

# Should show:
# CELERY_BROKER_URL=redis://:password@redis:6379/0
# CELERY_RESULT_BACKEND=redis://:password@redis:6379/0
```

## 🚀 **Deployment Steps**

### **1. Rebuild and Deploy**
```bash
# Stop current containers
docker-compose down

# Rebuild with fixes
docker-compose build --no-cache

# Start with fresh containers
docker-compose up -d

# Check logs
docker-compose logs -f web
```

### **2. Verify Redis Connection**
```bash
# Test Redis connection
docker exec attacksurface_web python test_docker_redis.py

# Check application startup logs
docker logs attacksurface_web | grep -i redis
```

### **3. Test Large-Scale Scanning**
```bash
# Access application
curl http://localhost:8077/api/system/redis-status

# Should return:
# {"success": true, "celery_available": true, "redis": {"status": "available"}}
```

## 📊 **Expected Results After Fix**

### **Before Fix (Broken)**
```
WARNING:utils.redis_checker:❌ Redis connection failed: Error 111 connecting to localhost:6379. Connection refused.
INFO:root:🔄 Using fallback mode for deep scan of example.com
```

### **After Fix (Working)**
```
INFO:root:🔍 Redis connection check using URL: redis://:***@redis:6379/0
INFO:root:✅ Redis connection successful: redis://:***@redis:6379/0
INFO:root:🚀 Started large-scale deep scan for example.com (Task ID: abc123-def456)
```

## 🎯 **Key Changes Made**

1. **✅ Environment Variable Priority**: Redis checker now uses `CELERY_BROKER_URL` environment variable first
2. **✅ Docker Service Name**: Connects to `redis:6379` instead of `localhost:6379` in Docker
3. **✅ Password Authentication**: Properly handles Redis password from environment variables
4. **✅ Fallback Compatibility**: Still works with `localhost:6379` for local development

## 🔧 **Manual Verification**

If you want to manually verify the fix:

### **1. Check Current Redis URL**
```bash
docker exec attacksurface_web python -c "
import os
print('CELERY_BROKER_URL:', os.environ.get('CELERY_BROKER_URL', 'Not set'))
print('Expected format: redis://:password@redis:6379/0')
"
```

### **2. Test Redis Connection**
```bash
docker exec attacksurface_web python -c "
import redis
import os
url = os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379/0')
print(f'Testing: {url}')
r = redis.from_url(url)
print('Ping result:', r.ping())
"
```

### **3. Test Large-Scale Scanning API**
```bash
# Test the API endpoint
curl -X POST http://localhost:8077/api/scan/large-domain \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "scan_type": "quick"}' \
  -b "session=your_session_cookie"

# Should return mode: "celery" instead of "fallback"
```

## 🎉 **Success Indicators**

After applying the fix, you should see:

1. **✅ No more "Connection refused" errors** in Docker logs
2. **✅ Redis connection successful** messages in application logs
3. **✅ Celery mode activated** instead of fallback mode for large-scale scanning
4. **✅ Background tasks working** with real Celery workers
5. **✅ Redis status API** returning `"celery_available": true`

The fix ensures your Docker deployment uses the correct Redis service name and authentication, enabling full Celery functionality for large-scale domain scanning! 🚀
