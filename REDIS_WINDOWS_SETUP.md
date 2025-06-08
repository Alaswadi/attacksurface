# Redis Setup for Windows Development

## 🎯 **Quick Setup Options**

### **Option 1: Docker (Recommended)**
```bash
# Pull and run Redis container
docker run -d --name redis-dev -p 6379:6379 redis:latest

# Verify Redis is running
docker ps | grep redis

# Test connection
docker exec -it redis-dev redis-cli ping
# Should return: PONG
```

### **Option 2: Windows Subsystem for Linux (WSL)**
```bash
# Install Redis in WSL
sudo apt update
sudo apt install redis-server

# Start Redis
sudo service redis-server start

# Test connection
redis-cli ping
# Should return: PONG
```

### **Option 3: Native Windows Installation**
```bash
# Download Redis for Windows from:
# https://github.com/microsoftarchive/redis/releases

# Or use Chocolatey
choco install redis-64

# Or use Windows Package Manager
winget install Redis.Redis
```

### **Option 4: Redis Cloud (Free Tier)**
```bash
# Sign up at: https://redis.com/try-free/
# Get connection string like: redis://username:password@host:port
# Update config.py with cloud Redis URL
```

## 🚀 **Quick Start Commands**

### **Start Redis (Docker)**
```bash
# Start Redis container
docker start redis-dev

# Stop Redis container
docker stop redis-dev

# View Redis logs
docker logs redis-dev
```

### **Test Redis Connection**
```bash
# Test from command line
redis-cli ping

# Test from Python
python -c "import redis; r=redis.Redis(); print(r.ping())"
```

## 🔧 **Configuration for Development**

### **Update config.py for local Redis**
```python
# For Docker Redis
CELERY_BROKER_URL = 'redis://localhost:6379/0'
CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'

# For Redis Cloud
CELERY_BROKER_URL = 'redis://username:password@host:port/0'
CELERY_RESULT_BACKEND = 'redis://username:password@host:port/0'
```

## 📊 **Verify Setup**

### **Check Redis Status**
```bash
# Docker
docker exec -it redis-dev redis-cli info server

# Native/WSL
redis-cli info server
```

### **Test Celery Connection**
```bash
# Start Celery worker (in project directory)
celery -A celery_app.celery worker --loglevel=info

# Should show: "Connected to redis://localhost:6379/0"
```

## 🎯 **Recommended Setup for Development**

1. **Use Docker Redis** (easiest and most reliable)
2. **Start Redis before running the application**
3. **Use fallback mode when Redis is unavailable**

### **Complete Setup Script**
```bash
# setup-redis-dev.bat
@echo off
echo Starting Redis for development...

# Check if Docker is running
docker info >nul 2>&1
if %errorlevel% neq 0 (
    echo Docker is not running. Please start Docker Desktop.
    pause
    exit /b 1
)

# Start Redis container
docker run -d --name redis-dev -p 6379:6379 redis:latest 2>nul
if %errorlevel% neq 0 (
    echo Redis container already exists, starting it...
    docker start redis-dev
)

# Wait for Redis to be ready
timeout /t 3 /nobreak >nul

# Test connection
docker exec redis-dev redis-cli ping >nul 2>&1
if %errorlevel% equ 0 (
    echo ✅ Redis is running and ready!
    echo 🌐 Redis available at: localhost:6379
    echo 🔧 You can now start the Flask application
) else (
    echo ❌ Redis failed to start properly
)

pause
```
