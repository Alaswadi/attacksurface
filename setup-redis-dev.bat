@echo off
title Redis Setup for Attack Surface Management - Development Mode

echo.
echo ================================================================
echo  Redis Setup for Attack Surface Management Application
echo  Development Mode - Large-Scale Scanning with Celery
echo ================================================================
echo.

REM Check if Docker is running
echo [1/5] Checking Docker availability...
docker info >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Docker is not running or not installed.
    echo.
    echo Please install Docker Desktop and start it:
    echo https://www.docker.com/products/docker-desktop
    echo.
    pause
    exit /b 1
)
echo ✅ Docker is running

REM Check if Redis container already exists
echo.
echo [2/5] Checking for existing Redis container...
docker ps -a --filter "name=redis-dev" --format "{{.Names}}" | findstr "redis-dev" >nul 2>&1
if %errorlevel% equ 0 (
    echo ⚠️  Redis container 'redis-dev' already exists
    echo.
    echo Stopping and removing existing container...
    docker stop redis-dev >nul 2>&1
    docker rm redis-dev >nul 2>&1
    echo ✅ Cleaned up existing container
)

REM Start Redis container
echo.
echo [3/5] Starting Redis container...
docker run -d --name redis-dev -p 6379:6379 redis:latest >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Failed to start Redis container
    echo.
    echo Troubleshooting:
    echo - Check if port 6379 is already in use
    echo - Ensure Docker has sufficient resources
    echo.
    pause
    exit /b 1
)
echo ✅ Redis container started successfully

REM Wait for Redis to be ready
echo.
echo [4/5] Waiting for Redis to be ready...
timeout /t 3 /nobreak >nul

REM Test Redis connection
echo.
echo [5/5] Testing Redis connection...
docker exec redis-dev redis-cli ping >nul 2>&1
if %errorlevel% equ 0 (
    echo ✅ Redis is running and responding to ping
) else (
    echo ❌ Redis is not responding properly
    echo.
    echo Checking container logs:
    docker logs redis-dev
    pause
    exit /b 1
)

echo.
echo ================================================================
echo  🎉 Redis Setup Complete!
echo ================================================================
echo.
echo ✅ Redis is now running at: localhost:6379
echo ✅ Container name: redis-dev
echo ✅ Ready for Celery large-scale scanning
echo.
echo 📋 Useful Commands:
echo   Start Redis:    docker start redis-dev
echo   Stop Redis:     docker stop redis-dev
echo   Redis CLI:      docker exec -it redis-dev redis-cli
echo   View logs:      docker logs redis-dev
echo   Remove:         docker stop redis-dev ^&^& docker rm redis-dev
echo.
echo 🚀 You can now start the Flask application:
echo   python app.py
echo.
echo 🌐 Then access large-scale scanning at:
echo   http://localhost:5000/large-scale-scanning
echo.
echo ================================================================

pause
