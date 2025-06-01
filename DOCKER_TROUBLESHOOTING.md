# Docker Deployment Troubleshooting Guide

## 🚨 **Common Error: Nginx Configuration Mount Issue**

### **Error Message:**
```
Error response from daemon: failed to create task for container: failed to create shim task: OCI runtime create failed: runc create failed: unable to start container process: error during container init: error mounting "/data/coolify/applications/.../nginx/nginx.conf" to rootfs at "/etc/nginx/nginx.conf": create mountpoint for /etc/nginx/nginx.conf mount: cannot create subdirectories in "/var/lib/docker/overlay2/.../merged/etc/nginx/nginx.conf": not a directory: unknown: Are you trying to mount a directory onto a file (or vice-versa)? Check if the specified host path exists and is the expected type
```

### **Root Cause:**
This error occurs when Docker tries to mount the nginx configuration file but encounters path or permission issues.

## 🔧 **Solutions**

### **Solution 1: Use Simple Configuration (Recommended)**

Use the simplified docker-compose configuration without file mounting:

```bash
# Use the simple configuration
cp docker-compose.simple.yml docker-compose.yml

# Deploy
docker-compose up -d
```

### **Solution 2: Fix File Permissions**

```bash
# Ensure nginx directory and files exist
mkdir -p nginx/ssl logs/nginx

# Set proper permissions
chmod 644 nginx/nginx.conf
chmod -R 755 nginx/
chmod 600 nginx/ssl/key.pem 2>/dev/null || true

# Try deployment again
docker-compose up -d
```

### **Solution 3: Use Built Nginx Image**

The original docker-compose.yml now builds a custom nginx image:

```bash
# Generate SSL certificates first
./generate-ssl.sh  # or .\generate-ssl.ps1

# Build and deploy
docker-compose build nginx
docker-compose up -d
```

### **Solution 4: Manual File Creation**

```bash
# Create all required directories
mkdir -p nginx/ssl logs/nginx

# Ensure nginx.conf exists
if [ ! -f nginx/nginx.conf ]; then
    echo "Nginx configuration file missing!"
    echo "Please ensure nginx/nginx.conf exists"
    exit 1
fi

# Generate SSL certificates if missing
if [ ! -f nginx/ssl/cert.pem ]; then
    ./generate-ssl.sh
fi

# Deploy
docker-compose up -d
```

## 🔍 **Diagnostic Commands**

### **Check File Existence**
```bash
# Verify all required files exist
ls -la nginx/
ls -la nginx/ssl/
ls -la logs/

# Check file permissions
stat nginx/nginx.conf
stat nginx/ssl/cert.pem
stat nginx/ssl/key.pem
```

### **Check Docker Environment**
```bash
# Check Docker version
docker --version
docker-compose --version

# Check available space
df -h

# Check Docker daemon status
docker info
```

### **Validate Configuration**
```bash
# Test nginx configuration syntax
docker run --rm -v $(pwd)/nginx/nginx.conf:/etc/nginx/nginx.conf:ro nginx:alpine nginx -t

# Test docker-compose syntax
docker-compose config
```

## 🛠️ **Quick Fix Script**

Create and run this fix script:

```bash
#!/bin/bash
# fix-docker-deployment.sh

echo "🔧 Fixing Docker deployment issues..."

# Create required directories
mkdir -p nginx/ssl logs/nginx

# Check if nginx.conf exists
if [ ! -f nginx/nginx.conf ]; then
    echo "❌ nginx/nginx.conf not found!"
    echo "Please ensure the nginx configuration file exists"
    exit 1
fi

# Generate SSL certificates if missing
if [ ! -f nginx/ssl/cert.pem ] || [ ! -f nginx/ssl/key.pem ]; then
    echo "🔐 Generating SSL certificates..."
    if command -v openssl >/dev/null 2>&1; then
        ./generate-ssl.sh
    else
        echo "⚠️  OpenSSL not found. Creating placeholder certificates..."
        touch nginx/ssl/cert.pem nginx/ssl/key.pem
    fi
fi

# Set proper permissions
chmod 644 nginx/nginx.conf
chmod -R 755 nginx/
chmod 600 nginx/ssl/key.pem 2>/dev/null || true

# Clean up any existing containers
echo "🧹 Cleaning up existing containers..."
docker-compose down 2>/dev/null || true

# Use simple configuration if original fails
echo "🚀 Attempting deployment..."
if ! docker-compose up -d; then
    echo "⚠️  Original configuration failed. Trying simple configuration..."
    cp docker-compose.simple.yml docker-compose.yml
    docker-compose up -d
fi

echo "✅ Deployment fix completed!"
```

## 🌐 **Alternative Access Methods**

If nginx proxy fails, you can still access the application directly:

```bash
# Direct Flask app access
curl http://localhost:8077/api/dashboard/stats

# Check if web container is running
docker-compose ps web

# Access web container directly
docker-compose exec web curl http://localhost:5000/api/dashboard/stats
```

## 📋 **Environment-Specific Solutions**

### **Coolify Platform**
If you're using Coolify, the paths might be different:

```bash
# Check Coolify-specific paths
ls -la /data/coolify/applications/*/nginx/

# Use absolute paths in docker-compose.yml
volumes:
  - /absolute/path/to/nginx/nginx.conf:/etc/nginx/nginx.conf:ro
```

### **Docker Swarm**
For Docker Swarm deployments:

```bash
# Use configs instead of bind mounts
docker config create nginx_conf nginx/nginx.conf
docker service create --config source=nginx_conf,target=/etc/nginx/nginx.conf nginx:alpine
```

### **Kubernetes**
For Kubernetes deployments:

```yaml
# Use ConfigMaps
apiVersion: v1
kind: ConfigMap
metadata:
  name: nginx-config
data:
  nginx.conf: |
    # nginx configuration content here
```

## 🔄 **Recovery Steps**

If deployment completely fails:

1. **Stop all services:**
   ```bash
   docker-compose down
   docker system prune -f
   ```

2. **Use minimal configuration:**
   ```bash
   cp docker-compose.simple.yml docker-compose.yml
   ```

3. **Deploy step by step:**
   ```bash
   docker-compose up -d db redis
   sleep 10
   docker-compose up -d web
   sleep 10
   docker-compose up -d nginx
   ```

4. **Check logs:**
   ```bash
   docker-compose logs nginx
   docker-compose logs web
   ```

## 📞 **Getting Help**

If issues persist:

1. **Collect diagnostic information:**
   ```bash
   docker-compose logs > deployment-logs.txt
   docker info > docker-info.txt
   ls -la nginx/ > file-listing.txt
   ```

2. **Check system resources:**
   ```bash
   free -h
   df -h
   docker system df
   ```

3. **Verify network connectivity:**
   ```bash
   docker-compose exec web ping db
   docker-compose exec web ping redis
   ```

The simple configuration (`docker-compose.simple.yml`) should work in most environments and avoids file mounting issues entirely.
