# Simple Deployment Guide (No SSL)

## 🚀 **Simplified Configuration**

This deployment removes SSL certificates and uses a simpler port configuration to avoid conflicts.

### 🌐 **Port Configuration**

| Service | Purpose | Port | Access URL |
|---------|---------|------|------------|
| **Nginx HTTP** | HTTP proxy to Flask app | **8090** | http://localhost:8090 |
| **Flask Direct** | Direct web app access | **8077** | http://localhost:8077 |

**Note**: SSL/HTTPS has been removed to simplify deployment and avoid certificate issues.

### 🔧 **What Changed**

✅ **Removed SSL Configuration**
- No more SSL certificates required
- No HTTPS port (8443) 
- Simplified nginx configuration
- No file mounting issues

✅ **Changed Port 8080 → 8090**
- Avoids port conflict that was causing the error
- Uses port 8090 for HTTP traffic

✅ **Simplified Docker Configuration**
- Nginx configuration embedded in docker-compose.yml
- No external file mounting
- Uses standard nginx:alpine image

## 🚀 **Quick Deployment**

### **Option 1: Simple Deployment Script (Recommended)**

```bash
# Linux/macOS
chmod +x deploy-simple.sh
./deploy-simple.sh

# Windows PowerShell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
.\deploy-simple.ps1
```

### **Option 2: Manual Deployment**

```bash
# Stop existing containers
docker-compose down --remove-orphans

# Deploy with new configuration
docker-compose up -d --build
```

## 🌐 **Access Points**

After successful deployment:

- **🌐 Main Access**: http://localhost:8090 (Nginx proxy)
- **⚡ Direct Access**: http://localhost:8077 (Flask app)
- **🔍 Health Check**: http://localhost:8090/health

## 📝 **Environment Configuration**

Your `.env` file should contain:
```bash
# Port Configuration (SSL removed)
WEB_PORT=8077
NGINX_PORT=8090

# Security (Change these!)
SECRET_KEY=your-super-secret-key-change-in-production
DB_PASSWORD=secure_database_password_change_me
REDIS_PASSWORD=redis_password_change_me
```

## 🛡️ **Firewall Configuration**

Update your firewall for the new ports:

```bash
# Ubuntu/Debian
sudo ufw allow 8090/tcp  # HTTP
sudo ufw allow 8077/tcp  # Direct access (optional)

# CentOS/RHEL
sudo firewall-cmd --permanent --add-port=8090/tcp
sudo firewall-cmd --permanent --add-port=8077/tcp
sudo firewall-cmd --reload
```

## ✅ **Verification**

Test the deployment:

```bash
# Check service status
docker-compose ps

# Test HTTP access
curl http://localhost:8090

# Test direct Flask access
curl http://localhost:8077/api/dashboard/stats

# Test health endpoint
curl http://localhost:8090/health

# Check logs if needed
docker-compose logs nginx
docker-compose logs web
```

## 🔍 **Troubleshooting**

### **If Port 8090 is Also Busy**

Edit `.env` file and change the port:
```bash
NGINX_PORT=8091  # or any other available port
```

Then redeploy:
```bash
docker-compose down
docker-compose up -d
```

### **Check Port Usage**

```bash
# Linux/macOS
netstat -tulpn | grep -E "(8090|8077)"

# Windows
netstat -an | findstr ":8090"
netstat -an | findstr ":8077"
```

### **View Logs**

```bash
# All services
docker-compose logs

# Specific service
docker-compose logs nginx
docker-compose logs web
docker-compose logs db
```

## 🔄 **Adding SSL Later**

If you want to add SSL back later:

1. **Generate certificates**:
   ```bash
   ./generate-ssl.sh  # or .\generate-ssl.ps1
   ```

2. **Use the original docker-compose.yml** with SSL configuration

3. **Update ports** in .env:
   ```bash
   NGINX_PORT=8090
   NGINX_SSL_PORT=8443
   ```

## 📊 **Service Architecture**

```
Internet → Nginx (Port 8090) → Flask App (Port 5000)
                                     ↓
                              PostgreSQL + Redis
```

**Simplified Flow:**
- HTTP requests to port 8090 → Nginx → Flask app
- Direct requests to port 8077 → Flask app
- No SSL/HTTPS complexity

## 🎯 **Benefits of Simple Deployment**

✅ **No SSL Certificate Issues**
- No file mounting problems
- No certificate generation required
- Simpler configuration

✅ **Fewer Port Conflicts**
- Uses port 8090 instead of 8080
- Only 2 ports instead of 3

✅ **Easier Troubleshooting**
- Embedded nginx configuration
- Standard Docker images
- Clear error messages

✅ **Faster Deployment**
- No certificate generation time
- Simpler build process
- Fewer dependencies

## 🔐 **Security Note**

This deployment uses HTTP only. For production use:

1. **Add SSL certificates** from a trusted CA
2. **Use HTTPS** for all traffic
3. **Configure proper firewall rules**
4. **Update default passwords**

---

**✅ Simplified deployment ready!**

Run `./deploy-simple.sh` to deploy your Attack Surface Discovery application without SSL complexity.
