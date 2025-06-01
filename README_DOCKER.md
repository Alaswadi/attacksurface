# 🐳 Attack Surface Discovery - Docker Deployment

A complete Docker-based deployment solution for the Attack Surface Discovery SaaS application with Subfinder, Naabu, and Nuclei integration.

## 🚀 **Quick Start**

### Option 1: Automated Deployment (Recommended)

**Linux/macOS:**
```bash
chmod +x deploy.sh
./deploy.sh
```

**Windows PowerShell:**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
.\deploy.ps1
```

### Option 2: Manual Deployment

1. **Setup Environment**
   ```bash
   cp .env.docker .env
   # Edit .env with your configuration
   ```

2. **Generate SSL Certificates**
   ```bash
   # Linux/macOS
   ./generate-ssl.sh
   
   # Windows
   .\generate-ssl.ps1
   ```

3. **Deploy**
   ```bash
   docker-compose up -d
   ```

## 📋 **Prerequisites**

- **Docker Engine**: 20.10+
- **Docker Compose**: 2.0+
- **System Requirements**:
  - 4GB+ RAM
  - 10GB+ disk space
  - Ports 80, 443, 8080 available

## 🏗️ **Architecture Overview**

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Internet  │───▶│    Nginx    │───▶│  Flask App  │
│             │    │ (SSL/Proxy) │    │ (4 workers) │
└─────────────┘    └─────────────┘    └─────────────┘
                           │                   │
                           ▼                   ▼
                   ┌─────────────┐    ┌─────────────┐
                   │ PostgreSQL  │    │    Redis    │
                   │ (Database)  │    │ (Cache/Jobs)│
                   └─────────────┘    └─────────────┘
                                             │
                                             ▼
                                    ┌─────────────┐
                                    │   Celery    │
                                    │ (Background)│
                                    └─────────────┘
```

## 🔧 **Services**

| Service | Description | Port | Health Check |
|---------|-------------|------|--------------|
| **nginx** | Reverse proxy with SSL | 80, 443 | `/health` |
| **web** | Flask application | 8080 | `/api/dashboard/stats` |
| **db** | PostgreSQL database | 5432 | `pg_isready` |
| **redis** | Cache and session store | 6379 | `redis-cli ping` |
| **celery** | Background task worker | - | Process monitoring |

## 🌐 **Access Points**

- **Primary**: https://localhost (SSL with redirect)
- **HTTP**: http://localhost (redirects to HTTPS)
- **Direct**: http://localhost:8080 (bypass proxy)

## ⚙️ **Configuration**

### Environment Variables (.env)

```bash
# Security (REQUIRED - Change these!)
SECRET_KEY=your-super-secret-key-change-in-production
DB_PASSWORD=secure_database_password_change_me
REDIS_PASSWORD=redis_password_change_me

# Application
FLASK_CONFIG=production

# Ports
WEB_PORT=8080
NGINX_PORT=80
NGINX_SSL_PORT=443

# Database
DATABASE_URL=postgresql://attacksurface_user:${DB_PASSWORD}@db:5432/attacksurface

# Redis
CELERY_BROKER_URL=redis://:${REDIS_PASSWORD}@redis:6379/0
CELERY_RESULT_BACKEND=redis://:${REDIS_PASSWORD}@redis:6379/0

# Mail (Optional)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
```

## 🔒 **Security Features**

### Network Security
- **SSL/TLS**: Full encryption with configurable certificates
- **Rate Limiting**: API (10 req/s), Login (5 req/min)
- **Firewall**: Internal Docker network isolation
- **Headers**: HSTS, XSS protection, content type validation

### Application Security
- **Authentication**: Session-based with secure cookies
- **CSRF Protection**: All forms protected
- **Password Hashing**: bcrypt with salt
- **Input Validation**: Comprehensive form validation

### Infrastructure Security
- **Non-root Containers**: All services run as non-root users
- **Secret Management**: Environment-based configuration
- **Health Checks**: Automated service monitoring
- **Log Management**: Centralized logging with rotation

## 📊 **Monitoring & Logs**

### Health Endpoints
```bash
# Nginx health
curl http://localhost/health

# Application health
curl http://localhost:8080/api/dashboard/stats

# Database health
docker-compose exec db pg_isready -U attacksurface_user
```

### Log Locations
- **Application**: `./logs/app.log`
- **Nginx Access**: `./logs/nginx/access.log`
- **Nginx Error**: `./logs/nginx/error.log`
- **Container Logs**: `docker-compose logs [service]`

### Monitoring Commands
```bash
# Service status
docker-compose ps

# Resource usage
docker stats

# Live logs
docker-compose logs -f web

# System resources
docker system df
```

## 🛠️ **Management**

### Service Control
```bash
# Start all services
docker-compose up -d

# Stop all services
docker-compose down

# Restart specific service
docker-compose restart web

# Scale web workers
docker-compose up -d --scale web=3

# Update and restart
docker-compose build --no-cache && docker-compose up -d
```

### Database Management
```bash
# Access database
docker-compose exec db psql -U attacksurface_user -d attacksurface

# Backup database
docker-compose exec db pg_dump -U attacksurface_user attacksurface > backup.sql

# Restore database
docker-compose exec -T db psql -U attacksurface_user attacksurface < backup.sql

# Database migrations
docker-compose exec web flask db upgrade
```

### Application Management
```bash
# Access application container
docker-compose exec web bash

# Flask shell
docker-compose exec web flask shell

# Create admin user
docker-compose exec web flask create-admin

# Clear cache
docker-compose exec redis redis-cli -a $REDIS_PASSWORD FLUSHALL
```

## 🔄 **Backup & Recovery**

### Automated Backup
```bash
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
mkdir -p backups

# Database backup
docker-compose exec -T db pg_dump -U attacksurface_user attacksurface > "backups/db_${DATE}.sql"

# Application data backup
tar -czf "backups/app_data_${DATE}.tar.gz" logs/ nginx/ssl/

echo "Backup completed: backups/db_${DATE}.sql"
```

### Recovery Process
```bash
# Stop services
docker-compose down

# Start database only
docker-compose up -d db

# Wait for database
sleep 10

# Restore database
docker-compose exec -T db psql -U attacksurface_user attacksurface < backups/db_backup.sql

# Start all services
docker-compose up -d
```

## 🚨 **Troubleshooting**

### Common Issues

**SSL Certificate Errors**
```bash
# Regenerate certificates
./generate-ssl.sh  # or .\generate-ssl.ps1
docker-compose restart nginx
```

**Database Connection Issues**
```bash
# Check database logs
docker-compose logs db

# Test connection
docker-compose exec db pg_isready -U attacksurface_user
```

**Application Not Starting**
```bash
# Check application logs
docker-compose logs web

# Check environment
docker-compose exec web env | grep -E "(DATABASE|REDIS|SECRET)"
```

**Port Conflicts**
```bash
# Check port usage
netstat -tulpn | grep -E "(80|443|8080)"

# Change ports in .env
WEB_PORT=8081
NGINX_PORT=8080
```

### Performance Issues

**High Memory Usage**
```bash
# Reduce workers
# Edit docker-compose.yml: --workers 2

# Monitor usage
docker stats
```

**Slow Database**
```bash
# Check database performance
docker-compose exec db psql -U attacksurface_user -d attacksurface -c "SELECT * FROM pg_stat_activity;"
```

## 🔮 **Production Deployment**

### 1. Security Hardening
```bash
# Generate strong secrets
SECRET_KEY=$(openssl rand -base64 32)
DB_PASSWORD=$(openssl rand -base64 24)
REDIS_PASSWORD=$(openssl rand -base64 24)

# Update .env file with generated secrets
```

### 2. SSL Certificates
```bash
# Use Let's Encrypt
certbot certonly --standalone -d yourdomain.com

# Copy certificates
cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem nginx/ssl/cert.pem
cp /etc/letsencrypt/live/yourdomain.com/privkey.pem nginx/ssl/key.pem
```

### 3. Firewall Configuration
```bash
# Ubuntu/Debian
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable

# CentOS/RHEL
firewall-cmd --permanent --add-port=80/tcp
firewall-cmd --permanent --add-port=443/tcp
firewall-cmd --reload
```

### 4. Monitoring Setup
```bash
# Add monitoring stack (optional)
# Prometheus, Grafana, AlertManager
# See monitoring/docker-compose.monitoring.yml
```

## 📈 **Scaling**

### Horizontal Scaling
```bash
# Scale web workers
docker-compose up -d --scale web=4

# Load balancer configuration
# Nginx automatically load balances
```

### Vertical Scaling
```bash
# Increase resources in docker-compose.yml
services:
  web:
    deploy:
      resources:
        limits:
          memory: 2G
          cpus: '1.0'
```

## 🎯 **Next Steps**

1. **Custom Domain**: Update Nginx configuration
2. **Real SSL**: Replace self-signed certificates
3. **Monitoring**: Add Prometheus/Grafana stack
4. **CI/CD**: Implement automated deployment
5. **Backup Strategy**: Automate backup and recovery
6. **Tool Integration**: Replace simulation with real Subfinder/Naabu/Nuclei

## 📞 **Support**

- **Documentation**: See `DOCKER_DEPLOYMENT.md` for detailed guide
- **Logs**: Check `docker-compose logs` for issues
- **Health**: Monitor `/health` endpoints
- **Community**: GitHub issues and discussions

---

**🎉 Your Attack Surface Discovery SaaS is now ready for deployment!**
