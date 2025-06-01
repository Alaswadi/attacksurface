# Attack Surface Discovery - Docker Deployment Guide

## 🐳 **Quick Start**

### Prerequisites
- Docker Engine 20.10+
- Docker Compose 2.0+
- 4GB+ RAM
- 10GB+ disk space

### 1. Clone and Setup
```bash
git clone <your-repo>
cd attacksurface

# Copy environment file
cp .env.docker .env

# Edit environment variables
nano .env  # or vim .env
```

### 2. Generate SSL Certificates
```bash
# Linux/macOS
chmod +x generate-ssl.sh
./generate-ssl.sh

# Windows PowerShell
.\generate-ssl.ps1
```

### 3. Deploy
```bash
# Start all services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f web
```

### 4. Access Application
- **HTTP**: http://localhost:8088 (redirects to HTTPS)
- **HTTPS**: https://localhost:8443
- **Direct Web**: http://localhost:8077

## 🏗️ **Architecture**

### Services
- **nginx**: Reverse proxy with SSL termination
- **web**: Flask application (4 workers)
- **db**: PostgreSQL 15 database
- **redis**: Redis cache and session store
- **celery**: Background task worker

### Ports
- `8088`: HTTP (redirects to HTTPS)
- `8443`: HTTPS (main access)
- `8077`: Direct web access (optional)

### Volumes
- `postgres_data`: Database persistence
- `redis_data`: Redis persistence
- `app_data`: Application data
- `./logs`: Application and Nginx logs

## ⚙️ **Configuration**

### Environment Variables (.env)
```bash
# Security (REQUIRED - Change these!)
SECRET_KEY=your-super-secret-key-change-in-production
DB_PASSWORD=secure_database_password_change_me
REDIS_PASSWORD=redis_password_change_me

# Ports
WEB_PORT=8077
NGINX_PORT=8088
NGINX_SSL_PORT=8443

# Mail (Optional)
MAIL_SERVER=smtp.gmail.com
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
```

### SSL Certificates
- **Development**: Use generated self-signed certificates
- **Production**: Replace with CA-signed certificates
  ```bash
  # Copy your certificates
  cp your-cert.pem nginx/ssl/cert.pem
  cp your-key.pem nginx/ssl/key.pem
  ```

## 🚀 **Production Deployment**

### 1. Security Hardening
```bash
# Update environment variables
SECRET_KEY=$(openssl rand -base64 32)
DB_PASSWORD=$(openssl rand -base64 24)
REDIS_PASSWORD=$(openssl rand -base64 24)
```

### 2. SSL Configuration
```bash
# Use Let's Encrypt or commercial certificates
certbot certonly --standalone -d yourdomain.com
cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem nginx/ssl/cert.pem
cp /etc/letsencrypt/live/yourdomain.com/privkey.pem nginx/ssl/key.pem
```

### 3. Firewall Setup
```bash
# Allow only necessary ports
ufw allow 8088/tcp
ufw allow 8443/tcp
ufw enable
```

### 4. Monitoring
```bash
# Check service health
docker-compose exec web curl -f http://localhost:5000/api/dashboard/stats
docker-compose exec nginx wget -q --spider http://localhost/health
```

## 🔧 **Management Commands**

### Service Management
```bash
# Start services
docker-compose up -d

# Stop services
docker-compose down

# Restart specific service
docker-compose restart web

# View logs
docker-compose logs -f web
docker-compose logs nginx

# Scale web workers
docker-compose up -d --scale web=3
```

### Database Management
```bash
# Access database
docker-compose exec db psql -U attacksurface_user -d attacksurface

# Backup database
docker-compose exec db pg_dump -U attacksurface_user attacksurface > backup.sql

# Restore database
docker-compose exec -T db psql -U attacksurface_user attacksurface < backup.sql
```

### Application Management
```bash
# Access web container
docker-compose exec web bash

# Run Flask commands
docker-compose exec web flask db upgrade
docker-compose exec web flask shell

# View application logs
docker-compose logs -f web celery
```

## 📊 **Monitoring & Health Checks**

### Health Endpoints
- `http://localhost:8088/health`: Nginx health
- `http://localhost:8077/api/dashboard/stats`: Application health

### Log Locations
- Application: `./logs/app.log`
- Nginx Access: `./logs/nginx/access.log`
- Nginx Error: `./logs/nginx/error.log`

### Resource Monitoring
```bash
# Container stats
docker stats

# Service status
docker-compose ps

# Disk usage
docker system df
```

## 🔒 **Security Features**

### Network Security
- Internal Docker network isolation
- Rate limiting (API: 10 req/s, Login: 5 req/min)
- SSL/TLS encryption
- Security headers (HSTS, XSS protection, etc.)

### Application Security
- CSRF protection
- Password hashing (bcrypt)
- Session management
- Input validation

### Database Security
- Isolated database user
- Password authentication
- Network isolation

## 🚨 **Troubleshooting**

### Common Issues

#### SSL Certificate Errors
```bash
# Regenerate certificates
./generate-ssl.sh
docker-compose restart nginx
```

#### Database Connection Issues
```bash
# Check database status
docker-compose logs db
docker-compose exec db pg_isready -U attacksurface_user
```

#### Application Errors
```bash
# Check application logs
docker-compose logs web
docker-compose exec web flask shell
```

#### Permission Issues
```bash
# Fix log permissions
sudo chown -R $USER:$USER logs/
chmod 755 logs/
```

### Performance Tuning

#### Scale Web Workers
```bash
# Increase workers based on CPU cores
docker-compose up -d --scale web=4
```

#### Database Optimization
```bash
# Increase shared_buffers and work_mem
# Edit docker-compose.yml postgres command
```

## 📈 **Backup & Recovery**

### Automated Backup Script
```bash
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
docker-compose exec -T db pg_dump -U attacksurface_user attacksurface > "backup_${DATE}.sql"
tar -czf "attacksurface_backup_${DATE}.tar.gz" backup_${DATE}.sql logs/ nginx/ssl/
```

### Recovery Process
```bash
# Stop services
docker-compose down

# Restore database
docker-compose up -d db
docker-compose exec -T db psql -U attacksurface_user attacksurface < backup.sql

# Start all services
docker-compose up -d
```

## 🔄 **Updates & Maintenance**

### Application Updates
```bash
# Pull latest code
git pull

# Rebuild and restart
docker-compose build --no-cache
docker-compose up -d
```

### System Maintenance
```bash
# Clean up Docker
docker system prune -f
docker volume prune -f

# Update base images
docker-compose pull
docker-compose up -d
```

## 📞 **Support**

For issues and questions:
1. Check logs: `docker-compose logs`
2. Verify configuration: `.env` file
3. Test connectivity: Health endpoints
4. Review documentation: This guide

## 🎯 **Next Steps**

1. **Custom Domain**: Update Nginx configuration
2. **Real SSL**: Replace self-signed certificates
3. **Monitoring**: Add Prometheus/Grafana
4. **Backups**: Implement automated backup strategy
5. **CI/CD**: Set up deployment pipeline
