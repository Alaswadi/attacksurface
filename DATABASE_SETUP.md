# Database Setup Guide

## 🗄️ **Database Initialization Fixed**

The "relation 'user' does not exist" error has been resolved by adding automatic database initialization to the Docker deployment.

### 🔧 **What Was Fixed**

**Original Error:**
```
sqlalchemy.exc.ProgrammingError: (psycopg2.errors.UndefinedTable) relation "user" does not exist
```

**Root Cause:** Database tables were not created when the Flask application started in Docker.

**Solution:** Added automatic database initialization that:
- ✅ Creates all database tables
- ✅ Creates sample data with admin user
- ✅ Runs automatically on container startup

### 📝 **Files Added/Updated**

1. **`init_db.py`** - Database initialization script
2. **`Dockerfile`** - Updated with entrypoint script
3. **`setup-database.sh`** - Manual database setup script
4. **`setup-database.ps1`** - Windows PowerShell version

### 🚀 **Automatic Database Setup**

The database is now automatically initialized when you deploy:

```bash
# Deploy with automatic database setup
./deploy-simple.sh  # or .\deploy-simple.ps1
```

**What happens automatically:**
1. 🐳 Docker containers start
2. ⏳ Web container waits for database (15 seconds)
3. 🔄 Database tables are created
4. 👤 Admin user is created (username: admin, password: password)
5. 📊 Sample data is added (assets, vulnerabilities, alerts)
6. 🌐 Web server starts

### 🛠️ **Manual Database Setup**

If you need to manually initialize or reset the database:

```bash
# Linux/macOS
chmod +x setup-database.sh
./setup-database.sh

# Windows PowerShell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
.\setup-database.ps1

# Or run directly in container
docker-compose exec web python init_db.py
```

### 👤 **Default Login Credentials**

After database initialization:
- **Username**: `admin`
- **Email**: `admin@attacksurface.com`
- **Password**: `password`

**⚠️ Important**: Change the default password in production!

### 📊 **Sample Data Created**

The initialization script creates:

**Assets (10 items):**
- Domains: example.com
- Subdomains: api.example.com, admin.example.com, staging.example.com
- IP Addresses: 192.168.1.100, 10.0.0.50
- Cloud Resources: EC2-web-server-1, S3-backup-bucket
- Services: nginx-service, postgresql-service

**Vulnerabilities (6 items):**
- SSL Certificate Expiring Soon (Critical)
- Open Database Port (High)
- Outdated Software Version (Medium)
- Missing Security Headers (Low)
- Weak SSL Configuration (Medium)
- Directory Listing Enabled (Low)

**Alerts (5 items):**
- Critical SSL certificate expiry
- High severity open database port
- Medium severity outdated software
- Info about new asset discovery
- Low severity missing security header

### 🔍 **Verification**

Check if database setup was successful:

```bash
# Check if admin user exists
docker-compose exec db psql -U attacksurface_user -d attacksurface -c "SELECT username, email FROM \"user\";"

# Check asset count
docker-compose exec db psql -U attacksurface_user -d attacksurface -c "SELECT COUNT(*) FROM asset;"

# Check vulnerability count
docker-compose exec db psql -U attacksurface_user -d attacksurface -c "SELECT COUNT(*) FROM vulnerability;"

# Test web application
curl http://localhost:8077/api/dashboard/stats
```

### 🚨 **Troubleshooting Database Issues**

#### **Issue: Database Connection Failed**
```bash
# Check if database container is running
docker-compose ps db

# Check database logs
docker-compose logs db

# Test database connection
docker-compose exec db pg_isready -U attacksurface_user
```

#### **Issue: Tables Not Created**
```bash
# Manually run database initialization
docker-compose exec web python init_db.py

# Check if tables exist
docker-compose exec db psql -U attacksurface_user -d attacksurface -c "\dt"
```

#### **Issue: Permission Denied**
```bash
# Check database user permissions
docker-compose exec db psql -U attacksurface_user -d attacksurface -c "SELECT current_user;"

# Reset database (WARNING: This deletes all data)
docker-compose down -v
docker-compose up -d
```

#### **Issue: Web Container Fails to Start**
```bash
# Check web container logs
docker-compose logs web

# Check if database is ready
docker-compose exec db pg_isready -U attacksurface_user -d attacksurface

# Restart web container
docker-compose restart web
```

### 🔄 **Database Reset**

To completely reset the database:

```bash
# Stop services and remove volumes (WARNING: Deletes all data)
docker-compose down -v

# Start services (will recreate database)
docker-compose up -d

# Or use the simple deployment script
./deploy-simple.sh
```

### 📋 **Database Schema**

The application creates these tables:
- **user** - User accounts
- **organization** - User organizations
- **asset** - Discovered assets (domains, IPs, etc.)
- **vulnerability** - Security vulnerabilities
- **alert** - Security alerts and notifications
- **scan_result** - Scan results and history

### 🔐 **Security Notes**

1. **Change Default Password**: Update admin password after first login
2. **Database Credentials**: Update database passwords in `.env` file
3. **Production Setup**: Use strong passwords and proper SSL certificates
4. **Backup Strategy**: Implement regular database backups

### 📈 **Next Steps**

1. **Deploy**: Run `./deploy-simple.sh`
2. **Login**: Access http://localhost:8090 with admin/password
3. **Explore**: Check the dashboard with sample data
4. **Customize**: Add your own assets and configure scans
5. **Secure**: Change default passwords and configure SSL

---

**✅ Database setup is now automated and working!**

The Flask application will automatically create all necessary tables and sample data when deployed.
