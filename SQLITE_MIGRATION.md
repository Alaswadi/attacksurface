# SQLite Migration for Docker

## Overview

We've updated the Docker configuration to use SQLite instead of PostgreSQL for consistency with local development. This eliminates database compatibility issues and simplifies deployment.

## Changes Made

### 1. Updated docker-compose.yml
- **Removed**: PostgreSQL service and dependencies
- **Added**: SQLite volume for persistent storage
- **Updated**: Environment variables to use SQLite
- **Simplified**: Dependencies (only Redis required now)

### 2. Updated Dockerfile
- **Removed**: PostgreSQL client libraries (`libpq-dev`)
- **Added**: SQLite libraries (`sqlite3`, `libsqlite3-dev`)
- **Updated**: Entrypoint script for SQLite initialization

### 3. Updated config.py
- **Modified**: Production config to use SQLite path compatible with Docker volumes

### 4. Added SQLite Initialization
- **Created**: `init_sqlite_docker.py` for proper database setup
- **Enhanced**: Database directory creation and table initialization

## Benefits

✅ **Consistency**: Same database engine (SQLite) for development and production
✅ **Simplicity**: No separate database service required
✅ **Reliability**: No more PostgreSQL-specific migration issues
✅ **Performance**: SQLite is sufficient for most attack surface management use cases
✅ **Portability**: Easier to backup and migrate (single file database)

## Migration Steps

### For Existing Deployments

1. **Backup your current data** (if needed):
   ```bash
   # Export data from PostgreSQL if you have important data
   docker exec attacksurface_db pg_dump -U attacksurface_user attacksurface > backup.sql
   ```

2. **Stop the current deployment**:
   ```bash
   docker-compose down
   ```

3. **Update your files** with the new configuration

4. **Start with SQLite**:
   ```bash
   docker-compose up -d
   ```

### For New Deployments

Simply use the updated `docker-compose.yml` - no additional steps required!

## File Structure

```
/app/
├── database/           # SQLite database storage (persistent volume)
│   └── attacksurface.db
├── data/              # Application data
└── logs/              # Application logs
```

## Environment Variables

The following environment variables are **no longer needed**:
- `DB_PASSWORD`
- `DATABASE_URL` (will use SQLite default)

Still required:
- `SECRET_KEY`
- `REDIS_PASSWORD`
- `WEB_PORT`
- `NGINX_PORT`

## Troubleshooting

### Database Issues
If you encounter database issues:

1. **Check database file permissions**:
   ```bash
   docker exec attacksurface_web ls -la /app/database/
   ```

2. **Reinitialize database**:
   ```bash
   docker exec attacksurface_web python init_sqlite_docker.py
   ```

3. **Check logs**:
   ```bash
   docker logs attacksurface_web
   ```

### Volume Issues
If the database doesn't persist:

1. **Check volume mounting**:
   ```bash
   docker volume ls
   docker volume inspect attacksurface_sqlite_data
   ```

2. **Recreate volumes if needed**:
   ```bash
   docker-compose down -v
   docker-compose up -d
   ```

## Enhanced Settings Compatibility

The enhanced settings functionality (user management, email configuration, organization settings) now works seamlessly with SQLite:

✅ All new tables created automatically
✅ No migration scripts needed
✅ Consistent behavior across environments
✅ Full functionality available immediately

## Performance Notes

SQLite is well-suited for attack surface management applications because:

- **Read-heavy workloads**: Most operations are data retrieval
- **Moderate concurrency**: Typical usage patterns don't require high concurrent writes
- **Data size**: Attack surface data is typically manageable in size
- **Simplicity**: No database server maintenance required

For very high-traffic deployments, PostgreSQL can still be used by setting the `DATABASE_URL` environment variable.
