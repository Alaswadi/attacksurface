# Email Notifications Docker Fix

This document explains how to fix the email notification settings issue in Docker deployments where the database migration for new notification fields was not applied.

## Problem

When using the consolidated email notification settings, you may encounter this error:

```
Failed to save notification settings: (sqlite3.OperationalError) no such column: email_notification_settings.notification_email
```

This happens because the Docker database doesn't have the new columns that were added for the consolidated notification settings feature.

## Solution

### Option 1: Fix Existing Docker Deployment (Recommended)

If you already have a running Docker deployment and want to fix it without losing data:

#### For Linux/macOS:
```bash
./fix_docker_email_notifications.sh
```

#### For Windows (PowerShell):
```powershell
.\fix_docker_email_notifications.ps1
```

This script will:
1. Copy the migration script to your running container
2. Run the database migration to add missing columns
3. Restart the web container to apply changes

### Option 2: Rebuild Docker Images

If you want to ensure the fix is included in future deployments:

1. **Pull the latest code** (which includes the migration):
   ```bash
   git pull origin main
   ```

2. **Rebuild and restart the containers**:
   ```bash
   docker-compose down
   docker-compose build --no-cache
   docker-compose up -d
   ```

### Option 3: Manual Migration

If the automated scripts don't work, you can run the migration manually:

1. **Copy the migration script to the container**:
   ```bash
   docker cp docker_migration_email_notifications.py attacksurface_web:/app/
   ```

2. **Run the migration**:
   ```bash
   docker exec attacksurface_web python docker_migration_email_notifications.py
   ```

3. **Restart the web container**:
   ```bash
   docker-compose restart web
   ```

## Verification

After applying the fix, verify that it works:

1. **Access your application** at your Docker deployment URL
2. **Go to Settings → Notifications**
3. **Configure both sections**:
   - Email Notifications (notification email, additional recipients, digest frequency)
   - Alert Severity Thresholds (critical, high, medium, low, info)
4. **Click "Save Notification Settings"**
5. **Verify success message** appears
6. **Refresh the page** and confirm all settings are preserved

## What the Fix Does

The migration adds these missing columns to the `email_notification_settings` table:

- `notification_email` (VARCHAR(255)) - Override email for notifications
- `additional_recipients` (TEXT) - Comma-separated additional email addresses
- `alert_critical` (BOOLEAN) - Whether to send critical severity alerts
- `alert_high` (BOOLEAN) - Whether to send high severity alerts
- `alert_medium` (BOOLEAN) - Whether to send medium severity alerts
- `alert_low` (BOOLEAN) - Whether to send low severity alerts
- `alert_info` (BOOLEAN) - Whether to send info severity alerts

## Future Deployments

For new Docker deployments after this fix:

1. The migration is now included in the Docker initialization process
2. New containers will automatically have the correct database schema
3. No manual intervention is required

## Troubleshooting

### Migration Script Fails

If the migration script fails:

1. **Check container logs**:
   ```bash
   docker-compose logs web
   ```

2. **Verify database file exists**:
   ```bash
   docker exec attacksurface_web ls -la /app/data/
   ```

3. **Check database permissions**:
   ```bash
   docker exec attacksurface_web ls -la /app/data/attacksurface.db
   ```

### Container Won't Start

If the container fails to start after the fix:

1. **Check logs for errors**:
   ```bash
   docker-compose logs web
   ```

2. **Restart all services**:
   ```bash
   docker-compose down
   docker-compose up -d
   ```

### Settings Still Don't Save

If settings still don't save after the migration:

1. **Verify the migration completed**:
   ```bash
   docker exec attacksurface_web sqlite3 /app/data/attacksurface.db ".schema email_notification_settings"
   ```

2. **Check for JavaScript errors** in browser console
3. **Verify API endpoint** is responding correctly

## Support

If you continue to experience issues:

1. Check the application logs: `docker-compose logs web`
2. Verify your Docker setup meets the requirements
3. Ensure you have the latest version of the code

## Files Involved

- `docker_migration_email_notifications.py` - Migration script for Docker
- `fix_docker_email_notifications.sh` - Automated fix script (Linux/macOS)
- `fix_docker_email_notifications.ps1` - Automated fix script (Windows)
- `init_sqlite_docker.py` - Updated to include migration for new deployments
- `Dockerfile` - Updated to include migration script
