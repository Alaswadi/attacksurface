# Local Database Migration Guide

## Problem
The application is crashing with this error:
```
sqlalchemy.exc.ProgrammingError: column vulnerability.confidence_score does not exist
```

## Solution: Migrate Database Locally

Instead of trying to auto-migrate in production, we'll migrate the database locally and then push the changes to GitHub.

## Steps to Fix

### 1. Run Local Migration

```bash
# In your local project directory
python migrate_db_locally.py
```

This script will:
- ✅ Add the missing database columns
- ✅ Update existing vulnerabilities with default values  
- ✅ Verify the migration worked
- ✅ Create a migration summary

### 2. Commit Changes to GitHub

```bash
# Add all changes
git add .

# Commit the migration
git commit -m "Add vulnerability validation database fields

- Added confidence_score, is_validated, validation_notes columns
- Added template_name, cvss_score, asset_metadata columns  
- Updated existing vulnerabilities with default values
- Enables display of all Nuclei scan results (validated and unvalidated)"

# Push to GitHub
git push
```

### 3. Deploy to Docker

Your Docker environment will now use the updated database schema and the application will work without errors.

## What the Migration Adds

| Column | Type | Purpose |
|--------|------|---------|
| `confidence_score` | INTEGER | Nuclei confidence score (0-100) |
| `is_validated` | BOOLEAN | Whether vulnerability passed validation |
| `validation_notes` | TEXT | Notes about validation status |
| `template_name` | VARCHAR | Nuclei template that found vulnerability |
| `cvss_score` | REAL | CVSS score if available |
| `asset_metadata` | JSON | Raw scan data for analysis |

## Benefits After Migration

✅ **No More Database Errors**: The `confidence_score does not exist` error will be fixed

✅ **Complete Vulnerability Visibility**: See ALL Nuclei scan results, not just validated ones

✅ **Enhanced UI Features**:
- Validation status badges (Validated/Unvalidated)
- Confidence score display
- Template name tags
- Validation filter options

✅ **Better Security Insights**:
- Previously hidden low-confidence vulnerabilities are now visible
- Clear distinction between validated and unvalidated findings
- Raw scan data preserved for analysis

## Verification

After migration, you can verify it worked by:

1. **Check the migration output** - Should show "Migration successful!"
2. **Look for MIGRATION_SUMMARY.md** - Created automatically
3. **Test locally** - Run the app locally to ensure no errors
4. **Deploy and test** - The Docker app should work without database errors

## Files Modified

- `models.py` - Added new vulnerability fields
- `app.py` - Updated to use new fields
- `tasks.py` - Modified to store all vulnerabilities
- `templates/vulnerabilities.html` - Enhanced UI with validation status
- `routes/api.py` - Updated API responses

## Troubleshooting

If the migration fails:

1. **Check database permissions** - Ensure you can modify the database
2. **Backup first** - Make a backup of your database before running
3. **Check logs** - The script provides detailed output about what failed
4. **Manual SQL** - Use the SQL files in `migrations/` folder as backup

## Expected Result

After completing these steps:

🎉 **Application starts without errors**
🎉 **Vulnerabilities page loads successfully** 
🎉 **Both validated and unvalidated vulnerabilities are displayed**
🎉 **New filtering and display features are active**

The specific vulnerabilities mentioned in your request will now be visible:
- "Web Configuration File - Detect" (confidence: 63%, severity: info)
- "Clockwork PHP page exposure" (confidence: 90%, severity: high)

Both will appear with "Unvalidated" badges, allowing you to review and manually validate them as needed.
