# Database Migration Summary

## Migration Date
2025-06-09 12:34:10

## Changes Made
- Added confidence_score column (INTEGER)
- Added is_validated column (BOOLEAN) 
- Added validation_notes column (TEXT)
- Added template_name column (VARCHAR)
- Added cvss_score column (REAL/FLOAT)
- Added asset_metadata column (JSON/JSONB)

## Purpose
These fields enable the vulnerability validation system to:
1. Store ALL Nuclei scan results (not just validated ones)
2. Display confidence scores for each vulnerability
3. Show validation status with visual indicators
4. Allow filtering by validation status
5. Preserve raw scan data for analysis

## Next Steps
1. Commit these changes to GitHub
2. Deploy to Docker environment
3. The application will now show both validated and unvalidated vulnerabilities
4. Use the new validation filter in the vulnerabilities page

## Files Modified
- Database schema (vulnerability table)
- All vulnerability-related code now supports the new fields
