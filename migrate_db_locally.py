#!/usr/bin/env python3
"""
Local database migration script for vulnerability validation fields
Run this locally, then commit the changes to GitHub
"""

import os
import sys
from datetime import datetime

def run_local_migration():
    """Run the database migration locally"""
    try:
        print("🔄 Starting local database migration...")
        
        # Import Flask app and database
        from app import create_app, db
        from models import Vulnerability
        from sqlalchemy import text, inspect
        
        app = create_app()
        
        with app.app_context():
            # Check current database type
            engine_name = db.engine.name
            print(f"📋 Database engine: {engine_name}")
            
            # Check if columns already exist
            inspector = inspect(db.engine)
            existing_columns = [col['name'] for col in inspector.get_columns('vulnerability')]
            print(f"📋 Current columns: {len(existing_columns)} total")
            
            # Define new columns based on database type
            if engine_name == 'postgresql':
                new_columns = [
                    ('confidence_score', 'INTEGER DEFAULT 0'),
                    ('is_validated', 'BOOLEAN DEFAULT FALSE'),
                    ('validation_notes', 'TEXT'),
                    ('template_name', 'VARCHAR(255)'),
                    ('cvss_score', 'REAL'),
                    ('asset_metadata', 'JSONB')
                ]
            else:  # SQLite
                new_columns = [
                    ('confidence_score', 'INTEGER DEFAULT 0'),
                    ('is_validated', 'BOOLEAN DEFAULT 0'),
                    ('validation_notes', 'TEXT'),
                    ('template_name', 'VARCHAR(255)'),
                    ('cvss_score', 'REAL'),
                    ('asset_metadata', 'JSON')
                ]
            
            # Add new columns if they don't exist
            columns_added = 0
            for column_name, column_def in new_columns:
                if column_name not in existing_columns:
                    print(f"➕ Adding column: {column_name}")
                    try:
                        if engine_name == 'postgresql':
                            # PostgreSQL syntax
                            sql = f"""
                            DO $$ 
                            BEGIN 
                                IF NOT EXISTS (
                                    SELECT 1 FROM information_schema.columns 
                                    WHERE table_name = 'vulnerability' 
                                    AND column_name = '{column_name}'
                                    AND table_schema = 'public'
                                ) THEN
                                    ALTER TABLE vulnerability ADD COLUMN {column_name} {column_def};
                                END IF;
                            END $$;
                            """
                        else:
                            # SQLite syntax
                            sql = f"ALTER TABLE vulnerability ADD COLUMN {column_name} {column_def};"
                        
                        db.session.execute(text(sql))
                        db.session.commit()
                        print(f"✅ Successfully added column: {column_name}")
                        columns_added += 1
                    except Exception as e:
                        print(f"❌ Failed to add column {column_name}: {str(e)}")
                        db.session.rollback()
                        continue
                else:
                    print(f"⏭️ Column {column_name} already exists, skipping...")
            
            # Update existing vulnerabilities with default values
            print("🔄 Updating existing vulnerabilities with default values...")
            try:
                if engine_name == 'postgresql':
                    update_sql = """
                    UPDATE vulnerability 
                    SET 
                        confidence_score = COALESCE(confidence_score, 50),
                        is_validated = COALESCE(is_validated, TRUE),
                        template_name = COALESCE(template_name, title)
                    WHERE 
                        confidence_score IS NULL 
                        OR is_validated IS NULL 
                        OR template_name IS NULL;
                    """
                else:  # SQLite
                    update_sql = """
                    UPDATE vulnerability 
                    SET 
                        confidence_score = COALESCE(confidence_score, 50),
                        is_validated = COALESCE(is_validated, 1),
                        template_name = COALESCE(template_name, title)
                    WHERE 
                        confidence_score IS NULL 
                        OR is_validated IS NULL 
                        OR template_name IS NULL;
                    """
                
                result = db.session.execute(text(update_sql))
                updated_count = result.rowcount
                db.session.commit()
                print(f"✅ Updated {updated_count} existing vulnerabilities")
                
            except Exception as e:
                print(f"❌ Failed to update existing vulnerabilities: {str(e)}")
                db.session.rollback()
            
            # Verify the migration
            print("🔍 Verifying migration...")
            inspector = inspect(db.engine)
            final_columns = [col['name'] for col in inspector.get_columns('vulnerability')]
            
            expected_new_columns = ['confidence_score', 'is_validated', 'validation_notes', 'template_name', 'cvss_score', 'asset_metadata']
            missing_columns = [col for col in expected_new_columns if col not in final_columns]
            
            if missing_columns:
                print(f"❌ Migration incomplete. Missing columns: {missing_columns}")
                return False
            else:
                print(f"✅ Migration successful! Added {columns_added} new columns")
                print(f"📊 Total columns now: {len(final_columns)}")
                
                # Test querying the new fields
                try:
                    vuln_count = Vulnerability.query.count()
                    print(f"📊 Total vulnerabilities: {vuln_count}")
                    
                    if vuln_count > 0:
                        # Test the new fields
                        test_vuln = Vulnerability.query.first()
                        print(f"🧪 Testing new fields on first vulnerability:")
                        print(f"  - confidence_score: {getattr(test_vuln, 'confidence_score', 'N/A')}")
                        print(f"  - is_validated: {getattr(test_vuln, 'is_validated', 'N/A')}")
                        print(f"  - template_name: {getattr(test_vuln, 'template_name', 'N/A')}")
                    
                except Exception as e:
                    print(f"⚠️ Warning: Could not test new fields: {str(e)}")
                
                return True
                
    except Exception as e:
        print(f"❌ Migration failed: {str(e)}")
        return False

def create_migration_summary():
    """Create a summary file of the migration"""
    summary = f"""# Database Migration Summary

## Migration Date
{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

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
"""
    
    with open('MIGRATION_SUMMARY.md', 'w') as f:
        f.write(summary)
    
    print("📄 Created MIGRATION_SUMMARY.md")

if __name__ == "__main__":
    print("🚀 Running local database migration for vulnerability validation...")
    
    success = run_local_migration()
    
    if success:
        create_migration_summary()
        print("\n🎉 Local migration completed successfully!")
        print("\n📋 Next steps:")
        print("1. Commit all changes to GitHub:")
        print("   git add .")
        print("   git commit -m 'Add vulnerability validation database fields'")
        print("   git push")
        print("\n2. Deploy to Docker environment")
        print("3. The database error will be resolved!")
        print("\n✨ All vulnerability validation features are now ready!")
    else:
        print("\n💥 Local migration failed!")
        print("Please check the error messages above and try again.")
        sys.exit(1)
