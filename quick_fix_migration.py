#!/usr/bin/env python3
"""
Quick fix script to apply the vulnerability validation migration
This script can be run directly in the Docker environment
"""

import os
import sys

# Add the app directory to Python path
sys.path.insert(0, '/app')

try:
    from app import create_app, db
    from sqlalchemy import text
    import logging
    
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    
    def apply_migration():
        """Apply the migration using raw SQL"""
        app = create_app()
        
        with app.app_context():
            try:
                logger.info("🔄 Applying vulnerability validation migration...")
                
                # SQL commands to add new columns
                migration_sql = """
                -- Add confidence_score column
                DO $$ 
                BEGIN 
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns 
                        WHERE table_name = 'vulnerability' 
                        AND column_name = 'confidence_score'
                        AND table_schema = 'public'
                    ) THEN
                        ALTER TABLE vulnerability ADD COLUMN confidence_score INTEGER DEFAULT 0;
                    END IF;
                END $$;
                
                -- Add is_validated column
                DO $$ 
                BEGIN 
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns 
                        WHERE table_name = 'vulnerability' 
                        AND column_name = 'is_validated'
                        AND table_schema = 'public'
                    ) THEN
                        ALTER TABLE vulnerability ADD COLUMN is_validated BOOLEAN DEFAULT FALSE;
                    END IF;
                END $$;
                
                -- Add validation_notes column
                DO $$ 
                BEGIN 
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns 
                        WHERE table_name = 'vulnerability' 
                        AND column_name = 'validation_notes'
                        AND table_schema = 'public'
                    ) THEN
                        ALTER TABLE vulnerability ADD COLUMN validation_notes TEXT;
                    END IF;
                END $$;
                
                -- Add template_name column
                DO $$ 
                BEGIN 
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns 
                        WHERE table_name = 'vulnerability' 
                        AND column_name = 'template_name'
                        AND table_schema = 'public'
                    ) THEN
                        ALTER TABLE vulnerability ADD COLUMN template_name VARCHAR(255);
                    END IF;
                END $$;
                
                -- Add cvss_score column
                DO $$ 
                BEGIN 
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns 
                        WHERE table_name = 'vulnerability' 
                        AND column_name = 'cvss_score'
                        AND table_schema = 'public'
                    ) THEN
                        ALTER TABLE vulnerability ADD COLUMN cvss_score REAL;
                    END IF;
                END $$;
                
                -- Add asset_metadata column
                DO $$ 
                BEGIN 
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns 
                        WHERE table_name = 'vulnerability' 
                        AND column_name = 'asset_metadata'
                        AND table_schema = 'public'
                    ) THEN
                        ALTER TABLE vulnerability ADD COLUMN asset_metadata JSONB;
                    END IF;
                END $$;
                """
                
                # Execute the migration
                db.session.execute(text(migration_sql))
                db.session.commit()
                
                logger.info("✅ Migration SQL executed successfully")
                
                # Update existing records
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
                
                result = db.session.execute(text(update_sql))
                db.session.commit()
                
                logger.info(f"✅ Updated {result.rowcount} existing vulnerabilities")
                
                # Verify the migration
                verify_sql = """
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'vulnerability' 
                AND column_name IN ('confidence_score', 'is_validated', 'validation_notes', 'template_name', 'cvss_score', 'asset_metadata')
                ORDER BY column_name;
                """
                
                result = db.session.execute(text(verify_sql))
                new_columns = [row[0] for row in result.fetchall()]
                
                logger.info(f"✅ Verified new columns: {new_columns}")
                
                if len(new_columns) == 6:
                    logger.info("🎉 Migration completed successfully!")
                    return True
                else:
                    logger.error(f"❌ Migration incomplete. Expected 6 columns, found {len(new_columns)}")
                    return False
                    
            except Exception as e:
                logger.error(f"❌ Migration failed: {str(e)}")
                db.session.rollback()
                return False
    
    if __name__ == "__main__":
        logger.info("🚀 Running quick fix migration...")
        success = apply_migration()
        
        if success:
            logger.info("\n✅ Quick fix migration completed!")
            logger.info("The application should now work correctly with vulnerability validation features.")
        else:
            logger.error("\n❌ Quick fix migration failed!")
            sys.exit(1)

except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Make sure this script is run from the correct directory with access to the Flask app")
    sys.exit(1)
except Exception as e:
    print(f"❌ Unexpected error: {e}")
    sys.exit(1)
