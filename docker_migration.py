#!/usr/bin/env python3
"""
Docker-specific migration script that runs automatically
This script is designed to run in the Docker PostgreSQL environment
"""

import os
import sys
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def run_docker_migration():
    """Run the PostgreSQL migration in Docker environment"""
    try:
        logger.info("🔄 Starting Docker PostgreSQL migration...")
        
        # Import Flask app and database
        from app import create_app, db
        from sqlalchemy import text, inspect
        
        app = create_app()
        
        with app.app_context():
            # Check database type
            engine_name = db.engine.name
            logger.info(f"📋 Database engine: {engine_name}")
            
            if engine_name != 'postgresql':
                logger.info("⏭️ Not PostgreSQL, skipping Docker migration")
                return True
            
            # Check if columns already exist
            try:
                inspector = inspect(db.engine)
                existing_columns = [col['name'] for col in inspector.get_columns('vulnerability')]
                logger.info(f"📋 Current columns: {len(existing_columns)} total")
                
                expected_columns = ['is_validated', 'validation_notes', 'template_name', 'cvss_score', 'asset_metadata']
                missing_columns = [col for col in expected_columns if col not in existing_columns]
                
                if not missing_columns:
                    logger.info("✅ All columns already exist, migration not needed")
                    return True
                
                logger.info(f"➕ Need to add columns: {missing_columns}")
                
            except Exception as e:
                logger.error(f"❌ Could not check existing columns: {e}")
                return False
            
            # Run the migration (without confidence_score)
            try:
                migration_sql = """
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
                        RAISE NOTICE 'Added is_validated column';
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
                        RAISE NOTICE 'Added validation_notes column';
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
                        RAISE NOTICE 'Added template_name column';
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
                        RAISE NOTICE 'Added cvss_score column';
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
                        RAISE NOTICE 'Added asset_metadata column';
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
                    is_validated = COALESCE(is_validated, TRUE),
                    template_name = COALESCE(template_name, title)
                WHERE
                    is_validated IS NULL
                    OR template_name IS NULL;
                """
                
                result = db.session.execute(text(update_sql))
                db.session.commit()
                logger.info(f"✅ Updated {result.rowcount} existing vulnerabilities")
                
                # Verify the migration
                inspector = inspect(db.engine)
                final_columns = [col['name'] for col in inspector.get_columns('vulnerability')]
                expected_columns = ['is_validated', 'validation_notes', 'template_name', 'cvss_score', 'asset_metadata']
                missing_columns = [col for col in expected_columns if col not in final_columns]
                
                if missing_columns:
                    logger.error(f"❌ Migration incomplete. Missing columns: {missing_columns}")
                    return False
                else:
                    logger.info(f"✅ Migration successful! All {len(expected_columns)} columns added")
                    logger.info(f"📊 Total columns now: {len(final_columns)}")
                    return True
                    
            except Exception as e:
                logger.error(f"❌ Migration failed: {str(e)}")
                db.session.rollback()
                return False
                
    except Exception as e:
        logger.error(f"❌ Docker migration failed: {str(e)}")
        return False

if __name__ == "__main__":
    logger.info("🚀 Running Docker PostgreSQL migration...")
    success = run_docker_migration()
    
    if success:
        logger.info("🎉 Docker migration completed successfully!")
    else:
        logger.error("💥 Docker migration failed!")
        sys.exit(1)
