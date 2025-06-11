#!/usr/bin/env python3
"""
Docker-specific migration script for enhanced settings functionality
This script is designed to run in the Docker PostgreSQL environment
"""

import os
import sys
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def run_enhanced_settings_migration():
    """Run the enhanced settings migration in Docker PostgreSQL environment"""
    try:
        logger.info("🔄 Starting Docker Enhanced Settings migration...")
        
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
            
            # Run the enhanced settings migration
            try:
                migration_sql = """
                -- Add columns to Organization table
                DO $$ 
                BEGIN 
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns 
                        WHERE table_name = 'organization' 
                        AND column_name = 'primary_domain'
                        AND table_schema = 'public'
                    ) THEN
                        ALTER TABLE organization ADD COLUMN primary_domain VARCHAR(255);
                        RAISE NOTICE 'Added primary_domain column to organization';
                    END IF;
                END $$;
                
                DO $$ 
                BEGIN 
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns 
                        WHERE table_name = 'organization' 
                        AND column_name = 'description'
                        AND table_schema = 'public'
                    ) THEN
                        ALTER TABLE organization ADD COLUMN description TEXT;
                        RAISE NOTICE 'Added description column to organization';
                    END IF;
                END $$;
                
                -- Add columns to User table (note: "user" is a reserved word in PostgreSQL)
                DO $$ 
                BEGIN 
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns 
                        WHERE table_name = 'user' 
                        AND column_name = 'is_email_verified'
                        AND table_schema = 'public'
                    ) THEN
                        ALTER TABLE "user" ADD COLUMN is_email_verified BOOLEAN DEFAULT FALSE;
                        RAISE NOTICE 'Added is_email_verified column to user';
                    END IF;
                END $$;
                """
                
                # Execute the migration
                db.session.execute(text(migration_sql))
                db.session.commit()
                logger.info("✅ Enhanced settings migration SQL executed successfully")
                
                # Create new tables using SQLAlchemy
                logger.info("📝 Creating new tables...")
                db.create_all()
                logger.info("✅ Created all new tables")
                
                # Verify the migration
                logger.info("🔍 Verifying migration...")
                
                # Check organization table columns
                inspector = inspect(db.engine)
                org_columns = [col['name'] for col in inspector.get_columns('organization')]
                expected_org_columns = ['primary_domain', 'description']
                missing_org_columns = [col for col in expected_org_columns if col not in org_columns]
                
                if missing_org_columns:
                    logger.error(f"❌ Organization table missing columns: {missing_org_columns}")
                else:
                    logger.info("✅ Organization table columns added successfully")
                
                # Check user table columns
                user_columns = [col['name'] for col in inspector.get_columns('user')]
                if 'is_email_verified' not in user_columns:
                    logger.error("❌ User table missing is_email_verified column")
                else:
                    logger.info("✅ User table is_email_verified column added successfully")
                
                # Check new tables
                tables_to_check = [
                    'organization_user',
                    'user_invitation', 
                    'email_configuration',
                    'email_template',
                    'email_notification_settings'
                ]
                
                existing_tables = inspector.get_table_names()
                missing_tables = [table for table in tables_to_check if table not in existing_tables]
                
                if missing_tables:
                    logger.error(f"❌ Missing tables: {missing_tables}")
                    return False
                else:
                    logger.info(f"✅ All {len(tables_to_check)} new tables created successfully")
                
                logger.info("🎉 Enhanced settings migration completed successfully!")
                return True
                    
            except Exception as e:
                logger.error(f"❌ Migration failed: {str(e)}")
                db.session.rollback()
                return False
                
    except Exception as e:
        logger.error(f"❌ Docker enhanced settings migration failed: {str(e)}")
        return False

if __name__ == "__main__":
    logger.info("🚀 Running Docker Enhanced Settings migration...")
    success = run_enhanced_settings_migration()
    
    if success:
        logger.info("🎉 Docker enhanced settings migration completed successfully!")
    else:
        logger.error("💥 Docker enhanced settings migration failed!")
        sys.exit(1)
