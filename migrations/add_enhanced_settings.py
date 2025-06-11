#!/usr/bin/env python3
"""
Database migration script for enhanced settings functionality
Adds user management, email configuration, and organization enhancements
"""

import os
import sys
from flask import Flask
from sqlalchemy import text

# Add the parent directory to the path so we can import our models
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import db
from config import config

def create_app():
    """Create Flask app for migration"""
    app = Flask(__name__)
    
    # Use production config for Docker
    config_name = os.environ.get('FLASK_CONFIG', 'production')
    app.config.from_object(config[config_name])
    
    # Initialize database
    db.init_app(app)
    
    return app

def run_migration():
    """Run the database migration"""
    app = create_app()

    with app.app_context():
        try:
            print("🔄 Starting enhanced settings migration...")

            # Check current schema
            print("🔍 Checking current database schema...")

            # Check if columns already exist
            def column_exists(table_name, column_name):
                try:
                    result = db.session.execute(text(f"PRAGMA table_info({table_name})"))
                    columns = [row[1] for row in result.fetchall()]
                    return column_name in columns
                except:
                    return False

            # Add new columns to Organization table
            print("📝 Adding new columns to Organization table...")

            if not column_exists('organization', 'primary_domain'):
                try:
                    db.session.execute(text("ALTER TABLE organization ADD COLUMN primary_domain VARCHAR(255)"))
                    db.session.commit()
                    print("✅ Added primary_domain column")
                except Exception as e:
                    print(f"❌ Error adding primary_domain: {e}")
                    db.session.rollback()
            else:
                print("⚠️  primary_domain column already exists")

            if not column_exists('organization', 'description'):
                try:
                    db.session.execute(text("ALTER TABLE organization ADD COLUMN description TEXT"))
                    db.session.commit()
                    print("✅ Added description column")
                except Exception as e:
                    print(f"❌ Error adding description: {e}")
                    db.session.rollback()
            else:
                print("⚠️  description column already exists")

            if not column_exists('organization', 'updated_at'):
                try:
                    db.session.execute(text("ALTER TABLE organization ADD COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP"))
                    db.session.commit()
                    print("✅ Added updated_at column")
                except Exception as e:
                    print(f"❌ Error adding updated_at: {e}")
                    db.session.rollback()
            else:
                print("⚠️  updated_at column already exists")

            # Add new columns to User table
            print("📝 Adding new columns to User table...")
            if not column_exists('user', 'is_email_verified'):
                try:
                    db.session.execute(text("ALTER TABLE user ADD COLUMN is_email_verified BOOLEAN DEFAULT 0"))
                    db.session.commit()
                    print("✅ Added is_email_verified column")
                except Exception as e:
                    print(f"❌ Error adding is_email_verified: {e}")
                    db.session.rollback()
            else:
                print("⚠️  is_email_verified column already exists")

            # Create new tables
            print("📝 Creating new tables...")

            # Create all tables (this will only create tables that don't exist)
            db.create_all()
            print("✅ Created all new tables")

            # Verify tables exist
            print("🔍 Verifying new tables...")
            tables_to_check = [
                'organization_user',
                'user_invitation',
                'email_configuration',
                'email_template',
                'email_notification_settings'
            ]

            for table in tables_to_check:
                try:
                    result = db.session.execute(text(f"SELECT COUNT(*) FROM {table}"))
                    count = result.scalar()
                    print(f"✅ Table '{table}' exists with {count} records")
                except Exception as e:
                    print(f"❌ Table '{table}' verification failed: {e}")

            # Verify organization table columns
            print("🔍 Verifying organization table columns...")
            result = db.session.execute(text("PRAGMA table_info(organization)"))
            columns = [row[1] for row in result.fetchall()]
            print(f"Organization table columns: {columns}")

            print("🎉 Enhanced settings migration completed successfully!")

        except Exception as e:
            print(f"❌ Migration failed: {e}")
            db.session.rollback()
            raise

if __name__ == "__main__":
    run_migration()
