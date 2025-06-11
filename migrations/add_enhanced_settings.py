#!/usr/bin/env python3
"""
Database migration script for enhanced settings functionality
Adds user management, email configuration, and organization enhancements
Works with both SQLite and PostgreSQL
"""

import os
import sys
from flask import Flask
from sqlalchemy import text, inspect

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

def get_database_type():
    """Detect database type from connection string"""
    try:
        engine = db.get_engine()
        return engine.dialect.name
    except:
        return 'unknown'

def column_exists_postgres(table_name, column_name):
    """Check if column exists in PostgreSQL"""
    try:
        result = db.session.execute(text("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = :table_name AND column_name = :column_name
        """), {'table_name': table_name, 'column_name': column_name})
        return result.fetchone() is not None
    except Exception as e:
        print(f"Error checking column {column_name} in {table_name}: {e}")
        return False

def column_exists_sqlite(table_name, column_name):
    """Check if column exists in SQLite"""
    try:
        result = db.session.execute(text(f"PRAGMA table_info({table_name})"))
        columns = [row[1] for row in result.fetchall()]
        return column_name in columns
    except Exception as e:
        print(f"Error checking column {column_name} in {table_name}: {e}")
        return False

def table_exists(table_name):
    """Check if table exists"""
    try:
        db_type = get_database_type()
        if db_type == 'postgresql':
            result = db.session.execute(text("""
                SELECT table_name
                FROM information_schema.tables
                WHERE table_name = :table_name
            """), {'table_name': table_name})
        else:  # SQLite
            result = db.session.execute(text("""
                SELECT name FROM sqlite_master
                WHERE type='table' AND name = :table_name
            """), {'table_name': table_name})
        return result.fetchone() is not None
    except Exception as e:
        print(f"Error checking table {table_name}: {e}")
        return False

def run_migration():
    """Run the database migration"""
    app = create_app()

    with app.app_context():
        try:
            print("🔄 Starting enhanced settings migration...")

            # Detect database type
            db_type = get_database_type()
            print(f"🔍 Detected database type: {db_type}")

            # Choose appropriate column check function
            if db_type == 'postgresql':
                column_exists = column_exists_postgres
            else:
                column_exists = column_exists_sqlite

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

            # Add new columns to User table
            print("📝 Adding new columns to User table...")
            if not column_exists('user', 'is_email_verified'):
                try:
                    if db_type == 'postgresql':
                        db.session.execute(text('ALTER TABLE "user" ADD COLUMN is_email_verified BOOLEAN DEFAULT FALSE'))
                    else:
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
                if table_exists(table):
                    try:
                        if db_type == 'postgresql':
                            result = db.session.execute(text(f'SELECT COUNT(*) FROM "{table}"'))
                        else:
                            result = db.session.execute(text(f"SELECT COUNT(*) FROM {table}"))
                        count = result.scalar()
                        print(f"✅ Table '{table}' exists with {count} records")
                    except Exception as e:
                        print(f"❌ Table '{table}' verification failed: {e}")
                else:
                    print(f"❌ Table '{table}' does not exist")

            # Verify organization table columns
            print("🔍 Verifying organization table columns...")
            if db_type == 'postgresql':
                result = db.session.execute(text("""
                    SELECT column_name
                    FROM information_schema.columns
                    WHERE table_name = 'organization'
                    ORDER BY ordinal_position
                """))
                columns = [row[0] for row in result.fetchall()]
            else:
                result = db.session.execute(text("PRAGMA table_info(organization)"))
                columns = [row[1] for row in result.fetchall()]

            print(f"Organization table columns: {columns}")

            # Verify user table columns
            print("🔍 Verifying user table columns...")
            if db_type == 'postgresql':
                result = db.session.execute(text("""
                    SELECT column_name
                    FROM information_schema.columns
                    WHERE table_name = 'user'
                    ORDER BY ordinal_position
                """))
                columns = [row[0] for row in result.fetchall()]
            else:
                result = db.session.execute(text("PRAGMA table_info(user)"))
                columns = [row[1] for row in result.fetchall()]

            print(f"User table columns: {columns}")

            print("🎉 Enhanced settings migration completed successfully!")

        except Exception as e:
            print(f"❌ Migration failed: {e}")
            db.session.rollback()
            raise

if __name__ == "__main__":
    run_migration()
