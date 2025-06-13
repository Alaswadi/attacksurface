#!/usr/bin/env python3
"""
Initialize SQLite database for Docker environment
This script ensures the database is properly set up with all tables and enhanced settings
"""

import os
import sys

def init_sqlite_docker():
    """Initialize SQLite database for Docker"""
    try:
        print("🔄 Initializing SQLite database for Docker...")

        # Create data directory if it doesn't exist
        data_dir = '/app/data'
        if not os.path.exists(data_dir):
            os.makedirs(data_dir, mode=0o755, exist_ok=True)
            print(f"✅ Created data directory: {data_dir}")

        # Set proper permissions
        try:
            os.chmod(data_dir, 0o755)
            print(f"✅ Set permissions for: {data_dir}")
        except Exception as e:
            print(f"⚠️  Could not set permissions: {e}")

        # Import Flask app and database
        from app import create_app, db

        app = create_app()

        with app.app_context():
            print(f"📋 Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")

            print("📝 Creating all database tables...")

            # Create all tables
            db.create_all()
            print("✅ Created all database tables")

            # Run email notification settings migration
            print("🔄 Running email notification settings migration...")
            try:
                import subprocess
                result = subprocess.run([sys.executable, 'docker_migration_email_notifications.py'],
                                      capture_output=True, text=True, cwd='/app')
                if result.returncode == 0:
                    print("✅ Email notification settings migration completed")
                else:
                    print(f"⚠️ Migration warning: {result.stderr}")
                    # Continue anyway as the migration might not be needed
            except Exception as e:
                print(f"⚠️ Could not run migration: {e}")
                # Continue anyway

            # Verify database file exists
            db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
            if os.path.exists(db_path):
                print(f"✅ Database file created: {db_path}")
                print(f"📊 Database file size: {os.path.getsize(db_path)} bytes")
            else:
                print(f"⚠️  Database file not found: {db_path}")

            # Check if we have any users (for first-time setup)
            try:
                from models import User, Organization

                user_count = User.query.count()
                org_count = Organization.query.count()

                print(f"📊 Database status:")
                print(f"   Users: {user_count}")
                print(f"   Organizations: {org_count}")

                if user_count == 0:
                    print("ℹ️  This appears to be a fresh database")
                    print("📋 You can create your first user by registering at /auth/register")
            except Exception as e:
                print(f"⚠️  Could not query database: {e}")

            print("🎉 SQLite database initialization completed successfully!")
            return True

    except Exception as e:
        print(f"❌ SQLite database initialization failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("🚀 Running SQLite database initialization for Docker...")
    success = init_sqlite_docker()
    
    if success:
        print("🎉 SQLite initialization completed successfully!")
    else:
        print("💥 SQLite initialization failed!")
        sys.exit(1)
