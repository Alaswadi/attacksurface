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
        
        # Create database directory if it doesn't exist
        db_dir = '/app/database'
        if not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
            print(f"✅ Created database directory: {db_dir}")
        
        # Import Flask app and database
        from app import create_app, db
        
        app = create_app()
        
        with app.app_context():
            print("📝 Creating all database tables...")
            
            # Create all tables
            db.create_all()
            print("✅ Created all database tables")
            
            # Check if we have any users (for first-time setup)
            from models import User, Organization
            
            user_count = User.query.count()
            org_count = Organization.query.count()
            
            print(f"📊 Database status:")
            print(f"   Users: {user_count}")
            print(f"   Organizations: {org_count}")
            
            if user_count == 0:
                print("ℹ️  This appears to be a fresh database")
                print("📋 You can create your first user by registering at /auth/register")
            
            print("🎉 SQLite database initialization completed successfully!")
            return True
                    
    except Exception as e:
        print(f"❌ SQLite database initialization failed: {str(e)}")
        return False

if __name__ == "__main__":
    print("🚀 Running SQLite database initialization for Docker...")
    success = init_sqlite_docker()
    
    if success:
        print("🎉 SQLite initialization completed successfully!")
    else:
        print("💥 SQLite initialization failed!")
        sys.exit(1)
