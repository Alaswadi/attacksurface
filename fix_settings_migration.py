#!/usr/bin/env python3
"""
Fix for the enhanced settings Docker PostgreSQL issue
This script adds the missing columns to fix the current error
"""

import os
import sys

# Add the app directory to Python path (for Docker)
sys.path.insert(0, '/app')

def run_settings_fix():
    """Run the enhanced settings fix for Docker PostgreSQL"""
    try:
        print("🔄 Starting enhanced settings fix...")
        
        # Import Flask app and database
        from app import create_app, db
        from sqlalchemy import text
        
        app = create_app()
        
        with app.app_context():
            print("📝 Adding missing columns...")
            
            # Fix the immediate issue: add is_email_verified column
            try:
                db.session.execute(text('ALTER TABLE "user" ADD COLUMN is_email_verified BOOLEAN DEFAULT FALSE'))
                db.session.commit()
                print("✅ Added is_email_verified column to user table")
            except Exception as e:
                if "already exists" in str(e).lower():
                    print("⚠️  is_email_verified column already exists")
                else:
                    print(f"❌ Error adding is_email_verified: {e}")
            
            # Add organization columns
            try:
                db.session.execute(text("ALTER TABLE organization ADD COLUMN primary_domain VARCHAR(255)"))
                db.session.commit()
                print("✅ Added primary_domain column to organization table")
            except Exception as e:
                if "already exists" in str(e).lower():
                    print("⚠️  primary_domain column already exists")
                else:
                    print(f"⚠️  Could not add primary_domain: {e}")
            
            try:
                db.session.execute(text("ALTER TABLE organization ADD COLUMN description TEXT"))
                db.session.commit()
                print("✅ Added description column to organization table")
            except Exception as e:
                if "already exists" in str(e).lower():
                    print("⚠️  description column already exists")
                else:
                    print(f"⚠️  Could not add description: {e}")
            
            # Create new tables for enhanced settings
            try:
                print("📝 Creating new tables for enhanced settings...")
                db.create_all()
                print("✅ Created all new tables")
            except Exception as e:
                print(f"⚠️  Error creating tables: {e}")
            
            # Verify the fix
            print("🔍 Verifying the fix...")
            try:
                result = db.session.execute(text('SELECT column_name FROM information_schema.columns WHERE table_name = \'user\' AND column_name = \'is_email_verified\''))
                if result.fetchone():
                    print("✅ is_email_verified column verified")
                else:
                    print("❌ is_email_verified column not found")
                    return False
            except Exception as e:
                print(f"❌ Verification failed: {e}")
                return False
            
            print("🎉 Enhanced settings fix completed successfully!")
            return True
                    
    except Exception as e:
        print(f"❌ Enhanced settings fix failed: {str(e)}")
        return False

if __name__ == "__main__":
    print("🚀 Running enhanced settings fix for Docker...")
    success = run_settings_fix()
    
    if success:
        print("🎉 Fix completed successfully!")
        print("📋 You can now restart your Docker container")
        print("🌐 The enhanced settings page should work correctly")
    else:
        print("💥 Fix failed!")
        sys.exit(1)
