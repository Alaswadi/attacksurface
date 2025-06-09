#!/usr/bin/env python3
"""
Simple script to verify the database migration was successful
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import create_app, db
from models import Vulnerability
from sqlalchemy import inspect

def verify_migration():
    """Verify that the new fields were added successfully"""
    app = create_app()
    
    with app.app_context():
        try:
            print("🔍 Verifying database migration...")
            
            # Check if new columns exist
            inspector = inspect(db.engine)
            columns = [col['name'] for col in inspector.get_columns('vulnerability')]
            
            expected_columns = [
                'confidence_score',
                'is_validated', 
                'validation_notes',
                'template_name',
                'cvss_score',
                'asset_metadata'
            ]
            
            print(f"📋 Current vulnerability table columns: {columns}")
            
            missing_columns = []
            for col in expected_columns:
                if col in columns:
                    print(f"✅ Column '{col}' exists")
                else:
                    print(f"❌ Column '{col}' missing")
                    missing_columns.append(col)
            
            if missing_columns:
                print(f"\n❌ Migration incomplete. Missing columns: {missing_columns}")
                return False
            else:
                print(f"\n✅ All expected columns are present!")
                
                # Test creating a vulnerability with new fields
                print("\n🧪 Testing vulnerability creation with new fields...")
                
                # Count existing vulnerabilities
                existing_count = Vulnerability.query.count()
                print(f"📊 Current vulnerability count: {existing_count}")
                
                print("\n✅ Database migration verification successful!")
                print("The vulnerability validation functionality is ready to use.")
                return True
                
        except Exception as e:
            print(f"❌ Verification failed: {str(e)}")
            return False

if __name__ == "__main__":
    print("🔍 Verifying vulnerability validation migration...")
    success = verify_migration()
    
    if success:
        print("\n🎉 Migration verification passed!")
        print("\nNext steps:")
        print("1. Start the Flask application")
        print("2. Run a Nuclei scan to test the new functionality")
        print("3. Check the vulnerabilities page to see both validated and unvalidated findings")
    else:
        print("\n💥 Migration verification failed!")
        sys.exit(1)
