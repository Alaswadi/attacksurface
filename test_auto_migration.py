#!/usr/bin/env python3
"""
Test script to verify the auto-migration functionality
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_auto_migration():
    """Test that the auto-migration works when the app starts"""
    try:
        print("🧪 Testing auto-migration functionality...")
        
        # Import and create the app (this should trigger auto-migration)
        from app import create_app
        app = create_app()
        
        with app.app_context():
            from models import db, Vulnerability
            from sqlalchemy import inspect
            
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
            
            print(f"📋 Current vulnerability table columns: {len(columns)} total")
            
            missing_columns = []
            for col in expected_columns:
                if col in columns:
                    print(f"✅ Column '{col}' exists")
                else:
                    print(f"❌ Column '{col}' missing")
                    missing_columns.append(col)
            
            if missing_columns:
                print(f"\n❌ Auto-migration incomplete. Missing columns: {missing_columns}")
                return False
            else:
                print(f"\n✅ Auto-migration successful! All expected columns are present.")
                
                # Test querying the new fields
                try:
                    vuln_count = Vulnerability.query.count()
                    print(f"📊 Total vulnerabilities in database: {vuln_count}")
                    
                    if vuln_count > 0:
                        # Test querying new fields
                        test_vuln = Vulnerability.query.first()
                        print(f"🔍 Test vulnerability fields:")
                        print(f"  - confidence_score: {getattr(test_vuln, 'confidence_score', 'N/A')}")
                        print(f"  - is_validated: {getattr(test_vuln, 'is_validated', 'N/A')}")
                        print(f"  - template_name: {getattr(test_vuln, 'template_name', 'N/A')}")
                    
                    print("\n✅ Auto-migration verification successful!")
                    return True
                    
                except Exception as e:
                    print(f"❌ Error testing new fields: {str(e)}")
                    return False
                
    except Exception as e:
        print(f"❌ Auto-migration test failed: {str(e)}")
        return False

if __name__ == "__main__":
    print("🚀 Testing auto-migration functionality...")
    success = test_auto_migration()
    
    if success:
        print("\n🎉 Auto-migration test passed!")
        print("The application should now start without database errors.")
        print("All vulnerability validation features are ready to use.")
    else:
        print("\n💥 Auto-migration test failed!")
        print("Please check the error messages above.")
        sys.exit(1)
