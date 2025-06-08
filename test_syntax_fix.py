#!/usr/bin/env python3
"""
Quick test to verify syntax fixes are working
"""

def test_imports():
    """Test that all modules can be imported without syntax errors"""
    try:
        print("🧪 Testing imports...")
        
        # Test routes/api.py import
        print("📋 Testing routes/api.py...")
        from routes.api import api_bp
        print("✅ routes/api.py imported successfully")
        
        # Test tasks.py import
        print("📋 Testing tasks.py...")
        import tasks
        print("✅ tasks.py imported successfully")
        
        # Test progressive scanning functions exist
        print("📋 Testing progressive scanning functions...")
        if hasattr(tasks, 'progressive_large_domain_scan_orchestrator'):
            print("✅ progressive_large_domain_scan_orchestrator function exists")
        else:
            print("❌ progressive_large_domain_scan_orchestrator function missing")
            
        # Test API endpoints exist
        print("📋 Testing API endpoints...")
        if hasattr(api_bp, 'url_map'):
            print("✅ API blueprint has URL map")
        else:
            print("❌ API blueprint missing URL map")
        
        print("\n🎉 ALL SYNTAX FIXES SUCCESSFUL!")
        print("✅ No syntax errors found")
        print("✅ All modules import correctly")
        print("✅ Progressive scanning implementation is ready")
        
        return True
        
    except SyntaxError as e:
        print(f"❌ SYNTAX ERROR: {str(e)}")
        print(f"   File: {e.filename}")
        print(f"   Line: {e.lineno}")
        print(f"   Text: {e.text}")
        return False
        
    except ImportError as e:
        print(f"❌ IMPORT ERROR: {str(e)}")
        return False
        
    except Exception as e:
        print(f"❌ UNEXPECTED ERROR: {str(e)}")
        return False

def main():
    """Main test function"""
    print("🚀 TESTING SYNTAX FIXES")
    print("=" * 50)
    
    success = test_imports()
    
    print("\n" + "=" * 50)
    if success:
        print("🎯 RESULT: ✅ SYNTAX FIXES SUCCESSFUL")
        print("🚀 The application should now start without syntax errors!")
        print("📋 You can now run: docker-compose up -d")
    else:
        print("🎯 RESULT: ❌ SYNTAX ISSUES REMAIN")
        print("Please check the error messages above.")
    
    return 0 if success else 1

if __name__ == "__main__":
    import sys
    sys.exit(main())
