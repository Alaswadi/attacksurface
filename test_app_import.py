#!/usr/bin/env python3
"""
Test script to verify app.py imports correctly
This tests the fix for the UnboundLocalError: cannot access local variable 'os'
"""

import sys
import os

def test_app_import():
    """Test that app.py can be imported without errors"""
    print("🧪 Testing app.py import...")
    
    try:
        # Test importing the app module
        from app import create_app
        print("✅ Successfully imported create_app from app.py")
        
        # Test creating the app
        print("🔧 Testing app creation...")
        app = create_app()
        print("✅ Successfully created Flask app")
        
        # Test app configuration
        print("🔍 Testing app configuration...")
        print(f"   App name: {app.name}")
        print(f"   Debug mode: {app.debug}")
        print(f"   Config loaded: {bool(app.config)}")
        
        # Test Redis configuration
        print("🔗 Testing Redis configuration...")
        broker_url = app.config.get('broker_url', 'Not set')
        redis_available = app.config.get('REDIS_AVAILABLE', 'Not checked')
        print(f"   Broker URL configured: {bool(broker_url)}")
        print(f"   Redis available: {redis_available}")
        
        print("✅ All app import tests passed!")
        return True
        
    except Exception as e:
        print(f"❌ App import test failed: {str(e)}")
        import traceback
        print(f"❌ Traceback: {traceback.format_exc()}")
        return False

def test_environment_variables():
    """Test environment variable handling"""
    print("\n🌍 Testing environment variable handling...")
    
    # Test with no environment variables
    print("📋 Current environment variables:")
    celery_broker = os.environ.get('CELERY_BROKER_URL', 'Not set')
    flask_config = os.environ.get('FLASK_CONFIG', 'Not set')
    
    print(f"   CELERY_BROKER_URL: {celery_broker}")
    print(f"   FLASK_CONFIG: {flask_config}")
    
    # Test setting environment variables
    print("🔧 Testing with custom environment variables...")
    
    # Temporarily set environment variables
    original_broker = os.environ.get('CELERY_BROKER_URL')
    original_config = os.environ.get('FLASK_CONFIG')
    
    try:
        os.environ['CELERY_BROKER_URL'] = 'redis://test:6379/0'
        os.environ['FLASK_CONFIG'] = 'testing'
        
        # Import and create app with custom environment
        from app import create_app
        app = create_app()
        
        print("✅ App created successfully with custom environment variables")
        
        # Restore original environment
        if original_broker:
            os.environ['CELERY_BROKER_URL'] = original_broker
        else:
            os.environ.pop('CELERY_BROKER_URL', None)
            
        if original_config:
            os.environ['FLASK_CONFIG'] = original_config
        else:
            os.environ.pop('FLASK_CONFIG', None)
            
        return True
        
    except Exception as e:
        print(f"❌ Environment variable test failed: {str(e)}")
        return False

def main():
    """Main test function"""
    print("🔧 App Import Fix Verification")
    print("=" * 40)
    print("Testing fix for: UnboundLocalError: cannot access local variable 'os'")
    print()
    
    # Test basic app import
    import_success = test_app_import()
    
    # Test environment variable handling
    env_success = test_environment_variables()
    
    # Final results
    print("\n" + "=" * 40)
    print("📊 TEST RESULTS")
    print("=" * 40)
    print(f"🔧 App Import Test: {'✅ PASS' if import_success else '❌ FAIL'}")
    print(f"🌍 Environment Test: {'✅ PASS' if env_success else '❌ FAIL'}")
    
    if import_success and env_success:
        print("\n🎉 ALL TESTS PASSED!")
        print("✅ The UnboundLocalError has been fixed")
        print("✅ App can be imported and created successfully")
        print("✅ Environment variables are handled correctly")
        return 0
    else:
        print("\n💥 SOME TESTS FAILED!")
        print("❌ The app import issue needs further investigation")
        return 1

if __name__ == '__main__':
    sys.exit(main())
