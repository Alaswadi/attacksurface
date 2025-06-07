#!/usr/bin/env python3
"""
Test script to verify Celery integration
"""

import sys
import os

def test_celery_import():
    """Test if Celery app can be imported"""
    try:
        from celery_app import celery
        print("✅ Celery app imported successfully")
        print(f"   Broker: {celery.conf.broker_url}")
        print(f"   Backend: {celery.conf.result_backend}")
        return True
    except Exception as e:
        print(f"❌ Failed to import Celery app: {e}")
        return False

def test_tasks_import():
    """Test if tasks can be imported"""
    try:
        from tasks import test_task, scan_domain_task, process_scan_results_task
        print("✅ Tasks imported successfully")
        return True
    except Exception as e:
        print(f"❌ Failed to import tasks: {e}")
        return False

def test_flask_app():
    """Test if Flask app can be created"""
    try:
        from app import create_app
        app = create_app()
        print("✅ Flask app created successfully")
        print(f"   Config: {app.config.get('FLASK_CONFIG', 'default')}")
        return True
    except Exception as e:
        print(f"❌ Failed to create Flask app: {e}")
        return False

def test_celery_tasks_registration():
    """Test if tasks are registered with Celery"""
    try:
        from celery_app import celery
        task_names = list(celery.tasks.keys())
        custom_tasks = [name for name in task_names if name.startswith('tasks.')]
        
        print("✅ Celery tasks registered:")
        for task in custom_tasks:
            print(f"   - {task}")
        
        expected_tasks = [
            'tasks.test_task',
            'tasks.scan_domain_task', 
            'tasks.process_scan_results_task',
            'tasks.cleanup_old_data_task',
            'tasks.send_notification_task',
            'tasks.periodic_health_check'
        ]
        
        missing_tasks = [task for task in expected_tasks if task not in task_names]
        if missing_tasks:
            print(f"⚠️  Missing tasks: {missing_tasks}")
            return False
        
        return True
    except Exception as e:
        print(f"❌ Failed to check task registration: {e}")
        return False

def main():
    """Run all tests"""
    print("🧪 Testing Celery Integration")
    print("=" * 50)
    
    tests = [
        ("Flask App Creation", test_flask_app),
        ("Celery Import", test_celery_import),
        ("Tasks Import", test_tasks_import),
        ("Task Registration", test_celery_tasks_registration),
    ]
    
    results = []
    for test_name, test_func in tests:
        print(f"\n📋 {test_name}:")
        result = test_func()
        results.append(result)
    
    print("\n" + "=" * 50)
    print("📊 Test Summary:")
    
    passed = sum(results)
    total = len(results)
    
    if passed == total:
        print(f"✅ All tests passed ({passed}/{total})")
        print("🎉 Celery integration is working correctly!")
        return 0
    else:
        print(f"❌ {total - passed} tests failed ({passed}/{total} passed)")
        print("🔧 Please fix the issues before deploying")
        return 1

if __name__ == '__main__':
    sys.exit(main())
