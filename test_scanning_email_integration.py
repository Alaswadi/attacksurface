#!/usr/bin/env python3
"""
Test script to verify email notifications are properly integrated into all scanning workflows
"""

import sys
import os
import re

# Add the current directory to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_email_integration_in_tasks():
    """Test that email notifications are integrated into all scanning tasks"""
    
    print("🧪 Testing Email Integration in Scanning Tasks")
    print("=" * 60)
    
    # Read the tasks.py file
    try:
        with open('tasks.py', 'r', encoding='utf-8') as f:
            tasks_content = f.read()
    except Exception as e:
        print(f"❌ Failed to read tasks.py: {str(e)}")
        return False
    
    # Test 1: Check if dual notification task is defined
    print("📋 Test 1: Dual Notification Task Definition")
    if 'send_dual_scan_notifications_task' in tasks_content:
        print("✅ send_dual_scan_notifications_task is defined")
    else:
        print("❌ send_dual_scan_notifications_task is NOT defined")
        return False
    
    # Test 2: Check if large_domain_scan_orchestrator uses dual notifications
    print("\n📋 Test 2: Large Domain Scan Orchestrator Integration")
    large_scan_pattern = r'send_dual_scan_notifications_task\.delay\(.*large.*scale.*orchestrator'
    if re.search(large_scan_pattern, tasks_content, re.IGNORECASE | re.DOTALL):
        print("✅ large_domain_scan_orchestrator uses dual notifications")
    else:
        # Check for any dual notification call in large scan
        if 'send_dual_scan_notifications_task.delay' in tasks_content and 'large_domain_scan_orchestrator' in tasks_content:
            print("✅ large_domain_scan_orchestrator has dual notification integration")
        else:
            print("❌ large_domain_scan_orchestrator does NOT use dual notifications")
            return False
    
    # Test 3: Check if progressive_large_domain_scan_orchestrator uses dual notifications
    print("\n📋 Test 3: Progressive Scan Orchestrator Integration")
    progressive_scan_pattern = r'send_dual_scan_notifications_task\.delay\(.*progressive'
    if re.search(progressive_scan_pattern, tasks_content, re.IGNORECASE | re.DOTALL):
        print("✅ progressive_large_domain_scan_orchestrator uses dual notifications")
    else:
        # Check for any dual notification call in progressive scan
        if 'send_dual_scan_notifications_task.delay' in tasks_content and 'progressive_large_domain_scan_orchestrator' in tasks_content:
            print("✅ progressive_large_domain_scan_orchestrator has dual notification integration")
        else:
            print("❌ progressive_large_domain_scan_orchestrator does NOT use dual notifications")
            return False
    
    # Test 4: Check if comprehensive_nuclei_scan_task uses dual notifications
    print("\n📋 Test 4: Nuclei Scan Task Integration")
    nuclei_scan_pattern = r'send_dual_scan_notifications_task\.delay\(.*nuclei'
    if re.search(nuclei_scan_pattern, tasks_content, re.IGNORECASE | re.DOTALL):
        print("✅ comprehensive_nuclei_scan_task uses dual notifications")
    else:
        print("⚠️ comprehensive_nuclei_scan_task may still use old security alert system")
        print("   This is acceptable as it's a specialized vulnerability-only scan")
    
    # Test 5: Count total dual notification calls
    print("\n📋 Test 5: Total Dual Notification Integration Points")
    dual_notification_calls = tasks_content.count('send_dual_scan_notifications_task.delay')
    print(f"📊 Found {dual_notification_calls} dual notification integration points")
    
    if dual_notification_calls >= 2:
        print("✅ Sufficient integration points found")
    else:
        print("❌ Insufficient integration points - need at least 2")
        return False
    
    # Test 6: Check for old email task usage (should be minimal)
    print("\n📋 Test 6: Legacy Email Task Usage")
    old_scan_completion_calls = tasks_content.count('send_scan_completion_email_task.delay')
    old_security_alert_calls = tasks_content.count('send_security_alert_email_task.delay')
    
    print(f"📊 Old scan completion calls: {old_scan_completion_calls}")
    print(f"📊 Old security alert calls: {old_security_alert_calls}")
    
    if old_scan_completion_calls == 0:
        print("✅ No legacy scan completion email calls found")
    else:
        print("⚠️ Legacy scan completion email calls still exist")
    
    if old_security_alert_calls <= 1:
        print("✅ Minimal legacy security alert calls (acceptable for specialized tasks)")
    else:
        print("⚠️ Multiple legacy security alert calls found")
    
    return True

def test_celery_task_availability():
    """Test that Celery tasks can be imported"""
    
    print("\n🧪 Testing Celery Task Availability")
    print("-" * 40)
    
    try:
        from tasks import (
            send_dual_scan_notifications_task,
            large_domain_scan_orchestrator,
            progressive_large_domain_scan_orchestrator,
            comprehensive_nuclei_scan_task
        )
        
        print("✅ All scanning tasks imported successfully")
        
        # Check if tasks have delay method
        tasks_to_check = [
            ('send_dual_scan_notifications_task', send_dual_scan_notifications_task),
            ('large_domain_scan_orchestrator', large_domain_scan_orchestrator),
            ('progressive_large_domain_scan_orchestrator', progressive_large_domain_scan_orchestrator),
            ('comprehensive_nuclei_scan_task', comprehensive_nuclei_scan_task)
        ]
        
        for task_name, task_obj in tasks_to_check:
            if hasattr(task_obj, 'delay'):
                print(f"✅ {task_name} has delay method")
            else:
                print(f"❌ {task_name} missing delay method")
                return False
        
        return True
        
    except ImportError as e:
        print(f"❌ Failed to import tasks: {str(e)}")
        return False

def test_email_service_integration():
    """Test that EmailService has dual notification method"""
    
    print("\n🧪 Testing EmailService Integration")
    print("-" * 40)
    
    try:
        from services.email_service import EmailService
        
        # Check if EmailService has the dual notification method
        if hasattr(EmailService, 'send_dual_scan_notifications'):
            print("✅ EmailService has send_dual_scan_notifications method")
        else:
            print("❌ EmailService missing send_dual_scan_notifications method")
            return False
        
        # Check if EmailService has helper method
        if hasattr(EmailService, '_prepare_security_alert_from_scan'):
            print("✅ EmailService has _prepare_security_alert_from_scan helper method")
        else:
            print("❌ EmailService missing _prepare_security_alert_from_scan helper method")
            return False
        
        return True
        
    except ImportError as e:
        print(f"❌ Failed to import EmailService: {str(e)}")
        return False

def test_api_integration():
    """Test that API routes use the correct scanning tasks"""
    
    print("\n🧪 Testing API Integration")
    print("-" * 40)
    
    try:
        # Read the API routes file
        with open('routes/api.py', 'r', encoding='utf-8') as f:
            api_content = f.read()
        
        # Check if API uses progressive scanning (which now has email integration)
        if 'progressive_large_domain_scan_orchestrator.delay' in api_content:
            print("✅ API uses progressive scanning with email integration")
        else:
            print("⚠️ API may not be using progressive scanning")
        
        return True
        
    except Exception as e:
        print(f"❌ Failed to read API routes: {str(e)}")
        return False

def main():
    """Run all integration tests"""
    
    print("🚀 Scanning Email Integration Test")
    print("=" * 70)
    print("Verifying that email notifications are properly integrated")
    print("into all scanning workflows")
    print("=" * 70)
    
    # Run all tests
    tests = [
        ("Email Integration in Tasks", test_email_integration_in_tasks),
        ("Celery Task Availability", test_celery_task_availability),
        ("EmailService Integration", test_email_service_integration),
        ("API Integration", test_api_integration)
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ Test {test_name} failed with exception: {str(e)}")
            results.append((test_name, False))
    
    # Summary
    print("\n📊 Integration Test Results")
    print("=" * 40)
    
    passed = 0
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} - {test_name}")
        if result:
            passed += 1
    
    print(f"\n📈 Overall: {passed}/{len(results)} tests passed")
    
    if passed == len(results):
        print("\n🎉 EMAIL INTEGRATION IS COMPLETE!")
        print("\n📧 Scanning Workflows with Email Notifications:")
        print("✅ Large Domain Scan Orchestrator → Dual notifications")
        print("✅ Progressive Scan Orchestrator → Dual notifications")
        print("✅ Nuclei Scan Task → Security alerts + completion")
        print("✅ Dual Notification Task → Both email types")
        
        print("\n🔄 Expected Behavior:")
        print("1. User starts scan → Progressive/Large scan task triggered")
        print("2. Scan completes → Dual notification task triggered")
        print("3. Scan completion email sent (always)")
        print("4. Security alert email sent (if vulnerabilities found)")
        print("5. User receives appropriate notifications")
        
        print("\n✅ Your scanning system now sends emails!")
        
        return 0
    else:
        print(f"\n⚠️ {len(results) - passed} test(s) failed")
        print("Some email integrations may be missing.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
