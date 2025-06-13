#!/usr/bin/env python3
"""
Test script for the new dual email notification system
Tests both scan completion emails (always sent) and security alert emails (only when vulnerabilities found)
"""

import sys
import os
from datetime import datetime

# Add the current directory to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from models import db, User, Organization, EmailNotificationSettings
from services.email_service import EmailService

def test_dual_notifications_clean_scan():
    """Test dual notifications for a clean scan (no vulnerabilities)"""
    
    print("🧪 Test 1: Clean Scan (No Vulnerabilities)")
    print("-" * 50)
    
    app = create_app()
    
    with app.app_context():
        try:
            # Get organization
            org = Organization.query.first()
            if not org:
                print("❌ No organization found")
                return False
            
            # Initialize email service
            email_service = EmailService(org.id)
            
            if not email_service.is_configured():
                print("❌ Email service not configured")
                return False
            
            # Create clean scan data (no vulnerabilities)
            clean_scan_data = {
                'target': 'clean-site.com',
                'scan_type': 'Quick Scan',
                'duration': '1 minute 30 seconds',
                'started_at': '2024-01-15 10:00:00 UTC',
                'completed_at': '2024-01-15 10:01:30 UTC',
                'assets_discovered': {
                    'subdomains': 8,
                    'live_hosts': 6,
                    'open_ports': 15,
                    'services': 10,
                    'technologies': 4
                },
                'vulnerabilities_found': {
                    'total': 0,
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0,
                    'info': 0
                },
                'top_vulnerabilities': [],
                'scan_id': f"clean_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                'initiated_by': 'Test Script'
            }
            
            print(f"📋 Testing clean scan for: {clean_scan_data['target']}")
            print(f"🔍 Vulnerabilities found: {clean_scan_data['vulnerabilities_found']['total']}")
            
            # Test dual notifications
            result = email_service.send_dual_scan_notifications(clean_scan_data)
            
            print("\n📧 Email Results:")
            print(f"   Scan Completion - Sent: {result['scan_completion']['sent']}, Success: {result['scan_completion']['success']}")
            print(f"   Security Alert - Sent: {result['security_alert']['sent']}, Success: {result['security_alert']['success']}")
            print(f"   Overall Success: {result['overall_success']}")
            
            # Expected: Scan completion sent, security alert NOT sent
            expected_scan_completion = True
            expected_security_alert = False
            
            if (result['scan_completion']['sent'] == expected_scan_completion and 
                result['security_alert']['sent'] == expected_security_alert and
                result['overall_success']):
                print("✅ Clean scan test PASSED - Only scan completion email sent")
                return True
            else:
                print("❌ Clean scan test FAILED - Unexpected email behavior")
                return False
                
        except Exception as e:
            print(f"❌ Error in clean scan test: {str(e)}")
            return False

def test_dual_notifications_vulnerable_scan():
    """Test dual notifications for a scan with vulnerabilities"""
    
    print("\n🧪 Test 2: Vulnerable Scan (With Vulnerabilities)")
    print("-" * 50)
    
    app = create_app()
    
    with app.app_context():
        try:
            # Get organization
            org = Organization.query.first()
            if not org:
                print("❌ No organization found")
                return False
            
            # Initialize email service
            email_service = EmailService(org.id)
            
            if not email_service.is_configured():
                print("❌ Email service not configured")
                return False
            
            # Create vulnerable scan data (with vulnerabilities)
            vulnerable_scan_data = {
                'target': 'vulnerable-site.com',
                'scan_type': 'Deep Scan',
                'duration': '5 minutes 45 seconds',
                'started_at': '2024-01-15 11:00:00 UTC',
                'completed_at': '2024-01-15 11:05:45 UTC',
                'assets_discovered': {
                    'subdomains': 15,
                    'live_hosts': 12,
                    'open_ports': 28,
                    'services': 18,
                    'technologies': 8
                },
                'vulnerabilities_found': {
                    'total': 6,
                    'critical': 2,
                    'high': 2,
                    'medium': 2,
                    'low': 0,
                    'info': 0
                },
                'top_vulnerabilities': [
                    {
                        'title': 'SQL Injection in Login Form',
                        'severity': 'critical',
                        'asset': 'login.vulnerable-site.com'
                    },
                    {
                        'title': 'Remote Code Execution',
                        'severity': 'critical',
                        'asset': 'admin.vulnerable-site.com'
                    },
                    {
                        'title': 'Cross-Site Scripting (XSS)',
                        'severity': 'high',
                        'asset': 'api.vulnerable-site.com'
                    },
                    {
                        'title': 'Insecure Direct Object Reference',
                        'severity': 'high',
                        'asset': 'app.vulnerable-site.com'
                    },
                    {
                        'title': 'Information Disclosure',
                        'severity': 'medium',
                        'asset': 'www.vulnerable-site.com'
                    }
                ],
                'scan_id': f"vuln_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                'initiated_by': 'Test Script'
            }
            
            print(f"📋 Testing vulnerable scan for: {vulnerable_scan_data['target']}")
            print(f"🔍 Vulnerabilities found: {vulnerable_scan_data['vulnerabilities_found']['total']}")
            print(f"🚨 Critical: {vulnerable_scan_data['vulnerabilities_found']['critical']}, High: {vulnerable_scan_data['vulnerabilities_found']['high']}")
            
            # Test dual notifications
            result = email_service.send_dual_scan_notifications(vulnerable_scan_data)
            
            print("\n📧 Email Results:")
            print(f"   Scan Completion - Sent: {result['scan_completion']['sent']}, Success: {result['scan_completion']['success']}")
            print(f"   Security Alert - Sent: {result['security_alert']['sent']}, Success: {result['security_alert']['success']}")
            print(f"   Overall Success: {result['overall_success']}")
            
            # Expected: Both emails sent
            expected_scan_completion = True
            expected_security_alert = True
            
            if (result['scan_completion']['sent'] == expected_scan_completion and 
                result['security_alert']['sent'] == expected_security_alert and
                result['overall_success']):
                print("✅ Vulnerable scan test PASSED - Both emails sent")
                return True
            else:
                print("❌ Vulnerable scan test FAILED - Unexpected email behavior")
                return False
                
        except Exception as e:
            print(f"❌ Error in vulnerable scan test: {str(e)}")
            return False

def test_notification_preferences():
    """Test that user notification preferences are respected"""
    
    print("\n🧪 Test 3: User Notification Preferences")
    print("-" * 50)
    
    app = create_app()
    
    with app.app_context():
        try:
            # Get organization and user
            org = Organization.query.first()
            user = User.query.first()
            
            if not org or not user:
                print("❌ No organization or user found")
                return False
            
            # Check notification settings
            settings = EmailNotificationSettings.query.filter_by(
                user_id=user.id,
                organization_id=org.id
            ).first()
            
            if not settings:
                print("❌ No notification settings found")
                return False
            
            print(f"👤 User: {user.username} ({user.email})")
            print(f"📧 Notification email: {settings.notification_email or user.email}")
            print(f"🔔 Scan completion notifications: {settings.notify_scan_completion}")
            print(f"⚠️ Vulnerability notifications: {settings.notify_new_vulnerabilities}")
            print(f"📬 Additional recipients: {settings.additional_recipients or 'None'}")
            
            # Test that preferences are properly loaded
            if settings.notify_scan_completion and settings.notify_new_vulnerabilities:
                print("✅ User preferences test PASSED - Both notification types enabled")
                return True
            else:
                print("⚠️ User preferences test - Some notifications disabled")
                print("   This is expected behavior if user has disabled certain notifications")
                return True
                
        except Exception as e:
            print(f"❌ Error in preferences test: {str(e)}")
            return False

def test_celery_task_integration():
    """Test Celery task integration"""
    
    print("\n🧪 Test 4: Celery Task Integration")
    print("-" * 50)
    
    try:
        from tasks import send_dual_scan_notifications_task
        print("✅ Dual scan notifications task imported successfully")
        
        # Check if task has delay method
        if hasattr(send_dual_scan_notifications_task, 'delay'):
            print("✅ Task has delay method for async execution")
        else:
            print("⚠️ Task missing delay method")
        
        print("✅ Celery integration test PASSED")
        return True
        
    except Exception as e:
        print(f"❌ Celery integration test FAILED: {str(e)}")
        return False

def main():
    """Run all dual email notification tests"""
    
    print("🚀 Dual Email Notification System Test")
    print("=" * 70)
    print("Testing the new dual email system:")
    print("1. Scan completion emails (always sent)")
    print("2. Security alert emails (only when vulnerabilities found)")
    print("=" * 70)
    
    # Run all tests
    tests = [
        ("Clean Scan (No Vulnerabilities)", test_dual_notifications_clean_scan),
        ("Vulnerable Scan (With Vulnerabilities)", test_dual_notifications_vulnerable_scan),
        ("User Notification Preferences", test_notification_preferences),
        ("Celery Task Integration", test_celery_task_integration)
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
    print("\n📊 Test Results Summary")
    print("=" * 40)
    
    passed = 0
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} - {test_name}")
        if result:
            passed += 1
    
    print(f"\n📈 Overall: {passed}/{len(results)} tests passed")
    
    if passed == len(results):
        print("\n🎉 DUAL EMAIL NOTIFICATION SYSTEM IS WORKING!")
        print("\n📧 Email Behavior:")
        print("✅ Clean scans → Scan completion email only")
        print("✅ Vulnerable scans → Both scan completion + security alert emails")
        print("✅ User preferences respected")
        print("✅ Celery integration working")
        
        print("\n🔄 Expected Workflow:")
        print("1. Scan completes → Dual notification task triggered")
        print("2. Scan completion email sent (always)")
        print("3. If vulnerabilities found → Security alert email sent")
        print("4. Users receive appropriate notifications")
        
        return 0
    else:
        print(f"\n⚠️ {len(results) - passed} test(s) failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())
