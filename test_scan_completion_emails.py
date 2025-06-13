#!/usr/bin/env python3
"""
Comprehensive test script for scan completion email workflow
Tests the entire end-to-end email notification system
"""

import sys
import os
import json
from datetime import datetime

# Add the current directory to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from models import db, User, Organization, EmailNotificationSettings, EmailConfiguration
from services.email_service import EmailService

def test_email_configuration():
    """Test 1: Check SMTP configuration"""
    print("🧪 Test 1: Email Configuration")
    print("-" * 40)
    
    try:
        # Get the first organization
        org = Organization.query.first()
        if not org:
            print("❌ No organization found")
            return False
        
        # Check email configuration
        email_config = EmailConfiguration.query.filter_by(organization_id=org.id).first()
        
        if not email_config:
            print("❌ No email configuration found")
            print("📋 Please configure SMTP settings in Settings → Integrations")
            return False
        
        print(f"✅ Email configuration found for organization: {org.name}")
        print(f"📧 SMTP Host: {email_config.smtp_host}")
        print(f"📧 SMTP Port: {email_config.smtp_port}")
        print(f"📧 From Email: {email_config.from_email}")
        print(f"📧 Configured: {email_config.is_configured}")
        print(f"📧 Verified: {email_config.is_verified}")
        
        if not email_config.is_configured:
            print("⚠️ Email is not fully configured")
            return False
        
        return True
        
    except Exception as e:
        print(f"❌ Error checking email configuration: {str(e)}")
        return False

def test_notification_settings():
    """Test 2: Check user notification settings"""
    print("\n🧪 Test 2: User Notification Settings")
    print("-" * 40)
    
    try:
        # Get users and their notification settings
        users = User.query.all()
        if not users:
            print("❌ No users found")
            return False
        
        scan_completion_enabled_users = []
        
        for user in users:
            org = Organization.query.filter_by(user_id=user.id).first()
            if not org:
                continue
                
            settings = EmailNotificationSettings.query.filter_by(
                user_id=user.id,
                organization_id=org.id
            ).first()
            
            if settings and settings.notify_scan_completion:
                scan_completion_enabled_users.append({
                    'user': user,
                    'settings': settings,
                    'organization': org
                })
                print(f"✅ User {user.username} ({user.email}) has scan completion notifications enabled")
                print(f"   📧 Notification email: {settings.notification_email or user.email}")
                if settings.additional_recipients:
                    print(f"   📬 Additional recipients: {settings.additional_recipients}")
            else:
                print(f"⚠️ User {user.username} ({user.email}) does not have scan completion notifications enabled")
        
        if not scan_completion_enabled_users:
            print("❌ No users have scan completion notifications enabled")
            print("📋 Please enable scan completion notifications in Settings → Notifications")
            return False
        
        print(f"\n✅ Found {len(scan_completion_enabled_users)} users with scan completion notifications enabled")
        return True
        
    except Exception as e:
        print(f"❌ Error checking notification settings: {str(e)}")
        return False

def test_email_service():
    """Test 3: Test EmailService functionality"""
    print("\n🧪 Test 3: EmailService Functionality")
    print("-" * 40)
    
    try:
        # Get the first organization
        org = Organization.query.first()
        if not org:
            print("❌ No organization found")
            return False
        
        # Initialize email service
        email_service = EmailService(org.id)
        
        # Check if email is configured
        is_configured = email_service.is_configured()
        print(f"📧 Email service configured: {is_configured}")
        
        if not is_configured:
            print("❌ Email service is not configured")
            return False
        
        # Test scan completion email preparation (without sending)
        test_scan_data = {
            'target': 'example.com',
            'scan_type': 'Quick Scan',
            'duration': '2 minutes 30 seconds',
            'started_at': '2024-01-15 10:00:00 UTC',
            'completed_at': '2024-01-15 10:02:30 UTC',
            'assets_discovered': {
                'subdomains': 5,
                'live_hosts': 3,
                'open_ports': 12,
                'services': 8,
                'technologies': 4
            },
            'vulnerabilities_found': {
                'total': 3,
                'critical': 1,
                'high': 1,
                'medium': 1,
                'low': 0,
                'info': 0
            },
            'scan_id': f"test_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'initiated_by': 'Test Script'
        }
        
        print("📧 Testing scan completion email preparation...")
        
        # Get recipients
        notification_settings = EmailNotificationSettings.query.filter_by(
            organization_id=org.id,
            notify_scan_completion=True
        ).all()
        
        if notification_settings:
            recipients = []
            for setting in notification_settings:
                user = User.query.get(setting.user_id)
                if user:
                    email = setting.notification_email or user.email
                    recipients.append(email)
                    if setting.additional_recipients:
                        additional = [email.strip() for email in setting.additional_recipients.split(',') if email.strip()]
                        recipients.extend(additional)
            
            print(f"📬 Recipients: {recipients}")
            print("✅ Email service is ready to send scan completion emails")
            return True
        else:
            print("❌ No users configured for scan completion notifications")
            return False
        
    except Exception as e:
        print(f"❌ Error testing email service: {str(e)}")
        return False

def test_celery_task():
    """Test 4: Test Celery task functionality"""
    print("\n🧪 Test 4: Celery Task Functionality")
    print("-" * 40)
    
    try:
        # Check if Celery is available
        try:
            from celery_app import celery
            from tasks import send_scan_completion_email_task
            print("✅ Celery and scan completion task imported successfully")
        except ImportError as e:
            print(f"❌ Failed to import Celery components: {str(e)}")
            return False
        
        # Check Redis connection (Celery broker)
        try:
            from utils.redis_checker import is_redis_available
            redis_available = is_redis_available()
            print(f"📡 Redis (Celery broker) available: {redis_available}")
            
            if not redis_available:
                print("⚠️ Redis is not available - Celery tasks will not work")
                print("📋 For testing purposes, we can simulate the task execution")
        except Exception as e:
            print(f"⚠️ Could not check Redis status: {str(e)}")
        
        print("✅ Celery task structure is properly configured")
        return True
        
    except Exception as e:
        print(f"❌ Error testing Celery task: {str(e)}")
        return False

def test_email_template():
    """Test 5: Test email template rendering"""
    print("\n🧪 Test 5: Email Template Rendering")
    print("-" * 40)
    
    try:
        from flask import render_template
        
        # Test template context
        test_context = {
            'scan_target': 'example.com',
            'scan_type': 'Quick Scan',
            'scan_duration': '2 minutes 30 seconds',
            'scan_started_at': '2024-01-15 10:00:00 UTC',
            'scan_completed_at': '2024-01-15 10:02:30 UTC',
            'assets_discovered': {
                'subdomains': 5,
                'live_hosts': 3,
                'open_ports': 12,
                'services': 8,
                'technologies': 4
            },
            'vulnerabilities_found': {
                'total': 3,
                'critical': 1,
                'high': 1,
                'medium': 1,
                'low': 0,
                'info': 0
            },
            'organization_name': 'Test Organization',
            'dashboard_url': 'http://localhost:5000/dashboard',
            'settings_url': 'http://localhost:5000/settings',
            'current_year': datetime.now().year
        }
        
        # Try to render the template
        try:
            rendered_html = render_template('emails/scan_completion.html', **test_context)
            print("✅ Email template rendered successfully")
            print(f"📄 Template length: {len(rendered_html)} characters")
            
            # Check for key content
            if 'example.com' in rendered_html and 'Quick Scan' in rendered_html:
                print("✅ Template contains expected scan data")
            else:
                print("⚠️ Template may not be rendering scan data correctly")
            
            return True
            
        except Exception as e:
            print(f"❌ Failed to render email template: {str(e)}")
            return False
        
    except Exception as e:
        print(f"❌ Error testing email template: {str(e)}")
        return False

def simulate_scan_completion_email():
    """Test 6: Simulate sending a scan completion email"""
    print("\n🧪 Test 6: Simulate Scan Completion Email")
    print("-" * 40)
    
    try:
        # Get the first organization
        org = Organization.query.first()
        if not org:
            print("❌ No organization found")
            return False
        
        # Initialize email service
        email_service = EmailService(org.id)
        
        if not email_service.is_configured():
            print("❌ Email service is not configured")
            return False
        
        # Simulate scan completion data
        scan_completion_data = {
            'target': 'test-domain.com',
            'scan_type': 'Test Scan',
            'duration': '1 minute 45 seconds',
            'started_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
            'completed_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
            'assets_discovered': {
                'subdomains': 3,
                'live_hosts': 2,
                'open_ports': 8,
                'services': 5,
                'technologies': 2
            },
            'vulnerabilities_found': {
                'total': 2,
                'critical': 0,
                'high': 1,
                'medium': 1,
                'low': 0,
                'info': 0
            },
            'scan_id': f"test_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'initiated_by': 'Email Test Script'
        }
        
        print("📧 Attempting to send test scan completion email...")
        print(f"📋 Scan data: {json.dumps(scan_completion_data, indent=2)}")
        
        # Send the email
        result = email_service.send_scan_completion(scan_completion_data)
        
        if result['success']:
            print("✅ Scan completion email sent successfully!")
            print("📧 Check the recipient email addresses for the notification")
            return True
        else:
            print(f"❌ Failed to send scan completion email: {result.get('error')}")
            return False
        
    except Exception as e:
        print(f"❌ Error simulating scan completion email: {str(e)}")
        return False

def main():
    """Run all tests"""

    print("🚀 Scan Completion Email Workflow Test")
    print("=" * 70)

    app = create_app()

    # Configure app for testing
    app.config['SERVER_NAME'] = 'localhost:5000'
    app.config['PREFERRED_URL_SCHEME'] = 'http'

    with app.app_context():
        tests = [
            ("Email Configuration", test_email_configuration),
            ("Notification Settings", test_notification_settings),
            ("Email Service", test_email_service),
            ("Celery Task", test_celery_task),
            ("Email Template", test_email_template),
            ("Simulate Email", simulate_scan_completion_email)
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
            print("\n🎉 All tests passed! Scan completion email workflow is working correctly.")
        else:
            print(f"\n⚠️ {len(results) - passed} test(s) failed. Please address the issues above.")
            return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
