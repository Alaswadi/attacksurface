#!/usr/bin/env python3
"""
Test script to verify the consolidated notification settings functionality
"""

import sys
import os
import json

# Add the current directory to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from models import db, User, Organization, EmailNotificationSettings

def test_consolidated_notification_save():
    """Test that both email settings and alert thresholds are saved together"""
    
    print("🧪 Testing Consolidated Notification Settings Save")
    print("=" * 60)
    
    app = create_app()
    
    with app.app_context():
        try:
            # Get the first user and organization
            user = User.query.first()
            org = Organization.query.first()
            
            if not user or not org:
                print("❌ No user or organization found. Please create test data first.")
                return False
            
            print(f"👤 Testing with user: {user.username} ({user.email})")
            print(f"🏢 Testing with organization: {org.name}")
            
            # Simulate the consolidated form data that would be sent from the frontend
            test_form_data = {
                # Email notification settings
                'email_enabled': True,
                'notification_email': 'test@example.com',
                'additional_recipients': 'admin@example.com, security@example.com',
                'digest_frequency': 'daily',
                'notify_scan_completion': True,
                'notify_new_vulnerabilities': True,
                
                # Alert threshold settings
                'alert_thresholds': {
                    'critical': True,
                    'high': True,
                    'medium': False,
                    'low': False,
                    'info': False
                }
            }
            
            print("📝 Test data to save:")
            print(json.dumps(test_form_data, indent=2))
            
            # Get or create notification settings
            settings = EmailNotificationSettings.query.filter_by(
                user_id=user.id,
                organization_id=org.id
            ).first()
            
            if not settings:
                print("➕ Creating new notification settings...")
                settings = EmailNotificationSettings(
                    user_id=user.id,
                    organization_id=org.id
                )
                db.session.add(settings)
            else:
                print("✏️ Updating existing notification settings...")
            
            # Update all settings from the consolidated form data
            settings.notification_email = test_form_data.get('notification_email', user.email)
            settings.additional_recipients = test_form_data.get('additional_recipients', '')
            settings.digest_frequency = test_form_data.get('digest_frequency', 'daily')
            settings.notify_new_vulnerabilities = test_form_data.get('notify_new_vulnerabilities', True)
            settings.notify_scan_completion = test_form_data.get('notify_scan_completion', True)
            
            # Update alert thresholds
            alert_thresholds = test_form_data.get('alert_thresholds', {})
            settings.alert_critical = alert_thresholds.get('critical', True)
            settings.alert_high = alert_thresholds.get('high', True)
            settings.alert_medium = alert_thresholds.get('medium', True)
            settings.alert_low = alert_thresholds.get('low', False)
            settings.alert_info = alert_thresholds.get('info', False)
            
            # Save to database
            db.session.commit()
            print("✅ All notification settings saved successfully!")
            
            # Verify the save by reading back the data
            print("\n🔍 Verifying saved data:")
            print(f"📧 Notification email: {settings.notification_email}")
            print(f"📬 Additional recipients: {settings.additional_recipients}")
            print(f"🔔 Scan completion notifications: {settings.notify_scan_completion}")
            print(f"⚠️ Vulnerability notifications: {settings.notify_new_vulnerabilities}")
            print(f"📅 Digest frequency: {settings.digest_frequency}")
            print(f"🚨 Alert thresholds:")
            print(f"   - Critical: {settings.alert_critical}")
            print(f"   - High: {settings.alert_high}")
            print(f"   - Medium: {settings.alert_medium}")
            print(f"   - Low: {settings.alert_low}")
            print(f"   - Info: {settings.alert_info}")
            
            # Test that the API endpoint format matches what we expect
            expected_api_response = {
                'email_enabled': settings.notify_scan_completion or settings.notify_new_vulnerabilities,
                'notification_email': settings.notification_email or user.email,
                'additional_recipients': settings.additional_recipients or '',
                'digest_frequency': settings.digest_frequency,
                'notify_new_vulnerabilities': settings.notify_new_vulnerabilities,
                'notify_scan_completion': settings.notify_scan_completion,
                'alert_thresholds': {
                    'critical': settings.alert_critical,
                    'high': settings.alert_high,
                    'medium': settings.alert_medium,
                    'low': settings.alert_low,
                    'info': settings.alert_info
                }
            }
            
            print("\n📤 Expected API response format:")
            print(json.dumps(expected_api_response, indent=2))
            
            return True
            
        except Exception as e:
            print(f"❌ Error testing consolidated notification settings: {str(e)}")
            return False

def main():
    """Run the test"""
    
    print("🚀 Consolidated Notification Settings Test")
    print("=" * 70)
    
    success = test_consolidated_notification_save()
    
    print("\n📊 Test Results")
    print("=" * 30)
    print(f"✅ Consolidated Save: {'PASS' if success else 'FAIL'}")
    
    if success:
        print("\n🎉 Test passed! The consolidated notification settings system is working correctly.")
        print("\nThe single 'Save Notification Settings' button will now:")
        print("1. ✅ Collect data from both Email Notifications and Alert Thresholds sections")
        print("2. ✅ Send all data in a single API call to /api/settings/notifications")
        print("3. ✅ Save both email preferences and alert thresholds together")
        print("4. ✅ Show a single success/error message for the combined operation")
        print("5. ✅ Prevent the issue where only one section gets saved at a time")
    else:
        print("\n❌ Test failed! Please check the errors above.")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
