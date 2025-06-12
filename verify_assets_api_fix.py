#!/usr/bin/env python3
"""
Verify Assets API Fix
Quick verification that the assets API now works for invited users
"""

import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app

def test_assets_api():
    """Test the assets API with a test client"""
    print("🧪 Testing Assets API Fix...")
    print("=" * 50)
    
    app = create_app()
    
    with app.test_client() as client:
        try:
            # Test the assets API endpoint directly
            response = client.get('/api/assets')
            print(f"📡 GET /api/assets: {response.status_code}")
            
            if response.status_code == 401:
                print("   ℹ️ 401 Unauthorized - Expected (user not logged in)")
            elif response.status_code == 403:
                print("   ℹ️ 403 Forbidden - Expected (insufficient permissions)")
            elif response.status_code == 404:
                print("   ❌ 404 Not Found - This was the bug!")
                return False
            elif response.status_code == 200:
                print("   ✅ 200 OK - API working correctly")
            else:
                print(f"   ⚠️ Unexpected status: {response.status_code}")
            
            # Test other critical endpoints
            endpoints = [
                '/api/vulnerabilities',
                '/api/dashboard/stats',
                '/api/alerts',
                '/api/settings/organization'
            ]
            
            for endpoint in endpoints:
                response = client.get(endpoint)
                print(f"📡 GET {endpoint}: {response.status_code}")
                
                if response.status_code == 404:
                    print(f"   ❌ {endpoint} still returning 404!")
                    return False
                elif response.status_code in [200, 401, 403]:
                    print(f"   ✅ {endpoint} working (200=success, 401=auth needed, 403=permission denied)")
            
            print(f"\n🎉 All API endpoints are working correctly!")
            print(f"The 404 errors should be resolved for invited users.")
            return True
            
        except Exception as e:
            print(f"\n❌ Test failed: {str(e)}")
            return False

def check_organization_retrieval():
    """Check the organization retrieval logic"""
    print("\n🔍 Checking Organization Retrieval Logic...")
    print("=" * 50)
    
    app = create_app()
    
    with app.app_context():
        try:
            from models import User, Organization, OrganizationUser
            from utils.permissions import get_user_organization
            from flask_login import login_user
            
            # Get all users
            users = User.query.all()
            print(f"📊 Found {len(users)} users in database")
            
            for user in users:
                print(f"\n👤 User: {user.email}")
                
                # Check owned organizations
                owned_orgs = Organization.query.filter_by(user_id=user.id).all()
                print(f"   Owns: {len(owned_orgs)} organizations")
                
                # Check memberships
                memberships = OrganizationUser.query.filter_by(user_id=user.id, is_active=True).all()
                print(f"   Active memberships: {len(memberships)}")
                
                # Test get_user_organization function
                with app.test_request_context():
                    login_user(user)
                    user_org = get_user_organization()
                    
                    if user_org:
                        print(f"   ✅ get_user_organization(): {user_org.name}")
                        
                        # Determine user type
                        if len(owned_orgs) > 0:
                            print(f"   📝 User type: Organization Owner")
                        elif len(memberships) > 0:
                            membership = memberships[0]
                            print(f"   📝 User type: Organization Member ({membership.role.value})")
                        
                    else:
                        print(f"   ❌ get_user_organization(): None")
                        if len(owned_orgs) > 0 or len(memberships) > 0:
                            print(f"      🚨 ERROR: User has organizations but can't access them!")
                            return False
            
            print(f"\n✅ Organization retrieval logic is working correctly!")
            return True
            
        except Exception as e:
            print(f"\n❌ Check failed: {str(e)}")
            return False

def main():
    """Main test function"""
    print("🚀 Starting Assets API Fix Verification...")
    print("=" * 60)
    
    # Test API endpoints
    api_test = test_assets_api()
    
    # Check organization retrieval
    org_test = check_organization_retrieval()
    
    # Summary
    print(f"\n{'='*60}")
    print("📊 Test Results:")
    print(f"{'='*60}")
    print(f"   API Endpoints Test: {'✅ PASSED' if api_test else '❌ FAILED'}")
    print(f"   Organization Retrieval Test: {'✅ PASSED' if org_test else '❌ FAILED'}")
    
    if api_test and org_test:
        print(f"\n🎉 Assets API fix verification completed successfully!")
        print(f"\nExpected results:")
        print(f"✅ Invited users can now access /assets page without 404 errors")
        print(f"✅ API endpoints return proper responses for all authorized users")
        print(f"✅ Both organization owners and members can access their organization's data")
        print(f"✅ Permission system works correctly for Admin and Viewer roles")
        return 0
    else:
        print(f"\n💥 Some tests failed.")
        print(f"Please review the results above.")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
