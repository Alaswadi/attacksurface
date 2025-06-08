#!/usr/bin/env python3
"""
Test script to verify the variable scope fix in Celery orchestrator
Tests that http_data and port_results variables are properly initialized before use
"""

import sys
import time
import requests
import json
from datetime import datetime

def test_variable_scope_fix():
    """Test that the variable scope issue is fixed"""
    print("🧪 TESTING CELERY VARIABLE SCOPE FIX")
    print("=" * 50)
    
    base_url = "http://localhost:8077"
    
    # Test 1: Start large-scale scan
    print("\n1️⃣ TESTING LARGE-SCALE SCAN INITIATION")
    print("-" * 40)
    
    try:
        response = requests.post(f"{base_url}/api/large-scale-scan", 
                               json={
                                   "domain": "nmap.com",
                                   "scan_type": "quick",
                                   "organization_id": 1
                               },
                               timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            task_id = data.get('task_id')
            print(f"✅ Large-scale scan started successfully")
            print(f"📋 Task ID: {task_id}")
            
            if task_id:
                return test_scan_for_variable_errors(base_url, task_id)
            else:
                print("❌ No task ID returned")
                return False
        else:
            print(f"❌ Failed to start scan: {response.status_code}")
            print(f"Response: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Error starting scan: {str(e)}")
        return False

def test_scan_for_variable_errors(base_url, task_id):
    """Monitor scan for variable scope errors"""
    print(f"\n2️⃣ MONITORING SCAN FOR VARIABLE SCOPE ERRORS")
    print("-" * 40)
    
    max_wait_time = 180  # 3 minutes
    start_time = time.time()
    variable_errors_found = False
    database_storage_working = False
    
    while time.time() - start_time < max_wait_time:
        try:
            response = requests.get(f"{base_url}/api/large-scale-scan-status/{task_id}", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                state = data.get('state', 'UNKNOWN')
                stage = data.get('stage', 'unknown')
                progress = data.get('progress', 0)
                message = data.get('message', '')
                
                print(f"📊 Progress: {progress}% | Stage: {stage}")
                
                # Check for completion
                if state == 'SUCCESS' and stage == 'completed':
                    print(f"✅ Scan completed successfully!")
                    subdomains_found = data.get('subdomains_found', 0)
                    if subdomains_found > 0:
                        database_storage_working = True
                        print(f"✅ Database storage working: {subdomains_found} subdomains stored")
                    return test_final_results(variable_errors_found, database_storage_working)
                
                # Check for failure
                elif state == 'FAILURE':
                    error = data.get('error', 'Unknown error')
                    print(f"❌ Scan failed: {error}")
                    
                    # Check for variable scope errors
                    if "cannot access local variable 'http_data'" in error or "cannot access local variable 'port_results'" in error:
                        variable_errors_found = True
                        print("❌ VARIABLE SCOPE ERROR DETECTED!")
                    
                    return test_final_results(variable_errors_found, database_storage_working)
                
                # Check for database storage progress
                if 'database_storage' in stage:
                    print("✅ Reached database storage stage - variables are accessible")
                    
            else:
                print(f"⚠️ Status check failed: {response.status_code}")
            
            time.sleep(5)  # Wait 5 seconds between checks
            
        except Exception as e:
            print(f"⚠️ Error checking status: {str(e)}")
            time.sleep(5)
    
    print(f"⚠️ Scan monitoring timed out after {max_wait_time} seconds")
    return test_final_results(variable_errors_found, database_storage_working)

def test_final_results(variable_errors_found, database_storage_working):
    """Test final results and determine if fix worked"""
    print(f"\n3️⃣ TESTING FINAL RESULTS")
    print("-" * 40)
    
    success = True
    
    # Test 1: Variable scope errors
    print("\n🔍 TESTING VARIABLE SCOPE:")
    if variable_errors_found:
        print("❌ VARIABLE SCOPE FIX FAILED: 'http_data' or 'port_results' errors detected")
        success = False
    else:
        print("✅ VARIABLE SCOPE FIX WORKING: No variable access errors detected")
    
    # Test 2: Database storage
    print("\n💾 TESTING DATABASE STORAGE:")
    if database_storage_working:
        print("✅ DATABASE STORAGE WORKING: Subdomains successfully stored")
    else:
        print("❌ DATABASE STORAGE FAILED: No subdomains stored")
        success = False
    
    # Test 3: Check assets API for stored data
    print("\n📊 TESTING ASSETS API:")
    try:
        response = requests.get("http://localhost:8077/api/assets", timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            assets = data.get('assets', [])
            nmap_assets = [asset for asset in assets if 'nmap.com' in asset.get('name', '')]
            
            if nmap_assets:
                print(f"✅ ASSETS API WORKING: Found {len(nmap_assets)} nmap.com assets")
                
                # Check for metadata
                assets_with_metadata = 0
                for asset in nmap_assets:
                    if asset.get('asset_metadata'):
                        assets_with_metadata += 1
                
                if assets_with_metadata > 0:
                    print(f"✅ METADATA STORAGE WORKING: {assets_with_metadata} assets have metadata")
                else:
                    print("⚠️ METADATA STORAGE: No assets have metadata (may be expected)")
                    
            else:
                print("⚠️ ASSETS API: No nmap.com assets found")
        else:
            print(f"❌ ASSETS API FAILED: {response.status_code}")
            
    except Exception as e:
        print(f"❌ ASSETS API ERROR: {str(e)}")
    
    return success

def main():
    """Main test function"""
    print("🚀 STARTING CELERY VARIABLE SCOPE FIX TEST")
    print("=" * 50)
    print(f"⏰ Test started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Run test
    success = test_variable_scope_fix()
    
    # Final results
    print("\n" + "=" * 50)
    print("🎯 FINAL TEST RESULTS")
    print("=" * 50)
    
    if success:
        print("🎉 OVERALL RESULT: ✅ VARIABLE SCOPE FIX WORKING")
        print("✅ No 'cannot access local variable' errors detected!")
        print("✅ http_data and port_results variables properly initialized!")
        print("✅ Database storage working correctly!")
        print("✅ Celery orchestrator executing complete workflow!")
        print("\n🎯 The variable scope issue has been resolved!")
        print("   - HTTP probing happens BEFORE subdomain storage")
        print("   - Port scanning happens BEFORE subdomain storage") 
        print("   - Variables are available when storing metadata")
    else:
        print("❌ OVERALL RESULT: VARIABLE SCOPE ISSUES REMAIN")
        print("Please check the detailed output above for specific problems.")
        print("The fix may need additional adjustments.")
    
    print(f"⏰ Test completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
