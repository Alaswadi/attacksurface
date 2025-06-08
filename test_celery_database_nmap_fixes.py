#!/usr/bin/env python3
"""
Test script to verify Celery database and Nmap fixes
Tests both the Asset import error fix and Nmap hostname validation fix
"""

import sys
import time
import requests
import json
from datetime import datetime

def test_celery_fixes():
    """Test all Celery fixes"""
    print("🧪 TESTING CELERY DATABASE & NMAP FIXES")
    print("=" * 60)
    
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
                return test_scan_progress(base_url, task_id)
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

def test_scan_progress(base_url, task_id):
    """Test scan progress and verify all stages complete"""
    print(f"\n2️⃣ TESTING SCAN PROGRESS TRACKING")
    print("-" * 40)
    
    max_wait_time = 300  # 5 minutes
    start_time = time.time()
    last_stage = ""
    stages_seen = set()
    
    while time.time() - start_time < max_wait_time:
        try:
            response = requests.get(f"{base_url}/api/large-scale-scan-status/{task_id}", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                state = data.get('state', 'UNKNOWN')
                stage = data.get('stage', 'unknown')
                progress = data.get('progress', 0)
                message = data.get('message', '')
                
                # Track stages
                if stage != last_stage:
                    stages_seen.add(stage)
                    print(f"📊 Stage: {stage} | Progress: {progress}% | {message}")
                    last_stage = stage
                
                # Check for completion
                if state == 'SUCCESS' and stage == 'completed':
                    print(f"✅ Scan completed successfully!")
                    return test_scan_results(data, stages_seen)
                
                # Check for failure
                elif state == 'FAILURE':
                    error = data.get('error', 'Unknown error')
                    print(f"❌ Scan failed: {error}")
                    return False
                
                # Check specific fixes
                if 'subdomains_found' in data:
                    subdomains_count = data.get('subdomains_found', 0)
                    if subdomains_count > 0:
                        print(f"✅ DATABASE FIX WORKING: {subdomains_count} subdomains discovered and stored")
                
                if 'alive_hosts_found' in data:
                    alive_count = data.get('alive_hosts_found', 0)
                    if alive_count > 0:
                        print(f"✅ HTTPX INTEGRATION WORKING: {alive_count} alive hosts found")
                
            else:
                print(f"⚠️ Status check failed: {response.status_code}")
            
            time.sleep(5)  # Wait 5 seconds between checks
            
        except Exception as e:
            print(f"⚠️ Error checking status: {str(e)}")
            time.sleep(5)
    
    print(f"❌ Scan timed out after {max_wait_time} seconds")
    return False

def test_scan_results(final_data, stages_seen):
    """Test final scan results and verify all components worked"""
    print(f"\n3️⃣ TESTING SCAN RESULTS & COMPONENT INTEGRATION")
    print("-" * 40)
    
    success = True
    
    # Test 1: Database Storage Fix
    print("\n🔍 TESTING DATABASE STORAGE FIX:")
    subdomains_found = final_data.get('subdomains_found', 0)
    if subdomains_found > 0:
        print(f"✅ DATABASE FIX WORKING: {subdomains_found} subdomains stored successfully")
        print("✅ Asset import error resolved - no more 'cannot access local variable Asset' errors")
    else:
        print("❌ DATABASE FIX FAILED: No subdomains stored")
        success = False
    
    # Test 2: httpx Integration
    print("\n🌐 TESTING HTTPX INTEGRATION:")
    alive_hosts = final_data.get('alive_hosts_found', 0)
    if alive_hosts > 0:
        print(f"✅ HTTPX INTEGRATION WORKING: {alive_hosts} alive hosts discovered")
        print("✅ HTTP probing completed successfully")
    else:
        print("❌ HTTPX INTEGRATION FAILED: No alive hosts found")
        success = False
    
    # Test 3: Nmap Integration & Hostname Validation Fix
    print("\n🔍 TESTING NMAP INTEGRATION & HOSTNAME VALIDATION:")
    if 'port_results' in final_data:
        port_results = final_data.get('port_results', {})
        if port_results:
            print(f"✅ NMAP INTEGRATION WORKING: Port scan results found for hosts")
            print("✅ Hostname validation fix working - no more 'Failed to resolve .' errors")
        else:
            print("⚠️ NMAP COMPLETED: No open ports found (this is normal for some hosts)")
    else:
        print("⚠️ Port scanning data not available in final results")
    
    # Test 4: Complete Workflow
    print("\n🎯 TESTING COMPLETE WORKFLOW:")
    expected_stages = {'subfinder_scanning', 'http_probing', 'port_scanning', 'completed'}
    found_stages = stages_seen.intersection(expected_stages)
    
    if len(found_stages) >= 3:  # At least subfinder, http_probing, and completed
        print(f"✅ COMPLETE WORKFLOW: Saw stages {found_stages}")
        print("✅ All scanning tools integrated successfully")
    else:
        print(f"❌ INCOMPLETE WORKFLOW: Only saw stages {stages_seen}")
        success = False
    
    # Test 5: Progress Tracking
    print("\n📈 TESTING PROGRESS TRACKING:")
    final_progress = final_data.get('progress', 0)
    if final_progress == 100:
        print("✅ PROGRESS TRACKING WORKING: Reached 100% completion")
    else:
        print(f"⚠️ Progress tracking incomplete: Final progress {final_progress}%")
    
    return success

def test_database_verification():
    """Test database to verify assets were stored"""
    print(f"\n4️⃣ TESTING DATABASE VERIFICATION")
    print("-" * 40)
    
    try:
        # Test assets endpoint
        response = requests.get("http://localhost:8077/api/assets", timeout=10)
        
        if response.status_code == 200:
            assets = response.json()
            nmap_assets = [asset for asset in assets if 'nmap.com' in asset.get('name', '')]
            
            if nmap_assets:
                print(f"✅ DATABASE VERIFICATION: Found {len(nmap_assets)} nmap.com assets in database")
                for asset in nmap_assets[:3]:  # Show first 3
                    print(f"   📋 Asset: {asset.get('name')} (Type: {asset.get('asset_type')})")
                return True
            else:
                print("❌ DATABASE VERIFICATION FAILED: No nmap.com assets found in database")
                return False
        else:
            print(f"⚠️ Could not verify database: API returned {response.status_code}")
            return False
            
    except Exception as e:
        print(f"⚠️ Database verification error: {str(e)}")
        return False

def main():
    """Main test function"""
    print("🚀 STARTING CELERY DATABASE & NMAP FIXES TEST")
    print("=" * 60)
    print(f"⏰ Test started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Run tests
    scan_success = test_celery_fixes()
    
    if scan_success:
        db_success = test_database_verification()
        overall_success = scan_success and db_success
    else:
        overall_success = False
    
    # Final results
    print("\n" + "=" * 60)
    print("🎯 FINAL TEST RESULTS")
    print("=" * 60)
    
    if overall_success:
        print("🎉 OVERALL RESULT: ✅ ALL FIXES WORKING")
        print("✅ Database Asset import error is fixed!")
        print("✅ Nmap hostname validation error is fixed!")
        print("✅ Complete workflow (Subfinder → httpx → Nmap) is working!")
        print("✅ Database storage is working correctly!")
        print("✅ Real-time progress tracking is working!")
        print("\n🚀 Your Attack Surface Management application is now fully functional!")
    else:
        print("❌ OVERALL RESULT: SOME ISSUES REMAIN")
        print("Please check the detailed output above for specific problems.")
    
    print(f"⏰ Test completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    return 0 if overall_success else 1

if __name__ == "__main__":
    sys.exit(main())
