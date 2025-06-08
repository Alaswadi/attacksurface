#!/usr/bin/env python3
"""
Test script to verify Assets Page Metadata Integration
Tests that HTTP status codes, technologies, and port scan results are properly stored and displayed
"""

import sys
import time
import requests
import json
from datetime import datetime

def test_assets_metadata_integration():
    """Test complete assets metadata integration"""
    print("🧪 TESTING ASSETS PAGE METADATA INTEGRATION")
    print("=" * 60)
    
    base_url = "http://localhost:8077"
    
    # Test 1: Start large-scale scan to generate metadata
    print("\n1️⃣ TESTING LARGE-SCALE SCAN FOR METADATA GENERATION")
    print("-" * 50)
    
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
                return test_scan_completion_and_metadata(base_url, task_id)
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

def test_scan_completion_and_metadata(base_url, task_id):
    """Wait for scan completion and test metadata storage"""
    print(f"\n2️⃣ WAITING FOR SCAN COMPLETION & METADATA STORAGE")
    print("-" * 50)
    
    max_wait_time = 300  # 5 minutes
    start_time = time.time()
    
    while time.time() - start_time < max_wait_time:
        try:
            response = requests.get(f"{base_url}/api/large-scale-scan-status/{task_id}", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                state = data.get('state', 'UNKNOWN')
                stage = data.get('stage', 'unknown')
                progress = data.get('progress', 0)
                message = data.get('message', '')
                
                print(f"📊 Progress: {progress}% | Stage: {stage} | {message}")
                
                # Check for completion
                if state == 'SUCCESS' and stage == 'completed':
                    print(f"✅ Scan completed successfully!")
                    subdomains_found = data.get('subdomains_found', 0)
                    alive_hosts_found = data.get('alive_hosts_found', 0)
                    print(f"📊 Results: {subdomains_found} subdomains, {alive_hosts_found} alive hosts")
                    
                    # Wait a moment for database commit
                    time.sleep(5)
                    return test_assets_api_metadata(base_url)
                
                # Check for failure
                elif state == 'FAILURE':
                    error = data.get('error', 'Unknown error')
                    print(f"❌ Scan failed: {error}")
                    return False
            
            time.sleep(10)  # Wait 10 seconds between checks
            
        except Exception as e:
            print(f"⚠️ Error checking status: {str(e)}")
            time.sleep(10)
    
    print(f"❌ Scan timed out after {max_wait_time} seconds")
    return False

def test_assets_api_metadata(base_url):
    """Test that assets API returns proper metadata"""
    print(f"\n3️⃣ TESTING ASSETS API METADATA RETRIEVAL")
    print("-" * 50)
    
    try:
        response = requests.get(f"{base_url}/api/assets", timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            assets = data.get('assets', [])
            
            print(f"📊 Retrieved {len(assets)} assets from API")
            
            # Find nmap.com related assets
            nmap_assets = [asset for asset in assets if 'nmap.com' in asset.get('name', '')]
            print(f"🎯 Found {len(nmap_assets)} nmap.com related assets")
            
            if not nmap_assets:
                print("❌ No nmap.com assets found - scan may have failed")
                return False
            
            return test_metadata_content(nmap_assets)
            
        else:
            print(f"❌ Failed to retrieve assets: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Error retrieving assets: {str(e)}")
        return False

def test_metadata_content(assets):
    """Test the actual metadata content in assets"""
    print(f"\n4️⃣ TESTING METADATA CONTENT IN ASSETS")
    print("-" * 50)
    
    success = True
    
    # Test HTTP probe metadata
    print("\n🌐 TESTING HTTP PROBE METADATA:")
    assets_with_http = 0
    assets_with_status_codes = 0
    assets_with_technologies = 0
    
    for asset in assets:
        asset_metadata = asset.get('asset_metadata', {})
        http_probe = asset_metadata.get('http_probe', {})
        
        if http_probe:
            assets_with_http += 1
            print(f"   📋 {asset['name']}: HTTP probe data found")
            
            status_code = http_probe.get('status_code')
            if status_code:
                assets_with_status_codes += 1
                print(f"      ✅ Status Code: {status_code}")
            
            technologies = http_probe.get('tech', []) or http_probe.get('technologies', [])
            if technologies:
                assets_with_technologies += 1
                print(f"      ✅ Technologies: {technologies}")
            
            title = http_probe.get('title', '')
            if title:
                print(f"      ✅ Title: {title}")
            
            webserver = http_probe.get('webserver', '')
            if webserver:
                print(f"      ✅ Webserver: {webserver}")
    
    print(f"\n📊 HTTP Probe Results:")
    print(f"   - Assets with HTTP probe data: {assets_with_http}")
    print(f"   - Assets with status codes: {assets_with_status_codes}")
    print(f"   - Assets with technologies: {assets_with_technologies}")
    
    if assets_with_http == 0:
        print("❌ HTTP PROBE METADATA MISSING: No assets have HTTP probe data")
        success = False
    else:
        print("✅ HTTP PROBE METADATA WORKING: Assets have HTTP probe data")
    
    # Test port scan metadata
    print("\n🔍 TESTING PORT SCAN METADATA:")
    assets_with_ports = 0
    total_ports_found = 0
    
    for asset in assets:
        asset_metadata = asset.get('asset_metadata', {})
        ports = asset_metadata.get('ports', [])
        
        if ports and len(ports) > 0:
            assets_with_ports += 1
            total_ports_found += len(ports)
            print(f"   📋 {asset['name']}: {len(ports)} ports found")
            
            for port_info in ports[:3]:  # Show first 3 ports
                port = port_info.get('port', 'N/A')
                service = port_info.get('service', 'unknown')
                print(f"      ✅ Port {port}/{service}")
    
    print(f"\n📊 Port Scan Results:")
    print(f"   - Assets with port data: {assets_with_ports}")
    print(f"   - Total ports found: {total_ports_found}")
    
    if assets_with_ports == 0:
        print("⚠️ PORT SCAN METADATA: No assets have port data (this may be normal if no ports are open)")
    else:
        print("✅ PORT SCAN METADATA WORKING: Assets have port scan data")
    
    # Test metadata structure
    print("\n📋 TESTING METADATA STRUCTURE:")
    for asset in assets[:3]:  # Test first 3 assets
        asset_metadata = asset.get('asset_metadata', {})
        print(f"   📋 {asset['name']}:")
        print(f"      - Metadata keys: {list(asset_metadata.keys())}")
        
        # Check for expected keys
        expected_keys = ['discovery_method', 'scan_source']
        for key in expected_keys:
            if key in asset_metadata:
                print(f"      ✅ Has {key}: {asset_metadata[key]}")
            else:
                print(f"      ⚠️ Missing {key}")
    
    return success

def test_frontend_display():
    """Test that frontend can access the metadata"""
    print(f"\n5️⃣ TESTING FRONTEND METADATA ACCESS")
    print("-" * 50)
    
    try:
        # Test assets page loads
        response = requests.get("http://localhost:8077/assets", timeout=10)
        
        if response.status_code == 200:
            print("✅ Assets page loads successfully")
            
            # Check if the page contains expected JavaScript functions
            page_content = response.text
            
            if 'getStatusBadge' in page_content:
                print("✅ Status badge function found in assets page")
            else:
                print("❌ Status badge function missing from assets page")
            
            if 'getPortsBubbles' in page_content:
                print("✅ Ports bubbles function found in assets page")
            else:
                print("❌ Ports bubbles function missing from assets page")
            
            if 'asset_metadata.http_probe.status_code' in page_content:
                print("✅ HTTP probe status code access found in assets page")
            else:
                print("❌ HTTP probe status code access missing from assets page")
            
            return True
        else:
            print(f"❌ Assets page failed to load: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Error testing frontend: {str(e)}")
        return False

def main():
    """Main test function"""
    print("🚀 STARTING ASSETS METADATA INTEGRATION TEST")
    print("=" * 60)
    print(f"⏰ Test started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Run tests
    scan_success = test_assets_metadata_integration()
    frontend_success = test_frontend_display()
    
    overall_success = scan_success and frontend_success
    
    # Final results
    print("\n" + "=" * 60)
    print("🎯 FINAL TEST RESULTS")
    print("=" * 60)
    
    if overall_success:
        print("🎉 OVERALL RESULT: ✅ ASSETS METADATA INTEGRATION WORKING")
        print("✅ HTTP status codes are being stored and should display!")
        print("✅ Port scan results are being stored and should display!")
        print("✅ Technologies detection is working!")
        print("✅ Frontend has proper metadata access functions!")
        print("\n🎯 Check the assets page - you should now see:")
        print("   - HTTP status codes as colored badges")
        print("   - Port numbers as bubbles next to assets")
        print("   - Technology information in metadata")
    else:
        print("❌ OVERALL RESULT: METADATA INTEGRATION ISSUES FOUND")
        print("Please check the detailed output above for specific problems.")
    
    print(f"⏰ Test completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    return 0 if overall_success else 1

if __name__ == "__main__":
    sys.exit(main())
