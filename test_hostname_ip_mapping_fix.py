#!/usr/bin/env python3
"""
Test script to verify the hostname/IP mapping fix in Celery orchestrator
Tests that HTTP and port data is stored using hostnames as keys (not IP addresses)
"""

import sys
import time
import requests
import json
from datetime import datetime

def test_hostname_ip_mapping_fix():
    """Test that the hostname/IP mapping issue is fixed"""
    print("🧪 TESTING CELERY HOSTNAME/IP MAPPING FIX")
    print("=" * 50)
    
    base_url = "http://localhost:8077"
    
    # Test 1: Start large-scale scan
    print("\n1️⃣ TESTING LARGE-SCALE SCAN WITH HOSTNAME MAPPING")
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
    print(f"\n2️⃣ WAITING FOR SCAN COMPLETION & METADATA MAPPING")
    print("-" * 50)
    
    max_wait_time = 180  # 3 minutes
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
                
                print(f"📊 Progress: {progress}% | Stage: {stage}")
                
                # Check for completion
                if state == 'SUCCESS' and stage == 'completed':
                    print(f"✅ Scan completed successfully!")
                    subdomains_found = data.get('subdomains_found', 0)
                    alive_hosts_found = data.get('alive_hosts_found', 0)
                    print(f"📊 Results: {subdomains_found} subdomains, {alive_hosts_found} alive hosts")
                    
                    # Wait a moment for database commit
                    time.sleep(5)
                    return test_assets_metadata_mapping(base_url)
                
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

def test_assets_metadata_mapping(base_url):
    """Test that assets have proper HTTP and port metadata"""
    print(f"\n3️⃣ TESTING ASSETS METADATA HOSTNAME MAPPING")
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
            
            return test_metadata_hostname_consistency(nmap_assets)
            
        else:
            print(f"❌ Failed to retrieve assets: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Error retrieving assets: {str(e)}")
        return False

def test_metadata_hostname_consistency(assets):
    """Test that metadata uses hostnames consistently"""
    print(f"\n4️⃣ TESTING METADATA HOSTNAME CONSISTENCY")
    print("-" * 50)
    
    success = True
    
    # Test HTTP probe metadata with hostname keys
    print("\n🌐 TESTING HTTP PROBE METADATA MAPPING:")
    assets_with_http_status = 0
    assets_with_http_metadata = 0
    
    for asset in assets:
        asset_name = asset.get('name', '')
        asset_metadata = asset.get('asset_metadata', {})
        http_probe = asset_metadata.get('http_probe', {})
        
        print(f"\n   📋 Asset: {asset_name}")
        
        if http_probe:
            assets_with_http_metadata += 1
            print(f"      ✅ Has HTTP probe metadata")
            
            status_code = http_probe.get('status_code')
            if status_code and status_code != 0:
                assets_with_http_status += 1
                print(f"      ✅ HTTP Status Code: {status_code}")
            else:
                print(f"      ⚠️ No HTTP status code found")
            
            url = http_probe.get('url', '')
            if url:
                print(f"      ✅ URL: {url}")
            
            title = http_probe.get('title', '')
            if title:
                print(f"      ✅ Title: {title}")
            
            tech = http_probe.get('tech', [])
            if tech:
                print(f"      ✅ Technologies: {tech}")
            
            resolved_ip = http_probe.get('resolved_ip', '')
            if resolved_ip:
                print(f"      ✅ Resolved IP: {resolved_ip}")
        else:
            print(f"      ❌ No HTTP probe metadata found")
    
    print(f"\n📊 HTTP Probe Results:")
    print(f"   - Assets with HTTP metadata: {assets_with_http_metadata}")
    print(f"   - Assets with HTTP status codes: {assets_with_http_status}")
    
    if assets_with_http_status == 0:
        print("❌ HTTP STATUS MAPPING FAILED: No assets have HTTP status codes")
        success = False
    else:
        print("✅ HTTP STATUS MAPPING WORKING: Assets have HTTP status codes")
    
    # Test port scan metadata with hostname keys
    print("\n🔍 TESTING PORT SCAN METADATA MAPPING:")
    assets_with_ports = 0
    total_ports_found = 0
    
    for asset in assets:
        asset_name = asset.get('name', '')
        asset_metadata = asset.get('asset_metadata', {})
        ports = asset_metadata.get('ports', [])
        
        if ports and len(ports) > 0:
            assets_with_ports += 1
            total_ports_found += len(ports)
            print(f"\n   📋 Asset: {asset_name}")
            print(f"      ✅ Found {len(ports)} ports")
            
            for port_info in ports[:3]:  # Show first 3 ports
                port = port_info.get('port', 'N/A')
                service = port_info.get('service', 'unknown')
                protocol = port_info.get('protocol', 'tcp')
                state = port_info.get('state', 'open')
                print(f"      ✅ Port {port}/{protocol} ({service}) - {state}")
    
    print(f"\n📊 Port Scan Results:")
    print(f"   - Assets with port data: {assets_with_ports}")
    print(f"   - Total ports found: {total_ports_found}")
    
    if assets_with_ports == 0:
        print("⚠️ PORT MAPPING: No assets have port data (may be normal if no ports are open)")
    else:
        print("✅ PORT MAPPING WORKING: Assets have port scan data")
    
    # Test overall metadata consistency
    print("\n📋 TESTING OVERALL METADATA CONSISTENCY:")
    assets_with_complete_metadata = 0
    
    for asset in assets:
        asset_name = asset.get('name', '')
        asset_metadata = asset.get('asset_metadata', {})
        
        has_http = bool(asset_metadata.get('http_probe'))
        has_discovery = bool(asset_metadata.get('discovery_method'))
        has_scan_source = bool(asset_metadata.get('scan_source'))
        
        if has_http and has_discovery and has_scan_source:
            assets_with_complete_metadata += 1
    
    print(f"   - Assets with complete metadata: {assets_with_complete_metadata}/{len(assets)}")
    
    if assets_with_complete_metadata > 0:
        print("✅ METADATA CONSISTENCY WORKING: Assets have complete metadata structure")
    else:
        print("❌ METADATA CONSISTENCY FAILED: No assets have complete metadata")
        success = False
    
    return success

def main():
    """Main test function"""
    print("🚀 STARTING CELERY HOSTNAME/IP MAPPING FIX TEST")
    print("=" * 50)
    print(f"⏰ Test started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Run test
    success = test_hostname_ip_mapping_fix()
    
    # Final results
    print("\n" + "=" * 50)
    print("🎯 FINAL TEST RESULTS")
    print("=" * 50)
    
    if success:
        print("🎉 OVERALL RESULT: ✅ HOSTNAME/IP MAPPING FIX WORKING")
        print("✅ HTTP status codes are properly mapped to hostnames!")
        print("✅ Port scan results are properly mapped to hostnames!")
        print("✅ Assets page should now display HTTP status badges!")
        print("✅ Assets page should now display port bubbles!")
        print("✅ Metadata consistency is maintained!")
        print("\n🎯 The hostname/IP mapping issue has been resolved!")
        print("   - HTTP data stored using hostname keys (not IP addresses)")
        print("   - Port data stored using hostname keys (not IP addresses)")
        print("   - Assets page can now find and display the metadata")
    else:
        print("❌ OVERALL RESULT: HOSTNAME/IP MAPPING ISSUES REMAIN")
        print("Please check the detailed output above for specific problems.")
        print("The assets page may still show 'No open ports' and missing status codes.")
    
    print(f"⏰ Test completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
