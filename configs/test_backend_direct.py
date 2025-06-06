#!/usr/bin/env python3

import urllib.request
import time

def test_backend_direct():
    """Test the backend directly to verify it's working and logging"""
    
    print("🧪 Testing backend server directly...")
    
    try:
        print("📡 Making direct request to http://localhost:8081/")
        
        # Make a simple GET request
        req = urllib.request.Request('http://localhost:8081/')
        req.add_header('User-Agent', 'DirectTest/1.0')
        req.add_header('X-Test-Header', 'direct-backend-test')
        
        with urllib.request.urlopen(req, timeout=10) as response:
            data = response.read()
            print(f"✅ Response received: {response.status} {response.reason}")
            print(f"📊 Response size: {len(data)} bytes")
            print(f"📋 Response headers:")
            for header, value in response.headers.items():
                print(f"📋   {header}: {value}")
            
            # Show first 200 characters of response
            preview = data[:200].decode('utf-8', errors='ignore')
            print(f"📄 Response preview: {preview}...")
            
            return True
            
    except Exception as e:
        print(f"❌ Backend test failed: {e}")
        return False

if __name__ == "__main__":
    success = test_backend_direct()
    if success:
        print("✅ Backend direct test PASSED")
    else:
        print("❌ Backend direct test FAILED") 