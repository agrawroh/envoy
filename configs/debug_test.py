#!/usr/bin/env python3

import socket
import time
import sys

def debug_test():
    """Debug test to see exactly what's happening with the response"""
    
    print("🔍 DEBUG: Testing reverse connection with detailed logging...")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    
    try:
        print("📡 Connecting to 127.0.0.1:10000...")
        sock.connect(("127.0.0.1", 10000))
        print("✅ Connected successfully")
        
        # Send HTTP request
        http_request = (
            "GET / HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "User-Agent: DebugTest/1.0\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        
        print(f"📤 Sending {len(http_request)} bytes:")
        print(f"📤 Request: {repr(http_request)}")
        sock.send(http_request.encode())
        
        # Read response with detailed logging
        print("📥 Reading response...")
        all_data = b""
        chunk_count = 0
        
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    print("📝 Socket closed by server")
                    break
                    
                chunk_count += 1
                all_data += chunk
                print(f"📥 Chunk {chunk_count}: {len(chunk)} bytes")
                print(f"📥 Chunk data: {repr(chunk[:100])}{'...' if len(chunk) > 100 else ''}")
                print(f"📊 Total so far: {len(all_data)} bytes")
                
                # Show headers when we have them
                if b"\r\n\r\n" in all_data and chunk_count == 1:
                    headers_end = all_data.find(b"\r\n\r\n")
                    headers = all_data[:headers_end].decode('ascii', errors='ignore')
                    print("📋 Headers received:")
                    for line in headers.split('\r\n'):
                        print(f"📋   {line}")
                
            except socket.timeout:
                print("⏰ Socket timeout - no more data available")
                break
            except Exception as e:
                print(f"❌ Error: {e}")
                break
        
        print(f"📊 FINAL RESULT: {len(all_data)} bytes total")
        
        if all_data:
            print("✅ SUCCESS: Data received!")
            if all_data.startswith(b"HTTP/"):
                print("✅ Valid HTTP response")
                return True
            else:
                print("❌ Not HTTP response")
                return False
        else:
            print("❌ FAILED: No data received")
            return False
            
    except Exception as e:
        print(f"❌ Connection error: {e}")
        return False
    finally:
        sock.close()
        print("🔌 Socket closed")

if __name__ == "__main__":
    success = debug_test()
    sys.exit(0 if success else 1) 