#!/usr/bin/env python3

import http.server
import socketserver
import threading
import sys
import time
import socket
from socketserver import ThreadingMixIn

# Force immediate output flushing for logging (compatible with older Python)
import os
os.environ['PYTHONUNBUFFERED'] = '1'

# Create a custom print function that auto-flushes
def flush_print(*args, **kwargs):
    print(*args, **kwargs)
    sys.stdout.flush()

class KeepAliveHTTPHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler that supports connection keep-alive for socket handoff testing"""
    
    protocol_version = 'HTTP/1.1'  # Enable HTTP/1.1 for keep-alive
    
    def do_GET(self):
        # Detailed request logging
        timestamp = time.strftime("%H:%M:%S", time.localtime())
        flush_print(f"\n🔵 [{timestamp}] ===== INCOMING GET REQUEST (KEEP-ALIVE) =====")
        flush_print(f"📡 Client: {self.client_address[0]}:{self.client_address[1]}")
        flush_print(f"📄 Method: {self.command}")
        flush_print(f"🌐 Path: {self.path}")
        flush_print(f"📋 Headers ({len(self.headers)} total):")
        for header, value in self.headers.items():
            flush_print(f"📋   {header}: {value}")
        
        # Check if client requested keep-alive
        connection_header = self.headers.get('Connection', '').lower()
        client_wants_keepalive = 'keep-alive' in connection_header
        flush_print(f"🔗 Client Connection header: {connection_header}")
        flush_print(f"🔗 Client wants keep-alive: {client_wants_keepalive}")
        
        # Send response with keep-alive support
        flush_print(f"📤 Sending 200 OK response with keep-alive...")
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('Server', 'KeepAlive-Backend-Test-Server/1.0')
        self.send_header('Connection', 'keep-alive')  # CRITICAL: Keep connection alive
        self.send_header('Keep-Alive', 'timeout=60, max=1000')  # Keep alive for 60s, up to 1000 requests
        
        response_body = f"""<!DOCTYPE html>
<html>
<head><title>Keep-Alive Backend Service</title></head>
<body>
<h1>✅ Keep-Alive Backend Service Running</h1>
<p><strong>Method:</strong> {self.command}</p>
<p><strong>Path:</strong> {self.path}</p>
<p><strong>Client:</strong> {self.client_address[0]}:{self.client_address[1]}</p>
<p><strong>Timestamp:</strong> {timestamp}</p>
<p><strong>Connection:</strong> Keep-Alive Enabled</p>
<p><strong>Keep-Alive Config:</strong> timeout=60s, max=1000 requests</p>
<p><strong>Headers:</strong></p>
<ul>
{"".join(f"<li>{key}: {value}</li>" for key, value in self.headers.items())}
</ul>
<p><strong>Server:</strong> Keep-Alive Python Backend on port 7070</p>
<p><strong>Status:</strong> Ready for socket handoff optimization testing</p>
<p><strong>Connection Will:</strong> Stay open for reuse by socket handoff pool</p>
</body>
</html>"""
        
        response_bytes = response_body.encode('utf-8')
        self.send_header('Content-Length', str(len(response_bytes)))
        self.end_headers()
        
        # Send response body
        self.wfile.write(response_bytes)
        self.wfile.flush()
        
        flush_print(f"✅ Keep-alive response sent: {len(response_bytes)} bytes")
        flush_print(f"🔗 Connection will stay open for reuse")
        flush_print(f"🔵 [{timestamp}] ===== GET REQUEST COMPLETED (CONNECTION KEPT ALIVE) =====\n")
    
    def do_POST(self):
        # Detailed request logging
        timestamp = time.strftime("%H:%M:%S", time.localtime())
        content_length = int(self.headers.get('Content-Length', 0))
        
        flush_print(f"\n🟠 [{timestamp}] ===== INCOMING POST REQUEST (KEEP-ALIVE) =====")
        flush_print(f"📡 Client: {self.client_address[0]}:{self.client_address[1]}")
        flush_print(f"📄 Method: {self.command}")
        flush_print(f"🌐 Path: {self.path}")
        flush_print(f"📏 Content-Length: {content_length} bytes")
        flush_print(f"📋 Headers ({len(self.headers)} total):")
        for header, value in self.headers.items():
            flush_print(f"📋   {header}: {value}")
        
        # Read POST data
        flush_print(f"📥 Reading {content_length} bytes of POST data...")
        post_data = self.rfile.read(content_length) if content_length > 0 else b""
        flush_print(f"📥 POST data received: {len(post_data)} bytes")
        if post_data:
            # Show first 200 characters of POST data
            data_preview = post_data[:200].decode('utf-8', errors='ignore')
            flush_print(f"📥 Data preview: {repr(data_preview)}{'...' if len(post_data) > 200 else ''}")
        
        # Send response with keep-alive support
        flush_print(f"📤 Sending 200 OK response with keep-alive...")
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Server', 'KeepAlive-Backend-Test-Server/1.0')
        self.send_header('Connection', 'keep-alive')
        self.send_header('Keep-Alive', 'timeout=60, max=1000')
        
        response_body = f'{{"status": "success", "message": "POST processed with keep-alive", "received_bytes": {len(post_data)}, "timestamp": "{timestamp}"}}'
        response_bytes = response_body.encode('utf-8')
        self.send_header('Content-Length', str(len(response_bytes)))
        self.end_headers()
        
        self.wfile.write(response_bytes)
        self.wfile.flush()
        
        flush_print(f"✅ Keep-alive POST response sent: {len(response_bytes)} bytes")
        flush_print(f"🔗 Connection will stay open for reuse")
        flush_print(f"🟠 [{timestamp}] ===== POST REQUEST COMPLETED (CONNECTION KEPT ALIVE) =====\n")
    
    def do_HEAD(self):
        timestamp = time.strftime("%H:%M:%S", time.localtime())
        flush_print(f"\n🟡 [{timestamp}] ===== INCOMING HEAD REQUEST (KEEP-ALIVE) =====")
        flush_print(f"📡 Client: {self.client_address[0]}:{self.client_address[1]}")
        flush_print(f"📄 Method: {self.command}")
        flush_print(f"🌐 Path: {self.path}")
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('Server', 'KeepAlive-Backend-Test-Server/1.0')
        self.send_header('Connection', 'keep-alive')
        self.send_header('Keep-Alive', 'timeout=60, max=1000')
        self.end_headers()
        
        flush_print(f"✅ Keep-alive HEAD response sent")
        flush_print(f"🔗 Connection will stay open for reuse")
        flush_print(f"🟡 [{timestamp}] ===== HEAD REQUEST COMPLETED (CONNECTION KEPT ALIVE) =====\n")
    
    def log_message(self, format, *args):
        # Override default logging to be more visible
        timestamp = time.strftime("%H:%M:%S", time.localtime())
        flush_print(f"🔧 [{timestamp}] HTTP: {format % args}")

class ThreadingKeepAliveHTTPServer(ThreadingMixIn, socketserver.TCPServer):
    """Threaded HTTP server with keep-alive support"""
    
    daemon_threads = True
    allow_reuse_address = True
    
    def __init__(self, server_address, RequestHandlerClass):
        super().__init__(server_address, RequestHandlerClass)
        
        # Configure socket for optimal keep-alive behavior
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        
        # Set socket timeouts for keep-alive
        self.socket.settimeout(60)  # 60 second timeout for connections

def start_keepalive_backend_server():
    PORT = 7070  # Use port 7070 to avoid conflicts with Envoy
    
    flush_print("================================================================")
    flush_print("🚀 KEEP-ALIVE BACKEND SERVER FOR SOCKET HANDOFF TESTING")
    flush_print("================================================================")
    
    try:
        server = ThreadingKeepAliveHTTPServer(('127.0.0.1', PORT), KeepAliveHTTPHandler)
        
        flush_print(f"✅ Starting keep-alive HTTP server on http://127.0.0.1:{PORT}/")
        flush_print(f"✅ Connection keep-alive: ENABLED (timeout=60s, max=1000 requests)")
        flush_print(f"✅ This server will maintain connections for socket handoff optimization")
        flush_print(f"📊 Detailed logging enabled - will show all incoming requests")
        flush_print(f"🔗 Connections will be reused by Envoy's socket handoff pools")
        flush_print(f"⏹️  Press Ctrl+C to stop")
        flush_print("")
        
        # Test server responsiveness
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_socket.settimeout(5)
        
        try:
            test_socket.connect(('127.0.0.1', PORT))
            test_socket.close()
            flush_print("✅ Server socket binding successful")
        except Exception as e:
            flush_print(f"❌ Server socket binding failed: {e}")
            return False
        
        # Start serving requests
        flush_print("🌐 Server ready - connections will be kept alive for reuse")
        flush_print("⏳ Waiting for requests...\n")
        server.serve_forever()
        
    except KeyboardInterrupt:
        flush_print("\n🛑 Keep-alive server shutdown requested")
        server.shutdown()
        server.server_close()
        flush_print("✅ Keep-alive server stopped")
        return True
        
    except Exception as e:
        flush_print(f"❌ Keep-alive server error: {e}")
        sys.exit(1)

def test_keepalive_behavior():
    """Test the keep-alive behavior of this server"""
    
    flush_print("🧪 Testing keep-alive behavior...")
    
    try:
        import requests
        
        # Create a session to reuse connections
        session = requests.Session()
        
        # Make multiple requests to test keep-alive
        for i in range(3):
            start_time = time.time()
            response = session.get('http://127.0.0.1:7070/')
            duration = (time.time() - start_time) * 1000
            
            if response.status_code == 200:
                connection_header = response.headers.get('Connection', 'close')
                flush_print(f"✅ Request {i+1}: {duration:.1f}ms - Connection: {connection_header}")
            else:
                flush_print(f"❌ Request {i+1}: HTTP {response.status_code}")
            
            time.sleep(0.1)
        
        session.close()
        flush_print("✅ Keep-alive test completed")
        
    except ImportError:
        flush_print("⚠️  requests module not available for testing")
    except Exception as e:
        flush_print(f"❌ Keep-alive test failed: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        test_keepalive_behavior()
    else:
        start_keepalive_backend_server() 