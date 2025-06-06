#!/usr/bin/env python3

import http.server
import socketserver
import threading
import sys
import time

# Force immediate output flushing for logging (compatible with older Python)
import os
os.environ['PYTHONUNBUFFERED'] = '1'

# Create a custom print function that auto-flushes
def flush_print(*args, **kwargs):
    print(*args, **kwargs)
    sys.stdout.flush()

class SimpleHTTPHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # Detailed request logging
        timestamp = time.strftime("%H:%M:%S", time.localtime())
        flush_print(f"\n🔵 [{timestamp}] ===== INCOMING GET REQUEST =====")
        flush_print(f"📡 Client: {self.client_address[0]}:{self.client_address[1]}")
        flush_print(f"📄 Method: {self.command}")
        flush_print(f"🌐 Path: {self.path}")
        flush_print(f"📋 Headers ({len(self.headers)} total):")
        for header, value in self.headers.items():
            flush_print(f"📋   {header}: {value}")
        
        # Send response
        flush_print(f"📤 Sending 200 OK response...")
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('Server', 'Backend-Test-Server/1.0')
        self.end_headers()
        
        response_body = f"""
<!DOCTYPE html>
<html>
<head><title>Backend Service</title></head>
<body>
<h1>✅ Backend Service Running</h1>
<p><strong>Method:</strong> {self.command}</p>
<p><strong>Path:</strong> {self.path}</p>
<p><strong>Client:</strong> {self.client_address[0]}:{self.client_address[1]}</p>
<p><strong>Timestamp:</strong> {timestamp}</p>
<p><strong>Headers:</strong></p>
<ul>
{"".join(f"<li>{key}: {value}</li>" for key, value in self.headers.items())}
</ul>
<p><strong>Server:</strong> Simple Python Backend on port 8081</p>
<p><strong>Status:</strong> Ready for reverse tunnel testing</p>
</body>
</html>
        """
        response_bytes = response_body.encode()
        self.wfile.write(response_bytes)
        
        flush_print(f"✅ Response sent: {len(response_bytes)} bytes")
        flush_print(f"🔵 [{timestamp}] ===== REQUEST COMPLETED =====\n")
    
    def do_POST(self):
        # Detailed request logging
        timestamp = time.strftime("%H:%M:%S", time.localtime())
        content_length = int(self.headers.get('Content-Length', 0))
        
        flush_print(f"\n🟠 [{timestamp}] ===== INCOMING POST REQUEST =====")
        flush_print(f"📡 Client: {self.client_address[0]}:{self.client_address[1]}")
        flush_print(f"📄 Method: {self.command}")
        flush_print(f"🌐 Path: {self.path}")
        flush_print(f"📏 Content-Length: {content_length} bytes")
        flush_print(f"📋 Headers ({len(self.headers)} total):")
        for header, value in self.headers.items():
            flush_print(f"📋   {header}: {value}")
        
        # Read POST data
        flush_print(f"📥 Reading {content_length} bytes of POST data...")
        post_data = self.rfile.read(content_length)
        flush_print(f"📥 POST data received: {len(post_data)} bytes")
        if post_data:
            # Show first 200 characters of POST data
            data_preview = post_data[:200].decode('utf-8', errors='ignore')
            flush_print(f"📥 Data preview: {repr(data_preview)}{'...' if len(post_data) > 200 else ''}")
        
        # Send response
        flush_print(f"📤 Sending 200 OK response...")
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('Server', 'Backend-Test-Server/1.0')
        self.end_headers()
        
        response_body = f"""
<!DOCTYPE html>
<html>
<head><title>Backend Service - POST Response</title></head>
<body>
<h1>✅ POST Request Received</h1>
<p><strong>Method:</strong> {self.command}</p>
<p><strong>Path:</strong> {self.path}</p>
<p><strong>Client:</strong> {self.client_address[0]}:{self.client_address[1]}</p>
<p><strong>Timestamp:</strong> {timestamp}</p>
<p><strong>Content Length:</strong> {content_length} bytes</p>
<p><strong>POST Data:</strong> {post_data.decode('utf-8', errors='ignore')}</p>
<p><strong>Server:</strong> Simple Python Backend on port 8081</p>
</body>
</html>
        """
        response_bytes = response_body.encode()
        self.wfile.write(response_bytes)
        
        flush_print(f"✅ Response sent: {len(response_bytes)} bytes")
        flush_print(f"🟠 [{timestamp}] ===== POST REQUEST COMPLETED =====\n")
    
    def do_HEAD(self):
        timestamp = time.strftime("%H:%M:%S", time.localtime())
        flush_print(f"\n🟡 [{timestamp}] ===== INCOMING HEAD REQUEST =====")
        flush_print(f"📡 Client: {self.client_address[0]}:{self.client_address[1]}")
        flush_print(f"📄 Method: {self.command}")
        flush_print(f"🌐 Path: {self.path}")
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('Server', 'Backend-Test-Server/1.0')
        self.end_headers()
        
        flush_print(f"✅ HEAD response sent")
        flush_print(f"🟡 [{timestamp}] ===== HEAD REQUEST COMPLETED =====\n")
    
    def log_message(self, format, *args):
        # Override default logging to be more visible
        timestamp = time.strftime("%H:%M:%S", time.localtime())
        flush_print(f"🔧 [{timestamp}] HTTP: {format % args}")

def start_backend_server():
    PORT = 8081
    try:
        with socketserver.TCPServer(("", PORT), SimpleHTTPHandler) as httpd:
            flush_print(f"🚀 Backend server starting on port {PORT}")
            flush_print(f"📍 Serving HTTP requests for reverse tunnel testing")
            flush_print(f"🔗 Access: http://localhost:{PORT}/")
            flush_print(f"📊 Detailed logging enabled - will show all incoming requests")
            flush_print(f"⏹️  Press Ctrl+C to stop")
            flush_print(f"\n⏳ Waiting for requests...")
            httpd.serve_forever()
    except KeyboardInterrupt:
        flush_print(f"\n🛑 Backend server stopped")
    except Exception as e:
        flush_print(f"❌ Backend server error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    start_backend_server() 