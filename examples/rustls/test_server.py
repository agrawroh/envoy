#!/usr/bin/env python3
"""
Simple HTTPS test server for rustls transport socket testing.
Runs on port 8443 with TLS using the generated certificates.
"""

import http.server
import ssl
import os
import sys

# Get the directory containing this script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CERT_DIR = os.path.join(SCRIPT_DIR, "certs")

# Server configuration
HOST = "localhost"
PORT = 8443

class SimpleHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    """Simple handler that returns a test response."""
    
    def do_GET(self):
        """Handle GET requests."""
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        
        response = f"""<!DOCTYPE html>
<html>
<head>
    <title>Rustls Test Server</title>
</head>
<body>
    <h1>Rustls Transport Socket Test Server</h1>
    <p>Successfully connected via rustls!</p>
    <p>Request path: {self.path}</p>
    <p>Client address: {self.client_address[0]}:{self.client_address[1]}</p>
    <p>TLS protocol: {self.request.version()}</p>
    <p>TLS cipher: {self.request.cipher()}</p>
</body>
</html>"""
        self.wfile.write(response.encode())
    
    def log_message(self, format, *args):
        """Override to add timestamps and better formatting."""
        sys.stdout.write(f"[{self.log_date_time_string()}] {format % args}\n")


def main():
    """Start the HTTPS server."""
    
    # Check if certificates exist
    cert_file = os.path.join(CERT_DIR, "server-cert.pem")
    key_file = os.path.join(CERT_DIR, "server-key.pem")
    
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        print(f"ERROR: Certificates not found in {CERT_DIR}")
        print("Please run: ./generate_certs.sh")
        sys.exit(1)
    
    # Create HTTP server
    httpd = http.server.HTTPServer((HOST, PORT), SimpleHTTPRequestHandler)
    
    # Wrap with SSL/TLS
    try:
        # Python 3.6+
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    except AttributeError:
        # Python 3.5 and older
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    
    context.load_cert_chain(cert_file, key_file)
    
    # Force TLS 1.2 only (TLS 1.3 kTLS has kernel compatibility issues)
    try:
        # Python 3.7+
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2  # Force 1.2 only
    except AttributeError:
        # Python < 3.7 - use options instead
        context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        # Also disable TLS 1.3 if available
        try:
            context.options |= ssl.OP_NO_TLSv1_3
        except AttributeError:
            pass  # TLS 1.3 not available in this Python version
    
    # Set ALPN protocols (match what Envoy expects)
    try:
        context.set_alpn_protocols(['h2', 'http/1.1'])
    except AttributeError:
        # ALPN not supported in older Python versions
        print("Warning: ALPN not supported in this Python version")
    
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    
    print(f"🚀 Starting HTTPS test server on https://{HOST}:{PORT}")
    print(f"📁 Using certificates from: {CERT_DIR}")
    print(f"🔐 TLS 1.2 only (for kTLS compatibility) with ALPN: h2, http/1.1")
    print(f"✅ Server ready for rustls transport socket testing")
    print(f"\nPress Ctrl+C to stop the server\n")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n\n🛑 Server stopped")
        httpd.shutdown()


if __name__ == "__main__":
    main()

