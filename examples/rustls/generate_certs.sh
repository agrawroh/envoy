#!/bin/bash
# Script to generate self-signed certificates for rustls testing.

set -e

CERT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/certs"
mkdir -p "$CERT_DIR"

echo "Generating certificates in: $CERT_DIR"

# Generate CA certificate.
openssl req -x509 -newkey rsa:4096 -keyout "$CERT_DIR/ca-key.pem" -out "$CERT_DIR/ca-cert.pem" \
  -days 365 -nodes -subj "/CN=Test CA"

# Generate server certificate.
openssl req -newkey rsa:4096 -keyout "$CERT_DIR/server-key.pem" -out "$CERT_DIR/server-req.pem" \
  -nodes -subj "/CN=localhost"
openssl x509 -req -in "$CERT_DIR/server-req.pem" -CA "$CERT_DIR/ca-cert.pem" \
  -CAkey "$CERT_DIR/ca-key.pem" -CAcreateserial -out "$CERT_DIR/server-cert.pem" -days 365 \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1")

# Generate client certificate (for mTLS testing).
openssl req -newkey rsa:4096 -keyout "$CERT_DIR/client-key.pem" -out "$CERT_DIR/client-req.pem" \
  -nodes -subj "/CN=Test Client"
openssl x509 -req -in "$CERT_DIR/client-req.pem" -CA "$CERT_DIR/ca-cert.pem" \
  -CAkey "$CERT_DIR/ca-key.pem" -CAcreateserial -out "$CERT_DIR/client-cert.pem" -days 365

# Clean up temporary files.
rm -f "$CERT_DIR"/*.pem.srl "$CERT_DIR"/*-req.pem

echo "Certificates generated successfully!"
echo "Server cert: $CERT_DIR/server-cert.pem"
echo "Server key:  $CERT_DIR/server-key.pem"
echo "Client cert: $CERT_DIR/client-cert.pem"
echo "Client key:  $CERT_DIR/client-key.pem"
echo "CA cert:     $CERT_DIR/ca-cert.pem"

chmod +x "$CERT_DIR/../generate_certs.sh"

