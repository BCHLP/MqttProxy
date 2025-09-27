#!/bin/bash

# Script to create client certificates signed by intermediate CA
# Usage: ./create_client_with_intermediate.sh client_name

if [ $# -eq 0 ]; then
    echo "Usage: $0 <client_name>"
    echo "Example: $0 client1"
    exit 1
fi

CLIENT_NAME=$1
CERT_DIR="certs"

# Check if intermediate CA files exist
if [ ! -f "$CERT_DIR/intermediate-ca.crt" ] || [ ! -f "$CERT_DIR/intermediate-ca.key" ]; then
    echo "Error: Intermediate CA files (intermediate-ca.crt and intermediate-ca.key) not found!"
    echo "Please run the intermediate CA creation steps first."
    exit 1
fi

if [ ! -f "$CERT_DIR/ca-chain.crt" ]; then
    echo "Error: ca-chain.crt not found!"
    echo "Create it with: cat intermediate-ca.crt ca.crt > ca-chain.crt"
    exit 1
fi

echo "Creating client certificate for: $CLIENT_NAME (signed by Intermediate CA)"

# 1. Generate client private key
openssl genrsa -out ${CERT_DIR}/${CLIENT_NAME}.key 2048

# 2. Create certificate signing request
openssl req -new -key ${CERT_DIR}/${CLIENT_NAME}.key -out ${CERT_DIR}/${CLIENT_NAME}.csr \
    -subj "/C=US/ST=YourState/L=YourCity/O=YourOrg/CN=${CLIENT_NAME}"

# 3. Sign with INTERMEDIATE CA (not root CA)
openssl x509 -req -in ${CERT_DIR}/${CLIENT_NAME}.csr -CA ${CERT_DIR}/intermediate-ca.crt -CAkey ${CERT_DIR}/intermediate-ca.key \
    -CAcreateserial -out ${CERT_DIR}/${CLIENT_NAME}.crt -days 365

# 4. Create PFX with full certificate chain
openssl pkcs12 -export -out ${CERT_DIR}/${CLIENT_NAME}.pfx \
    -inkey ${CERT_DIR}/${CLIENT_NAME}.key \
    -in ${CERT_DIR}/${CLIENT_NAME}.crt \
    -certfile ${CERT_DIR}/ca-chain.crt \
    -name "${CLIENT_NAME}"

# Clean up CSR
rm ${CERT_DIR}/${CLIENT_NAME}.csr

if [ $? -eq 0 ]; then
    echo "✅ Success! Created certificates for $CLIENT_NAME:"
    echo "  - ${CLIENT_NAME}.key (private key)"
    echo "  - ${CLIENT_NAME}.crt (certificate - signed by Intermediate CA)"
    echo "  - ${CLIENT_NAME}.pfx (PFX with full certificate chain)"
    echo ""
    echo "Certificate chain: Root CA -> Intermediate CA -> ${CLIENT_NAME}"
    echo ""
    echo "Files to copy to client device:"
    echo "  - ca-chain.crt (for server validation)"
    echo "  - ${CLIENT_NAME}.pfx (for client authentication)"
else
    echo "❌ Failed to create certificate"
    exit 1
fi
