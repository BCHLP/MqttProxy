# MQTT PKI Certificate Setup Guide

This guide explains how to create a complete Public Key Infrastructure (PKI) for secure MQTT communications using a Root CA and Intermediate CA structure.

## Overview

This setup creates a three-tier certificate hierarchy:

```
Root CA (Self-signed, kept offline/secure)
    └── Intermediate CA (Signed by Root CA)
        ├── MQTT Broker Certificate
        └── Client Certificates (created via script)
```

## Prerequisites

- OpenSSL installed on your system
- Basic understanding of PKI concepts
- Directory to store certificates (e.g., `certs/`)

## Directory Structure

After completing this guide, you'll have:

```
certs/
├── ca.crt                    # Root CA certificate (distribute to clients)
├── ca.key                    # Root CA private key (KEEP SECURE!)
├── intermediate-ca.crt       # Intermediate CA certificate
├── intermediate-ca.key       # Intermediate CA private key (KEEP SECURE!)
├── ca-chain.crt             # Certificate chain (intermediate + root)
├── mqtt-broker.crt          # MQTT broker certificate
├── mqtt-broker.key          # MQTT broker private key
├── mqtt-broker.pfx          # MQTT broker PFX bundle
└── ... (client certificates created via script)
```

## Step 1: Create Root Certificate Authority (CA)

The Root CA is the foundation of your PKI. Keep the private key extremely secure!


# Create certificates directory
mkdir -p certs
cd certs

# 1. Generate Root CA private key (4096-bit for extra security)
openssl genrsa -out ca.key 4096

# 2. Create Root CA certificate (valid for 10 years)
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
    -sha384 \
    -subj "/C=US/ST=YourState/L=YourCity/O=YourOrg/CN=MQTT-Root-CA"\
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"


** Security Note**: The `ca.key` file is extremely sensitive. In production:
- Store it offline or in a Hardware Security Module (HSM)
- Use strong file permissions: `chmod 400 ca.key`
- Consider encrypting it with a passphrase

## Step 2: Create Intermediate Certificate Authority

The Intermediate CA will handle day-to-day certificate signing:

# 1. Generate Intermediate CA private key
openssl genrsa -out intermediate-ca.key 4096

# 2. Create Certificate Signing Request (CSR) for Intermediate CA
openssl req -new -key intermediate-ca.key -out intermediate-ca.csr \
    -subj "/C=US/ST=YourState/L=YourCity/O=YourOrg/CN=MQTT-Intermediate-CA"

# 3. Sign Intermediate CA certificate with Root CA (valid for 5 years)
openssl x509 -req -in intermediate-ca.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out intermediate-ca.crt -days 1825 -sha384 \
    -extfile <(printf "basicConstraints=critical,CA:true,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign") 

# 4. Create certificate chain file (Intermediate + Root)
cat intermediate-ca.crt ca.crt > ca-chain.crt

# 5. Clean up CSR file
rm intermediate-ca.csr

## Step 3: Create MQTT Broker Certificate

Create the server certificate for your MQTT broker:

# 1. Generate broker private key
openssl genrsa -out mqtt-broker.key 4096

# 2. Create broker Certificate Signing Request
openssl req -new -key mqtt-broker.key -out mqtt-broker.csr \
   -subj "/C=US/ST=YourState/L=YourCity/O=YourOrg/CN=broker.bchklp.com" \
   -addext "subjectAltName=DNS:broker.bchklp.com"

# 3. Sign broker certificate with Intermediate CA (including SAN)
openssl x509 -req -in mqtt-broker.csr \
    -CA intermediate-ca.crt \
    -CAkey intermediate-ca.key \
    -CAcreateserial \
    -out mqtt-broker.crt \
    -days 365 \
    -sha384 \
    -extfile <(printf "subjectAltName=DNS:broker.bchklp.com\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth")

# 4. Create broker PFX bundle (includes full certificate chain)
openssl pkcs12 -export -out mqtt-broker.pfx \
    -inkey mqtt-broker.key \
    -in mqtt-broker.crt \
    -certfile ca-chain.crt \
    -name "mqtt-broker"

# 5. Clean up CSR file
rm mqtt-broker.csr

** Note **: When prompted for PFX password, press Enter for no password (or set a password and update your broker code accordingly).

## Step 4: Verify Certificate Chain

Verify that your certificates are properly signed:

```bash
# Verify intermediate CA is signed by root CA
openssl verify -CAfile ca.crt intermediate-ca.crt

# Verify broker certificate is signed by intermediate CA
openssl verify -CAfile ca-chain.crt mqtt-broker.crt

# Check certificate details
openssl x509 -in ca.crt -text -noout | grep -A2 "Subject:"
openssl x509 -in intermediate-ca.crt -text -noout | grep -A2 "Subject:"
openssl x509 -in mqtt-broker.crt -text -noout | grep -A2 "Subject:"
```

Expected output should show successful verification and proper subject names.

## Step 5: Secure Your Private Keys

Set appropriate file permissions to protect private keys:

```bash
# Restrict access to private keys
chmod 400 ca.key intermediate-ca.key mqtt-broker.key

# Make certificates readable
chmod 444 ca.crt intermediate-ca.crt mqtt-broker.crt ca-chain.crt

# Make PFX readable by your application
chmod 444 mqtt-broker.pfx
```

## Step 6: Certificate Information Summary

After completing these steps, you can view your certificate information:

```bash
echo "=== Root CA ==="
openssl x509 -in ca.crt -noout -subject -dates

echo "=== Intermediate CA ==="
openssl x509 -in intermediate-ca.crt -noout -subject -dates

echo "=== MQTT Broker ==="
openssl x509 -in mqtt-broker.crt -noout -subject -dates

echo "=== PFX Contents ==="
openssl pkcs12 -in mqtt-broker.pfx -nokeys -info
```

## Configuration Notes

### Customizing Certificate Fields

Modify these fields in the certificate commands according to your organization:

- `C=US` → Your country code
- `ST=YourState` → Your state/province
- `L=YourCity` → Your city
- `O=YourOrg` → Your organization name
- `CN=...` → Common Name (critical for broker certificate!)

### Broker Common Name (CN)

The broker certificate's Common Name **must match** how clients connect:

- If connecting via `localhost` → use `CN=localhost`
- If connecting via IP `192.168.1.100` → use `CN=192.168.1.100`
- If connecting via domain `mqtt.company.com` → use `CN=mqtt.company.com`

### Certificate Lifetimes

Recommended certificate lifetimes:

- **Root CA**: 10 years (3650 days) - rarely changed
- **Intermediate CA**: 5 years (1825 days) - changed occasionally
- **Server/Client certificates**: 1 year (365 days) - renewed regularly

## Troubleshooting

### "certificate verify failed" errors

1. **Check certificate chain**: Ensure `ca-chain.crt` contains both intermediate and root CA
2. **Verify dates**: Check certificates haven't expired
3. **Common Name mismatch**: Ensure broker CN matches connection hostname

### "unable to load certificate" errors

1. **File permissions**: Ensure certificates are readable
2. **File format**: Ensure certificates are in PEM format
3. **File corruption**: Regenerate certificates if needed

### PFX loading issues

```bash
# Test PFX file
openssl pkcs12 -in mqtt-broker.pfx -nokeys -info

# If needed, recreate PFX
openssl pkcs12 -export -out mqtt-broker.pfx \
    -inkey mqtt-broker.key -in mqtt-broker.crt -certfile ca-chain.crt
```

## Certificate Renewal

When certificates near expiration:

### Renewing Broker Certificate
```bash
# Generate new CSR (or reuse existing key)
openssl req -new -key mqtt-broker.key -out mqtt-broker.csr \
    -subj "/C=US/ST=YourState/L=YourCity/O=YourOrg/CN=localhost"

# Sign with intermediate CA
openssl x509 -req -in mqtt-broker.csr -CA intermediate-ca.crt -CAkey intermediate-ca.key \
    -CAcreateserial -out mqtt-broker.crt -days 365

# Recreate PFX
openssl pkcs12 -export -out mqtt-broker.pfx \
    -inkey mqtt-broker.key -in mqtt-broker.crt -certfile ca-chain.crt
```

### Renewing Intermediate CA
This is more complex and requires updating all certificates signed by the intermediate CA.

## Next Steps

1. **Create client certificates**: Use the `create_client_with_intermediate.sh` script
2. **Configure MQTT broker**: Load the `mqtt-broker.pfx` file in your broker
3. **Configure MQTT clients**: Use `ca-chain.crt` for server validation and client PFX files for authentication
4. **Backup certificates**: Store copies securely, especially private keys
5. **Set up renewal procedures**: Plan for certificate lifecycle management

## Security Best Practices

- **Never share private keys** (`.key` files)
- **Backup your Root CA key securely** - losing it means recreating entire PKI
- **Use strong file permissions** on private keys (chmod 400)
- **Consider using passphrases** for private keys in production
- **Rotate certificates regularly** before expiration
- **Monitor certificate expiration dates**
- **Keep Root CA offline** when not needed for signing

## File Distribution

**To MQTT broker**:
- `mqtt-broker.pfx` (server certificate with private key)
- `ca-chain.crt` (for client certificate validation)

**To MQTT clients**:
- `ca-chain.crt` (for server certificate validation)
- `clientX.pfx` (client certificate with private key)

**Keep secure/offline**:
- `ca.key` (root CA private key)
- `intermediate-ca.key` (intermediate CA private key)

Your MQTT PKI is now ready for production use! 🎉