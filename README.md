# MQTT Proxy - Secure IoT Data Forwarding System

A secure MQTT-based infrastructure for forwarding IoT sensor data to a dashboard using mutual TLS authentication. This project implements a complete PKI (Public Key Infrastructure) with Root CA and Intermediate CA for secure client-server communication.

**Repository**: https://github.com/BCHLP/MqttProxy

## Overview

This system consists of two main components:

1. **MqttProxy** - MQTT broker with mutual TLS authentication
2. **MqttClient** - MQTT client that receives sensor data via UDP and forwards to the broker

### Data Flow

```
IoT Sensor → UDP → MqttClient → MQTT (TLS) → MqttProxy → Dashboard
```

The MqttClient listens for UDP packets from sensors, converts them to MQTT messages, and forwards them securely to the MqttProxy broker. The broker then relays messages to the [dashboard](https://github.com/BCHLP/dashboard) for visualization and monitoring.

## Features

- **Mutual TLS Authentication**: Both client and server authenticate using X.509 certificates
- **Three-tier PKI**: Root CA → Intermediate CA → Client/Server certificates
- **UDP to MQTT Gateway**: MqttClient forwards UDP sensor data to MQTT
- **Certificate Chain Validation**: Custom certificate validation against trusted CA chain
- **Audit Logging**: Connection and message auditing capabilities
- **Dashboard Integration**: Direct integration with custom monitoring dashboard

## Prerequisites

- .NET 8.0 SDK
- OpenSSL (for certificate generation)
- All NuGet package dependencies are automatically restored during build

## Project Structure

```
MqttAlpha/
├── MqttProxy/              # MQTT broker with mutual TLS
│   ├── certs/             # Certificate storage directory
│   ├── Program.cs         # Main broker implementation
│   ├── appsettings.json   # Broker configuration
│   ├── create_client_cert.sh  # Client certificate generation script
│   └── README.md          # Detailed PKI setup guide
├── MqttClient/            # MQTT client with UDP forwarding
│   ├── Program.cs         # Main client implementation
│   ├── UdpToMqttForwarder.cs  # UDP to MQTT conversion
│   └── appsettings.json   # Client configuration
└── MqttProxy.sln          # Solution file
```

## Installation & Setup

### 1. Clone the Repository

```bash
git clone https://github.com/BCHLP/MqttProxy.git
cd MqttProxy
```

### 2. Create PKI Certificates

Follow the detailed certificate setup guide in `MqttProxy/README.md`. Here's a quick summary:

#### Create Root CA
```bash
cd MqttProxy/certs

# Generate Root CA key and certificate
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
    -sha384 \
    -subj "/C=US/ST=YourState/L=YourCity/O=YourOrg/CN=MQTT-Root-CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
```

#### Create Intermediate CA
```bash
# Generate Intermediate CA key
openssl genrsa -out intermediate-ca.key 4096

# Create CSR for Intermediate CA
openssl req -new -key intermediate-ca.key -out intermediate-ca.csr \
    -subj "/C=US/ST=YourState/L=YourCity/O=YourOrg/CN=MQTT-Intermediate-CA"

# Sign with Root CA
openssl x509 -req -in intermediate-ca.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out intermediate-ca.crt -days 1825 -sha384 \
    -extfile <(printf "basicConstraints=critical,CA:true,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign")

# Create certificate chain
cat intermediate-ca.crt ca.crt > ca-chain.crt
rm intermediate-ca.csr
```

#### Create Broker Certificate
```bash
# Generate broker key
openssl genrsa -out mqtt-broker.key 4096

# Create broker CSR (replace localhost with your broker hostname)
openssl req -new -key mqtt-broker.key -out mqtt-broker.csr \
   -subj "/C=US/ST=YourState/L=YourCity/O=YourOrg/CN=localhost" \
   -addext "subjectAltName=DNS:localhost"

# Sign with Intermediate CA
openssl x509 -req -in mqtt-broker.csr \
    -CA intermediate-ca.crt \
    -CAkey intermediate-ca.key \
    -CAcreateserial \
    -out mqtt-broker.crt \
    -days 365 \
    -sha384 \
    -extfile <(printf "subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth")

# Create PFX bundle (press Enter when prompted for password)
openssl pkcs12 -export -out mqtt-broker.pfx \
    -inkey mqtt-broker.key \
    -in mqtt-broker.crt \
    -certfile ca-chain.crt \
    -name "mqtt-broker"

rm mqtt-broker.csr
```

#### Create Client Certificates

Use the provided script to create client certificates:

```bash
cd MqttProxy
./create_client_cert.sh client-name
```

This creates:
- `client-name.key` - Private key
- `client-name.crt` - Certificate signed by Intermediate CA
- `client-name.pfx` - PFX bundle for the client

**Important**: Replace `client-name` with a unique identifier for each client (e.g., sensor ID or device name).

### 3. Configure MqttProxy (Broker)

Edit `MqttProxy/appsettings.json`:

```json
{
  "Dashboard": {
    "url": "https://your-dashboard-url.com",
    "token": "your-dashboard-api-token"
  },
  "Certificate": "certs/mqtt-broker.pfx",
  "CaChain": "certs/ca-chain.crt"
}
```

**Note**: Use relative paths if `appsettings.json` is in the same directory as the binary, or absolute paths otherwise.

### 4. Configure MqttClient

Edit `MqttClient/appsettings.json`:

```json
{
  "ListenerPort": 1700,
  "SenderPort": 1705,
  "SenderIp": "127.0.0.1",
  "Broker": "localhost",
  "Certificate": "certs/your-client-name.pfx",
  "CaChain": "certs/ca-chain.crt",
  "ClientId": "unique-client-id"
}
```

**Configuration Parameters**:
- `ListenerPort`: UDP port to listen for incoming sensor data
- `SenderPort`: UDP port to send responses back to sensors
- `SenderIp`: IP address to send UDP responses
- `Broker`: MQTT broker hostname (must match broker certificate CN)
- `Certificate`: Path to client PFX certificate
- `CaChain`: Path to CA chain for server validation
- `ClientId`: Unique identifier for this client (replace "David" placeholder)

### 5. Build the Projects

```bash
# Build entire solution
dotnet build MqttProxy.sln

# Or build individually
cd MqttProxy
dotnet build

cd ../MqttClient
dotnet build
```

### 6. Run the System

#### Start the MQTT Broker
```bash
cd MqttProxy/bin/Debug/net8.0
dotnet MqttProxy.dll
```

The broker will:
- Start listening on port 8883 (MQTT over TLS)
- Require client certificates for authentication
- Validate client certificates against the CA chain
- Log connections and publish events

#### Start the MQTT Client
```bash
cd MqttClient/bin/Debug/net8.0
dotnet MqttClient.dll
```

The client will:
- Connect to the broker using mutual TLS
- Listen for UDP packets on the configured port
- Convert UDP data to MQTT messages and publish to broker
- Forward received MQTT messages back via UDP

## Usage

### Sending Sensor Data

Send UDP packets to the MqttClient listener port (default 1700) in JSON format:

```json
{
  "payload": "your sensor data here",
  "qos": 1,
  "retain": false
}
```

The client will forward this to the MQTT broker on topic `/application/1/device/SEN-001/down`.

### Certificate Distribution

**For the MQTT Broker**:
- Copy `mqtt-broker.pfx` to the broker's certs directory
- Copy `ca-chain.crt` to the broker's certs directory

**For Each MQTT Client**:
- Copy `ca-chain.crt` (for server validation)
- Copy `client-name.pfx` (for client authentication)

## Security Considerations

This project is designed for **testing and educational purposes**. For production use:

1. **Protect Private Keys**:
   ```bash
   chmod 400 certs/*.key
   ```

2. **Store Root CA Offline**: Keep `ca.key` in secure, offline storage

3. **Use Strong Passwords**: Add passwords to PFX files in production

4. **Regular Certificate Rotation**: Renew certificates before expiration (1 year default)

5. **Network Security**: Use firewalls to restrict access to MQTT port 8883

6. **Audit Logs**: Monitor connection attempts and unusual activity

## Troubleshooting

### Certificate Verification Failed

- Ensure the broker's Common Name (CN) matches the hostname used to connect
- Verify `ca-chain.crt` contains both intermediate and root CA certificates
- Check certificate expiration dates

### Connection Refused

- Verify the broker is running and listening on port 8883
- Check firewall rules allow TCP traffic on port 8883
- Ensure certificate paths in `appsettings.json` are correct

### UDP Forwarding Not Working

- Verify `ListenerPort` and `SenderPort` are not blocked by firewall
- Check that the sensor is sending to the correct IP and port
- Ensure JSON format of UDP packets is valid

### File Not Found Errors

- Ensure `appsettings.json` is in the same directory as the binary
- Use absolute paths for certificates if needed
- Verify certificate files exist at specified paths

## Development

### Project Dependencies

Both projects use:
- MQTTnet (v5.x) - MQTT client/server library
- Newtonsoft.Json - JSON serialization
- Microsoft.Extensions.Configuration - Configuration management

All dependencies are managed via NuGet and restored automatically during build.

### Adding New Clients

To add a new client device:

1. Generate a client certificate:
   ```bash
   ./create_client_cert.sh new-device-name
   ```

2. Copy files to the device:
   - `new-device-name.pfx`
   - `ca-chain.crt`

3. Update the device's `appsettings.json` with unique `ClientId` and certificate path

## Related Projects

- [Dashboard](https://github.com/BCHLP/dashboard) - Web dashboard for monitoring sensor data

## License

Educational/University Assignment Project

## Support

For issues and questions, please open an issue on the [GitHub repository](https://github.com/BCHLP/MqttProxy/issues).
