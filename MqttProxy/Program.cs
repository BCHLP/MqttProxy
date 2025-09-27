using System.Security.Cryptography.X509Certificates;
using System.Text;
using MQTTnet;
using MQTTnet.Server;
using MQTTnet.Protocol;
using System.Security.Authentication;

class Program
{
    private static List<X509Certificate2> _trustedCAs = new List<X509Certificate2>();

    static async Task Main(string[] args)
    {
        Console.WriteLine("=== Mutual TLS MQTT Broker ===");
        Console.WriteLine("TLS encryption with server certificate");
        Console.WriteLine("Client authentication via mutual TLS");
        Console.WriteLine();

        try
        {
            // Use consistent relative path (same as client)
            string certsPath = "../../../certs/";

            // Load server certificate
            var serverCert = new X509Certificate2(certsPath + "mqtt-broker.pfx", "",
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

            // Load trusted CAs for client validation
            _trustedCAs = LoadCertificateChain(certsPath + "ca-chain.crt");

            Console.WriteLine($"Server Certificate: {serverCert.Subject}");
            Console.WriteLine($"Loaded {_trustedCAs.Count} trusted CAs for client validation:");
            foreach (var ca in _trustedCAs)
            {
                Console.WriteLine($"   - {ca.Subject}");
            }

            var mqttServerFactory = new MqttServerFactory();

            // Configure mutual TLS for MQTTnet 5.x
            var optionsBuilder = new MqttServerOptionsBuilder()
                .WithEncryptedEndpoint()
                .WithEncryptedEndpointPort(8883)
                .WithEncryptionCertificate(serverCert.Export(X509ContentType.Pfx))
                .WithEncryptionSslProtocol(SslProtocols.Tls12)
                .WithoutDefaultEndpoint();

            var mqttServerOptions = optionsBuilder.Build();

            // CRITICAL: Enable client certificate requirement for mutual TLS
            mqttServerOptions.TlsEndpointOptions.ClientCertificateRequired = true;
            mqttServerOptions.TlsEndpointOptions.CheckCertificateRevocation = false;

            // Set up custom certificate validation
            mqttServerOptions.TlsEndpointOptions.RemoteCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) =>
            {
                if (certificate == null)
                {
                    Console.WriteLine("No client certificate provided");
                    return false;
                }

                var clientCert = new X509Certificate2(certificate);
                Console.WriteLine($"Validating client certificate: {clientCert.Subject}");

                return ValidateClientCertificate(clientCert);
            };

            using var mqttServer = mqttServerFactory.CreateMqttServer(mqttServerOptions);

            // Connection validation with certificate checking
            mqttServer.ValidatingConnectionAsync += async args =>
            {
                Console.WriteLine($"\nVALIDATING CONNECTION: {args.ClientId} from {args.Endpoint}");

                try
                {
                    // For now, allow the connection - we'll validate certificates via client authentication
                    // In a production setup, you'd check if the client provided a valid certificate
                    Console.WriteLine("Connection allowed - client certificate validation will occur during message exchange");
                    args.ReasonCode = MqttConnectReasonCode.Success;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Connection validation error: {ex.Message}");
                    args.ReasonCode = MqttConnectReasonCode.NotAuthorized;
                }
            };

            mqttServer.ClientConnectedAsync += async args =>
            {
                Console.WriteLine($"CLIENT CONNECTED: {args.ClientId} from {args.Endpoint}");
                Console.WriteLine($"   Authenticated via mutual TLS");
            };

            mqttServer.ClientDisconnectedAsync += async args =>
            {
                Console.WriteLine($"CLIENT DISCONNECTED: {args.ClientId}");
            };

            // Handle regular MQTT messages
            mqttServer.InterceptingPublishAsync += async args =>
            {
                var topic = args.ApplicationMessage.Topic;
                var clientId = args.ClientId;
                var payload = args.ApplicationMessage.ConvertPayloadToString();

                Console.WriteLine($"MESSAGE from {clientId}: '{payload}' on '{topic}'");

                // All messages are allowed since client is already authenticated via mutual TLS
                args.ProcessPublish = true;
            };

            mqttServer.InterceptingSubscriptionAsync += async args =>
            {
                Console.WriteLine($"SUBSCRIPTION from {args.ClientId}: {args.TopicFilter.Topic}");
                args.ProcessSubscription = true;
            };

            await mqttServer.StartAsync();
            Console.WriteLine("Mutual TLS Broker started!");
            Console.WriteLine("   - TLS encryption enabled");
            Console.WriteLine("   - Client certificate authentication required");
            Console.WriteLine("   - Listening on port 8883");
            Console.WriteLine();

            Console.WriteLine("Press Enter to stop broker...");
            Console.ReadLine();

            await mqttServer.StopAsync();
            Console.WriteLine("Broker stopped.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Broker error: {ex.Message}");
            if (ex.InnerException != null)
            {
                Console.WriteLine($"Inner: {ex.InnerException.Message}");
            }
        }
    }

    static bool ValidateClientCertificate(X509Certificate2 clientCert)
    {
        try
        {
            Console.WriteLine($"   Certificate: {clientCert.Subject}");
            Console.WriteLine($"   Issued by: {clientCert.Issuer}");
            Console.WriteLine($"   Valid: {clientCert.NotBefore} to {clientCert.NotAfter}");

            // Check certificate validity period
            if (DateTime.Now < clientCert.NotBefore || DateTime.Now > clientCert.NotAfter)
            {
                Console.WriteLine($"   Certificate expired or not yet valid");
                return false;
            }

            // Build certificate chain against trusted CAs
            X509Chain chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;

            // Add trusted CAs to the trust store
            foreach (var caCert in _trustedCAs)
            {
                chain.ChainPolicy.CustomTrustStore.Add(caCert);
            }

            bool isValid = chain.Build(clientCert);

            if (isValid)
            {
                Console.WriteLine($"   Certificate chain validation successful");

                // Print the validated chain
                Console.WriteLine($"   Certificate chain:");
                for (int i = 0; i < chain.ChainElements.Count; i++)
                {
                    var element = chain.ChainElements[i];
                    string certType = i == 0 ? "Client" :
                                     i == chain.ChainElements.Count - 1 ? "Root CA" :
                                     "Intermediate CA";
                    Console.WriteLine($"      {i}: {certType} - {element.Certificate.Subject}");
                }
            }
            else
            {
                Console.WriteLine($"   Certificate chain validation failed:");
                foreach (var status in chain.ChainStatus)
                {
                    Console.WriteLine($"      - {status.Status}: {status.StatusInformation}");
                }

                // Print the chain for debugging
                Console.WriteLine($"   Certificate chain (invalid):");
                for (int i = 0; i < chain.ChainElements.Count; i++)
                {
                    var element = chain.ChainElements[i];
                    Console.WriteLine($"      {i}: {element.Certificate.Subject}");
                    if (element.ChainElementStatus.Length > 0)
                    {
                        foreach (var status in element.ChainElementStatus)
                        {
                            Console.WriteLine($"         Error: {status.Status} - {status.StatusInformation}");
                        }
                    }
                }
            }

            return isValid;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"   Certificate validation error: {ex.Message}");
            return false;
        }
    }

    static List<X509Certificate2> LoadCertificateChain(string chainFilePath)
    {
        var certs = new List<X509Certificate2>();

        try
        {
            var chainContent = File.ReadAllText(chainFilePath);
            var certStrings = SplitPemCertificates(chainContent);

            Console.WriteLine($"Found {certStrings.Count} certificates in chain file");

            foreach (var certString in certStrings)
            {
                var cert = new X509Certificate2(Encoding.UTF8.GetBytes(certString));
                certs.Add(cert);
                Console.WriteLine($"   - Loaded: {cert.Subject}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error loading certificate chain: {ex.Message}");
        }

        return certs;
    }

    static List<string> SplitPemCertificates(string pemContent)
    {
        var certs = new List<string>();
        var lines = pemContent.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
        var currentCert = new List<string>();
        bool inCert = false;

        foreach (var line in lines)
        {
            if (line.Contains("-----BEGIN CERTIFICATE-----"))
            {
                inCert = true;
                currentCert.Clear();
                currentCert.Add(line);
            }
            else if (line.Contains("-----END CERTIFICATE-----"))
            {
                currentCert.Add(line);
                certs.Add(string.Join("\n", currentCert));
                inCert = false;
            }
            else if (inCert)
            {
                currentCert.Add(line);
            }
        }

        return certs;
    }
}