using System.Security.Cryptography.X509Certificates;
using System.Text;
using MQTTnet;
using MQTTnet.Server;
using MQTTnet.Protocol;
using System.Security.Authentication;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using MqttProxy;
using System;
using System.Text.Json;
using Microsoft.Extensions.Configuration;

class Program
{
    private static List<X509Certificate2> _trustedCAs = new List<X509Certificate2>();

    private static ConcurrentQueue<Audit> audits = new ConcurrentQueue<Audit>();

    private static IConfigurationRoot? configuration;

    private static Dashboard dashboard;

    static async Task Main(string[] args)
    {

        configuration = new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
            .Build();

        dashboard = new Dashboard(configuration["Dashboard:url"], configuration["Dashboard:token"]);

        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(1));
        var cancellationToken = new CancellationTokenSource();

        Console.WriteLine("starting timer");

        // Handle Ctrl+C for graceful shutdown
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cancellationToken.Cancel();
        };


        var timerTask = Task.Run(() => RunStatisticsTimer(cancellationToken.Token));

        Console.WriteLine("start mqtt");

        try
        {
            // Use consistent relative path (same as client)
            string certsPath = "../../../certs/";

            // Load server certificate
            var serverCert = new X509Certificate2(certsPath + "mqtt-broker.pfx", "",
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

            // Load trusted CAs for client validation
            _trustedCAs = LoadCertificateChain(certsPath + "ca-chain.crt");

            var mqttServerFactory = new MqttServerFactory();

            // Configure mutual TLS for MQTTnet 5.x
            var optionsBuilder = new MqttServerOptionsBuilder()
                .WithEncryptedEndpoint()
                .WithEncryptedEndpointPort(8883)
                .WithEncryptionCertificate(serverCert.Export(X509ContentType.Pfx))
                .WithEncryptionSslProtocol(SslProtocols.Tls12)
                .WithoutDefaultEndpoint();

            var mqttServerOptions = optionsBuilder.Build();

            mqttServerOptions.TlsEndpointOptions.ClientCertificateRequired = true;
            mqttServerOptions.TlsEndpointOptions.CheckCertificateRevocation = false;

            // Set up custom certificate validation
            mqttServerOptions.TlsEndpointOptions.RemoteCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) =>
            {
                if (certificate == null)
                {
                    audits.Enqueue(new Audit{ unusual = true, message = "Invalid or missing certificate" });
                    return false;
                }

                var clientCert = new X509Certificate2(certificate);

                return ValidateClientCertificate(clientCert);
            };

            using var mqttServer = mqttServerFactory.CreateMqttServer(mqttServerOptions);

            // Connection validation with certificate checking
            mqttServer.ValidatingConnectionAsync += async args =>
            {
                try
                {
                    // add some additional authentication check here. 
                    Console.WriteLine("Connection allowed - client certificate validation will occur during message exchange");
                    audits.Enqueue(new Audit { clientId = args.ClientId, message = "Allowing connection" });
                    args.ReasonCode = MqttConnectReasonCode.Success;
                }
                catch (Exception ex)
                {
                    audits.Enqueue(new Audit{ clientId = args.ClientId, unusual = true, message = $"Connection validation error: {ex.Message}" });
                    args.ReasonCode = MqttConnectReasonCode.NotAuthorized;
                }
            };

            mqttServer.ClientConnectedAsync += async args =>
            {
                audits.Enqueue(new Audit { clientId = args.ClientId, message = "Client connected" });
            };

            mqttServer.ClientDisconnectedAsync += async args =>
            {
                audits.Enqueue(new Audit { clientId = args.ClientId, message = "Client disconnected" });
            };

            // Handle regular MQTT messages
            mqttServer.InterceptingPublishAsync += async args =>
            {
                var topic = args.ApplicationMessage.Topic;
                var clientId = args.ClientId;
                var payload = args.ApplicationMessage.ConvertPayloadToString();

                audits.Enqueue(new Audit { clientId = args.ClientId, message = "Published on " + topic });

                args.ProcessPublish = true;
            };

            mqttServer.InterceptingSubscriptionAsync += async args =>
            {
                audits.Enqueue(new Audit{ clientId = args.ClientId, message = "Subscribed to " + args.TopicFilter.Topic });
                args.ProcessSubscription = true;
            };

            await mqttServer.StartAsync();

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

            // Check certificate validity period
            if (DateTime.Now < clientCert.NotBefore || DateTime.Now > clientCert.NotAfter)
            {
                Console.WriteLine($"   Certificate expired or not yet valid");
                audits.Enqueue(new Audit { clientId = clientCert.Subject, unusual = true, message = "Certificate expired or not yet valid" });
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
                audits.Enqueue(new Audit { clientId = clientCert.Subject, message = "Valid certificate" });
            }
            else
            {
                Console.WriteLine($"   Certificate chain validation failed:");
                audits.Enqueue(new Audit { clientId = clientCert.Subject, unusual = true, message = "Certificate chain validation failed" });
            }

            return isValid;
        }
        catch (Exception ex)
        {
            audits.Enqueue(new Audit { clientId = clientCert.Subject, unusual = true, message = $"Certificate validation error: {ex.Message}" });
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

            foreach (var certString in certStrings)
            {
                var cert = new X509Certificate2(Encoding.UTF8.GetBytes(certString));
                certs.Add(cert);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error loading certificate chain: {ex.Message}");
            audits.Enqueue(new Audit { unusual = true, message = $"Error loading certificate chain: {ex.Message}" });
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

    static async Task RunStatisticsTimer(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(1));

        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken))
            {
                await ReportStatistics();
            }
        }
        catch (OperationCanceledException)
        {
            Console.WriteLine("Timer stopped.");
        }
    }

    static async Task ReportStatistics()
    {
        var currentAudits = new List<Audit>();

        // Dequeue all current items
        while (audits.TryDequeue(out var audit))
        {
            currentAudits.Add(audit);
        }

        await dashboard.SendStatistics(currentAudits);

    }
}