using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Newtonsoft.Json;
using MQTTnet;
using MQTTnet.Protocol;
using MqttClient;

class Program
{
    private static string _clientId = "macbookpro";

    static async Task Main(string[] args)
    {
        string secret = "XTCRRDE6OBULY57NGHZ5PD7UZSYYPB67T7LIVN4EHNKQ4YLZC4CQ";
        TotpAuthenticator totp = new TotpAuthenticator(secret);
        Console.WriteLine(totp.GenerateCode());

        Console.WriteLine("=== Simplified Mutual TLS MQTT Client ===");
        Console.WriteLine();


        var factory = new MqttClientFactory();
        var mqttClient = factory.CreateMqttClient();

        string certsPath = "../../../certs/";

        try
        {
            // Load CA chain for server validation
            var caCerts = LoadCertificateChain(certsPath + "ca-chain.crt");
            Console.WriteLine($"Loaded {caCerts.Count} CA certificates for server validation");

            // Load our client certificate for mutual TLS
            var clientCert = new X509Certificate2(certsPath + "macbookpro.pfx", "",
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
            Console.WriteLine($"Client Certificate: {clientCert.Subject}");
            Console.WriteLine($"Has Private Key: {clientCert.HasPrivateKey}");

            // Create connection options using the correct MQTTnet 5.x API
            var options = new MqttClientOptionsBuilder()
                .WithTcpServer("localhost", 8883)
                .WithClientId(_clientId)
                .WithCleanSession()
                .WithTlsOptions(opts =>
                {
                    opts.UseTls();
                    opts.WithClientCertificates(new[] { clientCert });
                    opts.WithSslProtocols(SslProtocols.Tls12);
                    opts.WithCertificateValidationHandler(certContext => {
                        Console.WriteLine($"Validating server certificate: {certContext.Certificate.Subject}");

                        X509Chain chain = new X509Chain();
                        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;

                        foreach (var caCert in caCerts)
                        {
                            chain.ChainPolicy.CustomTrustStore.Add(caCert);
                        }

                        var serverCert = new X509Certificate2(certContext.Certificate);
                        bool isValid = chain.Build(serverCert);

                        Console.WriteLine($"Server certificate validation: {(isValid ? "SUCCESS" : "FAILED")}");

                        if (!isValid)
                        {
                            foreach (var status in chain.ChainStatus)
                            {
                                Console.WriteLine($"   - {status.Status}: {status.StatusInformation}");
                            }
                        }

                        return isValid;
                    });
                })
                .Build();

            // Set up message handler
            mqttClient.ApplicationMessageReceivedAsync += async e =>
            {
                var topic = e.ApplicationMessage.Topic;
                var message = Encoding.UTF8.GetString(e.ApplicationMessage.Payload);
                Console.WriteLine($"Received: {message} on topic: {topic}");
            };

            Console.WriteLine("Connecting to broker with mutual TLS...");
            var result = await mqttClient.ConnectAsync(options, CancellationToken.None);

            if (result.ResultCode == MqttClientConnectResultCode.Success)
            {
                Console.WriteLine("Connected to broker with mutual TLS!");

                // Subscribe to test topic
                await mqttClient.SubscribeAsync("test/topic");
                Console.WriteLine("Subscribed to test/topic");

                await SendTestMessage(mqttClient, 1);

                //// Send test messages
                //for (int i = 0; i < 3; i++)
                //{
                //    await SendTestMessage(mqttClient, i);
                //    await Task.Delay(2000);
                //}

                // Replay("/Users/davidbelle/Projects/uni/attacks/mqtt_replay_data.json", mqttClient);

                Console.WriteLine("Press Enter to disconnect...");
                Console.ReadKey();

                await mqttClient.DisconnectAsync();
            }
            else
            {
                Console.WriteLine($"Connection failed: {result.ResultCode} - {result.ReasonString}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Client error: {ex.Message}");
            if (ex.InnerException != null)
            {
                Console.WriteLine($"Inner: {ex.InnerException.Message}");
            }
        }
        finally
        {
            mqttClient.Dispose();
        }
    }

    static async Task SendTestMessage(IMqttClient client, int messageNumber)
    {
        try
        {
            var message = new MqttApplicationMessageBuilder()
                .WithTopic("metric/send")
                .WithPayload("{\"client_id\":\"SEN01\", \"wl\":5, \"fr\":7}")
                .WithQualityOfServiceLevel(MqttQualityOfServiceLevel.AtLeastOnce)
                .Build();

            await client.PublishAsync(message);
            Console.WriteLine($"Message sent: {Encoding.UTF8.GetString(message.Payload)}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error sending message: {ex.Message}");
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

    static void Replay(string jsonfile, IMqttClient client)
    {
        using (StreamReader r = new StreamReader(jsonfile))
        {
            string json = r.ReadToEnd();
            MqttFile file = JsonConvert.DeserializeObject<MqttFile>(json);

            if (file == null || file.mqtt_messages == null )
            {
                return;
            }

            foreach(MqttMessage jsonMessage in file.mqtt_messages )
            {
                if (jsonMessage.type != "PUBLISH")
                {
                    continue;
                }

                var mqttMessage = new MqttApplicationMessageBuilder()
                .WithTopic(jsonMessage.topic)
                .WithPayload(jsonMessage.payload_text)
                .WithQualityOfServiceLevel(MqttQualityOfServiceLevel.AtMostOnce)
                .WithRetainFlag(jsonMessage.retain)
                .Build();

                client.PublishAsync(mqttMessage);
                    
            }

        }
    }
}