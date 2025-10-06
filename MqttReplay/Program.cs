// See https://aka.ms/new-console-template for more information
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using MqttReplay;
using Newtonsoft.Json;

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

X509Certificate SelectLocalCertificate(object sender, string targetHost,
                                                  X509CertificateCollection localCertificates,
                                                  X509Certificate remoteCertificate,
                                                  string[] acceptableIssuers)
{
    Console.WriteLine($"Providing client certificate for mutual TLS authentication");
    string certsPath = "../../../certs/";
    return new X509Certificate(certsPath + "macbookpro.pfx");
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

bool ValidateServerCertificate(object sender, X509Certificate certificate,
                                         X509Chain chain, SslPolicyErrors sslPolicyErrors)
{

    string certsPath = "../../../certs/";
    var caCerts = LoadCertificateChain(certsPath + "ca-chain.crt");

    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
    chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;

    foreach (var caCert in caCerts)
    {
        chain.ChainPolicy.CustomTrustStore.Add(caCert);
    }

    var serverCert = new X509Certificate2(certificate);
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
}



// For TLS connections
async Task SendRawMqttPacket(string hexPacket, string brokerHost, int brokerPort)
{
    using var tcpClient = new TcpClient();
    await tcpClient.ConnectAsync(brokerHost, brokerPort);

    Stream stream = tcpClient.GetStream();

    // For TLS (since you mentioned mutual TLS)
    var sslStream = new SslStream(stream, false, ValidateServerCertificate, SelectLocalCertificate);
    await sslStream.AuthenticateAsClientAsync(brokerHost);

    // Convert hex string to bytes
    byte[] packetBytes = Convert.FromHexString(hexPacket);

    // Send raw packet
    await sslStream.WriteAsync(packetBytes);
    await sslStream.FlushAsync();
}

string jsonfile = "/Users/davidbelle/Projects/uni/attacks/mqtt_replay_data.json";
using (StreamReader r = new StreamReader(jsonfile))
{
    string json = r.ReadToEnd();
    MqttFile file = JsonConvert.DeserializeObject<MqttFile>(json);

    if (file == null || file.mqtt_messages == null)
    {
        return;
    }

    foreach (MqttMessage jsonMessage in file.mqtt_messages)
    {
        await SendRawMqttPacket(jsonMessage.raw_packet, "localhost", 8883);
        await Task.Delay(100); // Add delay to simulate timing
    }

}