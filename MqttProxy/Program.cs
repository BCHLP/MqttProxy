using System.Security.Cryptography.X509Certificates;
using MQTTnet;
using MQTTnet.Server;


Console.WriteLine("=== Simple MQTTnet Broker with TLS ===");

try
{
    // Step 1: Load server certificate WITH private key
    Console.WriteLine("Loading server certificate...");
    var serverCert = new X509Certificate2("/Users/davidbelle/Projects/uni/certs/mqtt-broker.pfx", "",
        X509KeyStorageFlags.Exportable);

    Console.WriteLine($"✅ Server Certificate: {serverCert.Subject}");
    Console.WriteLine($"✅ Has Private Key: {serverCert.HasPrivateKey}");
    Console.WriteLine($"✅ Valid Until: {serverCert.NotAfter}");

    if (!serverCert.HasPrivateKey)
    {
        Console.WriteLine("❌ ERROR: Server certificate missing private key!");
        Console.WriteLine("Create PFX: openssl pkcs12 -export -out mqtt-broker.pfx -inkey mqtt-broker.key -in mqtt-broker.crt");
        return;
    }

    // Step 2: Create simple MQTT server with TLS
    var mqttServerFactory = new MqttServerFactory();
    var mqttServerOptions = new MqttServerOptionsBuilder()
        .WithEncryptionCertificate(serverCert)
        .WithEncryptedEndpoint() // This creates TLS listener on port 8883
        .WithoutDefaultEndpoint() // Disable non-TLS port 1883
        .Build();

    using var mqttServer = mqttServerFactory.CreateMqttServer(mqttServerOptions);

    // Step 3: Event handlers
    mqttServer.ClientConnectedAsync += async args =>
    {
        Console.WriteLine($"🔗 CLIENT CONNECTED: {args.ClientId} from {args.Endpoint}");
    };

    mqttServer.ClientDisconnectedAsync += async args =>
    {
        Console.WriteLine($"❌ CLIENT DISCONNECTED: {args.ClientId} ({args.DisconnectType})");
    };

    mqttServer.ValidatingConnectionAsync += async args =>
    {
        Console.WriteLine($"🔐 CONNECTION ATTEMPT: {args.ClientId} from {args.Endpoint}");
        // Allow all connections for now (basic TLS only)
        args.ReasonCode = MQTTnet.Protocol.MqttConnectReasonCode.Success;
    };

    mqttServer.InterceptingPublishAsync += async args =>
    {
        Console.WriteLine($"📝 MESSAGE: '{args.ApplicationMessage.ConvertPayloadToString()}' on topic: '{args.ApplicationMessage.Topic}'");
    };

    // Step 4: Start server
    await mqttServer.StartAsync();
    Console.WriteLine("🚀 MQTT Broker started!");
    Console.WriteLine("   - TLS enabled on port 8883");
    Console.WriteLine("   - Accepting all TLS connections (no mutual auth yet)");
    Console.WriteLine("   - Ready for client connections");

    // Test message
    Console.WriteLine("\n📤 Injecting test message...");
    var testMessage = new MqttApplicationMessageBuilder()
        .WithTopic("test/topic")
        .WithPayload("Hello from TLS broker!")
        .Build();

    await mqttServer.InjectApplicationMessage(
        new InjectedMqttApplicationMessage(testMessage)
        {
            SenderClientId = "test-server",
        });

    Console.WriteLine("\nPress Enter to stop broker...");
    Console.ReadLine();

    await mqttServer.StopAsync();
    Console.WriteLine("🛑 Broker stopped.");
}
catch (Exception ex)
{
    Console.WriteLine($"❌ Broker error: {ex.Message}");
    if (ex.InnerException != null)
    {
        Console.WriteLine($"Inner: {ex.InnerException.Message}");
    }
}


/**
// See https://aka.ms/new-console-template for more information
using System.Net;
using MQTTnet;
using MQTTnet.Internal;
using MQTTnet.Server;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;


X509Certificate2 certificate = new X509Certificate2("/Users/davidbelle/Projects/uni/certs/mqtt-broker.crt");

var mqttServerFactory = new MqttServerFactory();
var mqttServerOptions = new MqttServerOptionsBuilder()
    .WithEncryptionCertificate(certificate)
    .WithEncryptedEndpoint()
    .Build();

using var mqttServer = mqttServerFactory.CreateMqttServer(mqttServerOptions);
mqttServer.InterceptingPublishAsync += async args =>
{

    Console.WriteLine("PAYLOAD:" + args.ApplicationMessage.ConvertPayloadToString());

};
mqttServer.ClientConnectedAsync += async args =>
{
    Console.WriteLine($"CLIENT CONNECTED: {args.ClientId} from {args.Endpoint}");
};

mqttServer.ClientDisconnectedAsync += async args =>
{
    Console.WriteLine($"CLIENT DISCONNECTED: {args.ClientId}");
};

mqttServer.ValidatingConnectionAsync += async args =>
{
    Console.WriteLine($"CONNECTION ATTEMPT: {args.ClientId} from {args.Endpoint}");
    args.ReasonCode = MQTTnet.Protocol.MqttConnectReasonCode.Success; // Allow connection
};


await mqttServer.StartAsync();

Console.WriteLine("Press Enter to exit.");
// Console.ReadLine();
var message = new MqttApplicationMessageBuilder().WithTopic("php-mqtt").WithPayload("Test").Build();
await mqttServer.InjectApplicationMessage(
               new InjectedMqttApplicationMessage(message)
               {
                   SenderClientId = "test-server",

               });
Console.ReadLine();
await mqttServer.StopAsync();


*/