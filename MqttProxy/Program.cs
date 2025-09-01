// See https://aka.ms/new-console-template for more information
using MQTTnet;
using MQTTnet.Internal;
using MQTTnet.Server;

var mqttServerFactory = new MqttServerFactory();
var mqttServerOptions = new MqttServerOptionsBuilder().WithDefaultEndpoint().Build();

using var mqttServer = mqttServerFactory.CreateMqttServer(mqttServerOptions);
mqttServer.InterceptingPublishAsync += async args =>
{
    // Here we only change the topic of the received application message.
    // but also changing the payload etc. is required. Changing the QoS after
    // transmitting is not supported and makes no sense at all.
    // args.ApplicationMessage.Topic += "/manipulated";

    Console.WriteLine(args.ApplicationMessage.Payload);

    //if (args.ClientId != "test-server")
    //{
    //    Console.WriteLine("Injecting new message");
    //    var message = new MqttApplicationMessageBuilder().WithTopic("php-mqtt").WithPayload("Test").Build();
    //    await mqttServer.InjectApplicationMessage(
    //           new InjectedMqttApplicationMessage(message)
    //           {
    //               SenderClientId = "test-server",

    //           });
    //}

};

await mqttServer.StartAsync();



Console.WriteLine("Press Enter to exit.");
Console.ReadLine();
var message = new MqttApplicationMessageBuilder().WithTopic("php-mqtt").WithPayload("Test").Build();
await mqttServer.InjectApplicationMessage(
               new InjectedMqttApplicationMessage(message)
               {
                   SenderClientId = "test-server",

               });
Console.ReadLine();
await mqttServer.StopAsync();






