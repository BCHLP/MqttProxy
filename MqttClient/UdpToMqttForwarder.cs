using System.Net;
using System.Net.Sockets;
using System.Text;
using MQTTnet;
using MQTTnet.Protocol;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace MqttClient
{
    public class UdpToMqttForwarder
    {
        private readonly int _udpListenPort;
        private readonly int _udpSendPort;
        private readonly string _udpSendHost;
        private readonly IMqttClient _mqttClient;
        private UdpClient? _udpListener;
        private UdpClient? _udpSender;
        private CancellationTokenSource? _cancellationTokenSource;
        private Task? _listenerTask;
        private string _clientId;

        public UdpToMqttForwarder(int udpListenPort, int udpSendPort, string udpSendHost, IMqttClient mqttClient, string clientId)
        {
            _udpListenPort = udpListenPort;
            _udpSendPort = udpSendPort;
            _udpSendHost = udpSendHost;
            _mqttClient = mqttClient;
            _clientId = clientId;
        }

        public void Start()
        {
            if (_listenerTask != null)
            {
                Console.WriteLine("UDP listener is already running.");
                return;
            }

            _cancellationTokenSource = new CancellationTokenSource();
            _listenerTask = Task.Run(() => ListenForUdpPackets(_cancellationTokenSource.Token));
            _udpSender = new UdpClient();
            Console.WriteLine($"UDP listener started on port {_udpListenPort}");
            Console.WriteLine($"UDP sender configured for {_udpSendHost}:{_udpSendPort}");
        }

        public async Task Stop()
        {
            if (_cancellationTokenSource != null)
            {
                _cancellationTokenSource.Cancel();
            }

            if (_listenerTask != null)
            {
                await _listenerTask;
            }

            _udpListener?.Close();
            _udpListener?.Dispose();
            _udpListener = null;

            _udpSender?.Close();
            _udpSender?.Dispose();
            _udpSender = null;

            _listenerTask = null;

            Console.WriteLine("UDP listener and sender stopped.");
        }

        private async Task ListenForUdpPackets(CancellationToken cancellationToken)
        {
            _udpListener = new UdpClient(_udpListenPort);
            Console.WriteLine($"Listening for UDP packets on port {_udpListenPort}...");

            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    try
                    {
                        var result = await _udpListener.ReceiveAsync(cancellationToken);
                        var payload = Encoding.UTF8.GetString(result.Buffer);
                        var remoteEndPoint = result.RemoteEndPoint;

                        Console.WriteLine($"Received UDP packet from {remoteEndPoint}: {payload.Length} bytes");

                        await ProcessUdpPayload(payload, remoteEndPoint);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error receiving UDP packet: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"UDP listener error: {ex.Message}");
            }
            finally
            {
                _udpListener?.Close();
            }
        }

        private async Task ProcessUdpPayload(string payload, IPEndPoint remoteEndPoint)
        {
            try
            {
                // Try to parse as JSON
                var jsonObject = JObject.Parse(payload);

                // Extract topic and message payload
                // Default topic if not specified
                // string topic = jsonObject["topic"]?.ToString() ?? $"udp/{remoteEndPoint.Address}";
                string topic = "application/1/device/"+_clientId+"/command/up";

                // If the JSON has a 'payload' or 'message' field, use that, otherwise use the entire JSON
                string messagePayload;
                if (jsonObject["payload"] != null)
                {
                    messagePayload = jsonObject["payload"]!.ToString();
                }
                else if (jsonObject["message"] != null)
                {
                    messagePayload = jsonObject["message"]!.ToString();
                }
                else
                {
                    // Use the entire JSON as the payload
                    messagePayload = payload;
                }

                // Determine QoS level (default to AtLeastOnce)
                var qos = MqttQualityOfServiceLevel.AtLeastOnce;
                if (jsonObject["qos"] != null)
                {
                    var qosValue = jsonObject["qos"]!.Value<int>();
                    qos = qosValue switch
                    {
                        0 => MqttQualityOfServiceLevel.AtMostOnce,
                        1 => MqttQualityOfServiceLevel.AtLeastOnce,
                        2 => MqttQualityOfServiceLevel.ExactlyOnce,
                        _ => MqttQualityOfServiceLevel.AtLeastOnce
                    };
                }

                // Check for retain flag
                bool retain = jsonObject["retain"]?.Value<bool>() ?? false;

                // Create and publish MQTT message
                var mqttMessage = new MqttApplicationMessageBuilder()
                    .WithTopic(topic)
                    .WithPayload(messagePayload)
                    .WithQualityOfServiceLevel(qos)
                    .WithRetainFlag(retain)
                    .Build();

                await _mqttClient.PublishAsync(mqttMessage);
                Console.WriteLine($"Forwarded to MQTT - Topic: {topic}, Payload: {messagePayload.Substring(0, Math.Min(100, messagePayload.Length))}...");



                var payloadBytes = Encoding.UTF8.GetBytes("{\"received\":true}");

                // Forward to UDP
                await SendMqttMessageToUdp(
                    topic,
                    payloadBytes,
                    0,
                    false
                );
            }
            catch (JsonException ex)
            {
                Console.WriteLine($"Invalid JSON payload from {remoteEndPoint}: {ex.Message}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error processing UDP payload: {ex.Message}");
            }
        }

        public async Task SendMqttMessageToUdp(string topic, byte[] payload, int qos, bool retain)
        {
            try
            {
                if (_udpSender == null)
                {
                    Console.WriteLine("UDP sender not initialized.");
                    return;
                }

                // Create JSON wrapper for the MQTT message
                //var jsonMessage = new JObject
                //{
                //    ["topic"] = topic,
                //    ["payload"] = Encoding.UTF8.GetString(payload),
                //    ["qos"] = qos,
                //    ["retain"] = retain,
                //    ["timestamp"] = DateTime.UtcNow.ToString("O")
                //};
                // var payloadString = Encoding.UTF8.GetString(payload),

                // var jsonString = jsonMessage.ToString(Formatting.None);
                // var udpPayload = Encoding.UTF8.GetBytes(jsonString);

                await _udpSender.SendAsync(payload, payload.Length, _udpSendHost, _udpSendPort);
                Console.WriteLine($"Forwarded to UDP {_udpSendHost}:{_udpSendPort} - Topic: {topic}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error sending MQTT message to UDP: {ex.Message}");
            }
        }
    }
}
