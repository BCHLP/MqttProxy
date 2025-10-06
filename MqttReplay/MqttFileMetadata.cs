using System;
namespace MqttReplay
{
    public class MqttFileMetadata
    {
        public int total_messages;
        public Dictionary<string, int> packet_types = new Dictionary<string, int>();
        public string[] unique_topics = new string[0] { };
        public string[] unique_clients = new string[0] { };

    }
}

