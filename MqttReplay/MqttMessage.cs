using System;
namespace MqttReplay
{
	public class MqttMessage
    {
		public string? type;
		public string? timestamp;
		public string? raw_packet;
		public string? client_id;
		public string? username;
		public bool clean_session;
		public int keep_alive;

		public string? topic;
		public string? payload;
		public string? payload_text;
		public int qos;
		public bool retain;
    }
}

