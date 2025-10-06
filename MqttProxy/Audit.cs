using System;
namespace MqttProxy
{
	public class Audit
	{
		public string clientId { get; set; } = "";
		public DateTime when { get; } = DateTime.Now;
		public bool unusual { get; set; } = false;
		public string message { get; set; } = "";
	}
}

