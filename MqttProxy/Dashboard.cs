using System;
using System.Text;
using System.Text.Json;

namespace MqttProxy
{
	public class Dashboard
	{
		private string? url = "";
		private string? token = "";

		public Dashboard(string? url, string? token)
		{
			this.url = url + "/api/mqtt-audits";
			this.token = token;

            _httpClient = new HttpClient();
            _jsonOptions = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            };

            ConfigureHttpClient();
        }

        private readonly HttpClient _httpClient;
        private readonly JsonSerializerOptions _jsonOptions;

        private void ConfigureHttpClient()
        {
            _httpClient.DefaultRequestHeaders.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

            _httpClient.Timeout = TimeSpan.FromSeconds(30);
            _httpClient.DefaultRequestHeaders.ConnectionClose = false; // Keep connections alive
        }

        public async Task<bool> SendStatistics(List<Audit>? currentAudits)
        {
            if (currentAudits == null || currentAudits.Count == 0)
            {
                return false;
            }

            string jsonContent = JsonSerializer.Serialize(currentAudits);

            try
            {
                var content = new StringContent(jsonContent, Encoding.UTF8, "application/json");

                var response = await _httpClient.PostAsync(url, content);

                if (response.IsSuccessStatusCode)
                {
                    Console.WriteLine($"✓ Data sent successfully at {DateTime.Now:HH:mm:ss}");
                    return true;
                }
                else
                {
                    Console.WriteLine($"✗ Failed to send data: {response.StatusCode}");
                    return false;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"✗ Error sending data: {ex.Message}");
                return false;
            }
        }

        public void Dispose()
        {
            _httpClient?.Dispose();
        }
    }
}

