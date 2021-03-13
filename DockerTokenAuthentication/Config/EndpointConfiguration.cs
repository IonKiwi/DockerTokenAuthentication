using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace DockerTokenAuthentication.Config {

	public interface IServerCertificateSettings {
		string ServerCertificateProvider { get; }

		string ServerCertificate { get; }

		string ServerCertificatePasswordProvider { get; }

		string ServerCertificatePassword { get; }
	}

	public interface IEndpointConfiguration : IServerCertificateSettings {
		IReadOnlyDictionary<string, IServerCertificateSettings> ServerName { get; }
	}

	public class ServerNameConfiguration : IServerCertificateSettings {
		[JsonPropertyName("serverCertificateProvider")]
		public string ServerCertificateProvider { get; set; }

		[JsonPropertyName("serverCertificate")]
		public string ServerCertificate { get; set; }

		[JsonPropertyName("serverCertificatePasswordProvider")]
		public string ServerCertificatePasswordProvider { get; set; }

		[JsonPropertyName("serverCertificatePassword")]
		public string ServerCertificatePassword { get; set; }
	}

	public class EndpointConfiguration : IServerCertificateSettings, IEndpointConfiguration {

		private Dictionary<string, IServerCertificateSettings> _serverName;

		[JsonPropertyName("serverCertificateProvider")]
		public string ServerCertificateProvider { get; set; }

		[JsonPropertyName("serverCertificate")]
		public string ServerCertificate { get; set; }

		[JsonPropertyName("serverCertificatePasswordProvider")]
		public string ServerCertificatePasswordProvider { get; set; }

		[JsonPropertyName("serverCertificatePassword")]
		public string ServerCertificatePassword { get; set; }

		[JsonPropertyName("serverName")]
		public Dictionary<string, ServerNameConfiguration> ServerName { get; set; }

		IReadOnlyDictionary<string, IServerCertificateSettings> IEndpointConfiguration.ServerName => _serverName;

		public void Init() {
			var serverName = new Dictionary<string, IServerCertificateSettings>(StringComparer.OrdinalIgnoreCase);
			if (ServerName != null) {
				foreach (var kv in ServerName) {
					serverName.Add(kv.Key, kv.Value);
				}
			}
			_serverName = serverName;
		}
	}
}
