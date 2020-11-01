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

	public class ServerCertificateSettings : IServerCertificateSettings {
		[JsonPropertyName("serverCertificateProvider")]
		public string ServerCertificateProvider { get; set; }

		[JsonPropertyName("serverCertificate")]
		public string ServerCertificate { get; set; }

		[JsonPropertyName("serverCertificatePasswordProvider")]
		public string ServerCertificatePasswordProvider { get; set; }

		[JsonPropertyName("serverCertificatePassword")]
		public string ServerCertificatePassword { get; set; }

		public void Init() {

		}
	}
}
