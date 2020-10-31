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
		public string ServerCertificateProvider { get; set; }

		public string ServerCertificate { get; set; }

		public string ServerCertificatePasswordProvider { get; set; }

		public string ServerCertificatePassword { get; set; }

		public void Init() {

		}
	}
}
