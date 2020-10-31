using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace DockerTokenAuthentication.Config {
	public interface IServerBinding {
		int Port { get; }
		IServerCertificateSettings Config { get; }
	}

	public class ServerBinding : IServerBinding {
		[JsonPropertyName("port")]
		public int Port { get; set; }

		[JsonPropertyName("config")]
		public ServerCertificateSettings Config { get; set; }

		public void Init() {
			if (Config != null) {
				Config.Init();
			}
		}

		IServerCertificateSettings IServerBinding.Config => Config;
	}
}
