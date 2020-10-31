using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace DockerTokenAuthentication.Config {
	public class GlobalConfig : IFarmSettings {
		[JsonPropertyName("serverBindings")]
		public List<ServerBinding> ServerBindings {
			get;
			set;
		}

		[JsonPropertyName("tokenAuthentication")]
		public TokenAuthentication TokenAuthentication {
			get;
			set;
		}

		public void Init() {
			if (ServerBindings != null) {
				foreach (var sb in ServerBindings) {
					sb.Init();
				}
			}
			if (TokenAuthentication != null) {
				TokenAuthentication.Init();
			}
		}

		IReadOnlyList<IServerBinding> IFarmSettings.ServerBindings => ServerBindings;

		ITokenAuthentication IFarmSettings.TokenAuthentication => TokenAuthentication;
	}
}
