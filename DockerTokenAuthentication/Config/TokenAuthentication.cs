using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace DockerTokenAuthentication.Config {
	public interface ITokenAuthentication {
		byte[] EccKey { get; }
		string Issuer { get; }
		IReadOnlyList<IRegistryAccount> Accounts { get; }
	}

	public class TokenAuthentication : ITokenAuthentication {
		[JsonPropertyName("eccKey")]
		public byte[] EccKey { get; set; }

		[JsonPropertyName("issuer")]
		public string Issuer { get; set; }

		[JsonPropertyName("accounts")]
		public List<RegistryAccount> Accounts { get; set; }

		public void Init() {
			if (Accounts != null) {
				foreach (var account in Accounts) {
					account.Init();
				}
			}
		}

		IReadOnlyList<IRegistryAccount> ITokenAuthentication.Accounts => Accounts;
	}
}
