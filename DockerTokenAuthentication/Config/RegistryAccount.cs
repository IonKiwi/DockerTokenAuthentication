using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace DockerTokenAuthentication.Config {

	public interface IRegistryAccount {
		public string Registry { get; set; }
		public string Username { get; set; }
		public string Password { get; set; }
		public IReadOnlyList<string> Access { get; }
	}

	public class RegistryAccount : IRegistryAccount {

		[JsonPropertyName("registry")]
		public string Registry { get; set; }

		[JsonPropertyName("username")]
		public string Username { get; set; }

		[JsonPropertyName("password")]
		public string Password { get; set; }

		[JsonPropertyName("access")]
		public List<string> Roles { get; set; }

		public void Init() {

		}

		IReadOnlyList<string> IRegistryAccount.Access => Roles;
	}
}
