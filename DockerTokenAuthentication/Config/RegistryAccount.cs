using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace DockerTokenAuthentication.Config {

	public interface IRegistryAccount {
		string Registry { get; set; }
		string Username { get; set; }
		string Password { get; set; }
		IRegistryAccess RepositoryAccess { get; }
		IRegistryAccess RegistryAccess { get; }
	}

	public class RegistryAccount : IRegistryAccount {

		[JsonPropertyName("registry")]
		public string Registry { get; set; }

		[JsonPropertyName("username")]
		public string Username { get; set; }

		[JsonPropertyName("password")]
		public string Password { get; set; }

		[JsonPropertyName("repositoryAccess")]
		public RegistryAccess RepositoryAccess { get; set; }

		[JsonPropertyName("registryAccess")]
		public RegistryAccess RegistryAccess { get; set; }

		public void Init() {
			if (RepositoryAccess != null) {
				RepositoryAccess.Init();
			}
			if (RegistryAccess != null) {
				RegistryAccess.Init();
			}
		}

		IRegistryAccess IRegistryAccount.RegistryAccess => RegistryAccess;

		IRegistryAccess IRegistryAccount.RepositoryAccess => RepositoryAccess;
	}
}
