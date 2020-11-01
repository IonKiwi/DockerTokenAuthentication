using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace DockerTokenAuthentication.Config {
	public interface IRegistryAccess {
		IReadOnlyList<string> Access { get; }
		IReadOnlyDictionary<string, IReadOnlyList<string>> ScopedAccess { get; }
	}

	public class RegistryAccess : IRegistryAccess {

		private IReadOnlyDictionary<string, IReadOnlyList<string>> _scopedAccessValue;

		[JsonPropertyName("access")]
		public List<string> Access { get; set; }

		[JsonPropertyName("scopedAccess")]
		public Dictionary<string, List<string>> ScopedAccess { get; set; }

		public void Init() {
			if (ScopedAccess != null) {
				var scopedAccessValue = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal);
				foreach (var kv in ScopedAccess) {
					scopedAccessValue.Add(kv.Key, kv.Value);
				}
				_scopedAccessValue = scopedAccessValue;
			}
		}

		IReadOnlyList<string> IRegistryAccess.Access => Access;
		IReadOnlyDictionary<string, IReadOnlyList<string>> IRegistryAccess.ScopedAccess => _scopedAccessValue;
	}
}
