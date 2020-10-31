using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DockerTokenAuthentication.Config {
	public interface IFarmSettings {
		public IReadOnlyList<IServerBinding> ServerBindings { get; }
		public ITokenAuthentication TokenAuthentication { get; }
	}
}
