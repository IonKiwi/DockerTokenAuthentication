using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DockerTokenAuthentication.Config {
	public interface IFarmSettings {
		IReadOnlyList<IServerBinding> ServerBindings { get; }
		ITokenAuthentication TokenAuthentication { get; }
	}
}
