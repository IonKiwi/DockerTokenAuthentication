using DockerTokenAuthentication.Config;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DockerTokenAuthentication.Core {
	public class DockerTokenAuthenticationMiddleware {
		private readonly RequestDelegate _nextMiddleware;
		private readonly IFarmSettings _settings;
		private readonly object _logger;

		public DockerTokenAuthenticationMiddleware(RequestDelegate nextMiddleware, IFarmSettings settings, ILoggerFactory logger) {
			_nextMiddleware = nextMiddleware;
			_settings = settings;
			_logger = logger.CreateLogger<DockerTokenAuthenticationMiddleware>();
		}

		public async Task Invoke(HttpContext context) {
			await _nextMiddleware(context);
		}
	}
}
