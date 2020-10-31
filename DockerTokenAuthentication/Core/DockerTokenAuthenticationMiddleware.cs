﻿using DockerTokenAuthentication.Config;
using DockerTokenAuthentication.Utilities;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading;
using System.Threading.Tasks;

namespace DockerTokenAuthentication.Core {
	public class DockerTokenAuthenticationMiddleware {
		private readonly RequestDelegate _nextMiddleware;
		private readonly IFarmSettings _settings;
		private readonly ILogger _logger;

		public DockerTokenAuthenticationMiddleware(RequestDelegate nextMiddleware, IFarmSettings settings, ILoggerFactory logger) {
			_nextMiddleware = nextMiddleware;
			_settings = settings;
			_logger = logger.CreateLogger<DockerTokenAuthenticationMiddleware>();
		}

		public async Task Invoke(HttpContext context) {

			var requestUri = new Uri($"{context.Request.Scheme}://{context.Request.Host}{context.Request.Path}{context.Request.QueryString}");
			_logger.LogWarning("Request: " + requestUri.OriginalString);

			string authorization = context.Request.Headers["Authorization"];
			string service = context.Request.Query["service"];
			string scope = context.Request.Query["scope"];
			if (authorization != null && authorization.StartsWith("Basic ", StringComparison.Ordinal) && !string.IsNullOrEmpty(service)) {
				var credentials = Encoding.UTF8.GetString(Convert.FromBase64String(authorization.Substring(6)));
				int x = credentials.IndexOf(':');
				if (x > 0) {
					string user = credentials.Substring(0, x);
					string password = credentials.Substring(x + 1);
					var account = _settings.TokenAuthentication.Accounts.FirstOrDefault(z
						=> string.Equals(z.Registry, service, StringComparison.OrdinalIgnoreCase) &&
						string.Equals(z.Username, user, StringComparison.OrdinalIgnoreCase) &&
						string.Equals(z.Password, password, StringComparison.Ordinal));
					if (account != null) {
						context.Response.StatusCode = 200;
						context.Response.ContentType = "application/json";

						string type = null;
						string name = null;
						string[] access = null;
						if (scope != null && scope.StartsWith("repository:", StringComparison.Ordinal)) {
							x = scope.LastIndexOf(':');
							if (x > 0) {
								type = "repository";
								name = scope.Substring(11, x - 11);
								access = scope.Substring(x + 1).Split(',');
							}
						}
						else if (scope != null && scope.StartsWith("registry:", StringComparison.Ordinal)) {
							x = scope.LastIndexOf(':');
							if (x > 0) {
								type = "registry";
								name = scope.Substring(9, x - 9);
								access = scope.Substring(x + 1).Split(',');
							}
						}

						await context.Response.WriteAsync($"{{\"token\":\"{CreateToken(account, type, name, access)}\"}}");
						return;
					}
				}
			}

			context.Response.StatusCode = 401;
			context.Response.Headers["WWW-Authenticate"] = "Basic realm=\"Docker token authentication\", charset=\"UTF-8\"";
			return;
			//await _nextMiddleware(context);
		}

		private string CreateToken(IRegistryAccount account, string type, string name, string[] requestedAccess) {

			string kid;
			using (var ecdsa = ECDsa.Create()) {
				ecdsa.ImportPkcs8PrivateKey(_settings.TokenAuthentication.EccKey, out _);
				var derEncoded = ecdsa.ExportSubjectPublicKeyInfo();
				byte[] hash;
				using (var sha256 = SHA256.Create()) {
					hash = sha256.ComputeHash(derEncoded);
				}
				var base32 = Base32Encoding.ToString(hash.Take(30).ToArray()).TrimEnd('=');
				StringBuilder sb = new StringBuilder();
				int i = 0;
				for (i = 0; i < base32.Length / 4 - 1; i++) {
					sb.Append(base32, i * 4, 4);
					sb.Append(':');
				}
				sb.Append(base32, i * 4, 4);
				kid = sb.ToString();
			}

			DateTime now = DateTime.UtcNow;

			string header = "{\"typ\":\"JWT\",\"alg\":\"ES256\",\"kid\":\"" + kid + "\"}";
			string claimset = "{";
			claimset += $"\"iss\":\"{JavaScriptEncoder.UnsafeRelaxedJsonEscaping.Encode(_settings.TokenAuthentication.Issuer)}\",";
			claimset += $"\"sub\":\"{account.Username}\",";
			claimset += $"\"aud\":\"{JavaScriptEncoder.UnsafeRelaxedJsonEscaping.Encode(account.Registry)}\",";
			claimset += $"\"exp\":{CommonUtility.GetTimestamp(now.AddHours(24))},";
			claimset += $"\"nbf\":{CommonUtility.GetTimestamp(now)},";
			claimset += $"\"iat\":{CommonUtility.GetTimestamp(now)},";
			claimset += $"\"jti\":\"{Guid.NewGuid().ToString("N")}\"";
			if (requestedAccess != null && requestedAccess.Length > 0) {
				claimset += ",\"access\":[{";
				claimset += $"\"type\":\"{type}\",";
				claimset += $"\"name\":\"{JavaScriptEncoder.UnsafeRelaxedJsonEscaping.Encode(name)}\",";
				claimset += "\"actions\":[";
				bool first = true;
				foreach (var access in requestedAccess) {
					if (account.Access.Contains(access)) {
						if (first) { first = false; }
						else { claimset += ','; }
						claimset += $"\"{JavaScriptEncoder.UnsafeRelaxedJsonEscaping.Encode(access)}\"";
					}
				}
				claimset += "]}]";
			}
			claimset += "}";

			string headerData = Base64UrlEncode(Encoding.UTF8.GetBytes(header));
			string payloadData = Base64UrlEncode(Encoding.UTF8.GetBytes(claimset));
			string signInput = string.Concat(headerData, '.', payloadData);
			byte[] signBytes = Encoding.UTF8.GetBytes(signInput);

			byte[] signed = SignData(signBytes);
			string signedB64 = Base64UrlEncode(signed);

			return signInput + '.' + signedB64;
		}

		public byte[] SignData(byte[] input) {
			using (var ecdsa = ECDsa.Create()) {
				ecdsa.ImportPkcs8PrivateKey(_settings.TokenAuthentication.EccKey, out _);
				return ecdsa.SignData(input, HashAlgorithmName.SHA256);
			}
		}

		private static string Base64UrlEncode(byte[] arg) {
			string s = Convert.ToBase64String(arg); // Regular base64 encoder
			s = s.Split('=')[0]; // Remove any trailing '='s
			s = s.Replace('+', '-'); // 62nd char of encoding
			s = s.Replace('/', '_'); // 63rd char of encoding
			return s;
		}
	}
}