using DockerTokenAuthentication.Config;
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
using DockerTokenAuthentication.Extensions;
using System.Text.Json.Serialization;
using System.Text.Json;
using System.Security.Claims;

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
			var requestId = Guid.NewGuid().ToString("D");

			bool isForm = false;
			if (context.Request.Method == HttpMethods.Post && context.Request.HasFormContentType) {
				_logger.LogInformation($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [{requestId}] Request: {context.Request.Method} {requestUri.OriginalString} Form: {string.Join("|", context.Request.Form.Keys)}");
				isForm = true;
			}
			else {
				_logger.LogInformation($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [{requestId}] Request: {context.Request.Method} {requestUri.OriginalString}");
			}

			if (isForm) {
				// https://docs.docker.com/registry/spec/auth/oauth/

				var service = context.Request.Form["service"].OneOrDefault();
				var scope = context.Request.Form["scope"].OneOrDefault();
				var accessType = context.Request.Form["access_type"].OneOrDefault();
				var includeRefreshToken = string.Equals("offline", accessType, StringComparison.Ordinal);
				if (!string.IsNullOrEmpty(service)) {
					if (string.Equals("refresh_token", context.Request.Form["grant_type"], StringComparison.Ordinal)) {
						var refreshToken = context.Request.Form["refresh_token"].OneOrDefault();
						if (!string.IsNullOrEmpty(refreshToken)) {

							//var ecdsa = ECDsa.Create();
							//ecdsa.ImportPkcs8PrivateKey(_settings.TokenAuthentication.EccKey, out _);

							//var parameters = new TokenValidationParameters {
							//	LifetimeValidator = (before, expires, token, parameters) => expires > DateTime.UtcNow,
							//	ValidateAudience = false,
							//	ValidateIssuer = false,
							//	ValidateActor = false,
							//	ValidateLifetime = true,
							//	IssuerSigningKey = new ECDsaSecurityKey(ecdsa)
							//};

							//var handler = new JwtSecurityTokenHandler();
							//var identity = handler.ValidateToken(refreshToken, parameters, out var token);

							var tokenParts = refreshToken.Split('.');
							if (tokenParts.Length == 3) {
								var header = CommonUtility.Base64UrlDecode(tokenParts[0]);
								var body = CommonUtility.Base64UrlDecode(tokenParts[1]);
								var signature = CommonUtility.Base64UrlDecode(tokenParts[2]);
								var headerObject = JsonSerializer.Deserialize<JwtHeader>(header);
								if (headerObject == null || headerObject.Algorithm?.StartsWith("ES", StringComparison.Ordinal) != true || !string.Equals("JWT", headerObject.TokenType)) {
									_logger.LogInformation($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [{requestId}] Invalid token received");
								}
								else {
									var toVerify = Encoding.UTF8.GetBytes(tokenParts[0] + "." + tokenParts[1]);
									bool valid = false;
									using (var ecdsa = ECDsa.Create()) {
										ecdsa.ImportPkcs8PrivateKey(_settings.TokenAuthentication.EccKey, out _);
										if (headerObject.Algorithm == "ES256") {
											valid = ecdsa.VerifyData(toVerify, signature, HashAlgorithmName.SHA256);
										}
										else if (headerObject.Algorithm == "ES384") {
											valid = ecdsa.VerifyData(toVerify, signature, HashAlgorithmName.SHA384);
										}
										else if (headerObject.Algorithm == "ES512") {
											valid = ecdsa.VerifyData(toVerify, signature, HashAlgorithmName.SHA512);
										}
									}
									if (!valid) {
										_logger.LogInformation($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [{requestId}] Invalid token received");
									}
									else {
										var tokenInfo = ReadTokenBody(body);
										var username = tokenInfo.claims.OneOrDefault(z => z.Type == ClaimsIdentity.DefaultNameClaimType);
										if (username != null) {
											var account = _settings.TokenAuthentication.Accounts.FirstOrDefault(z
												=> string.Equals(z.Registry, service, StringComparison.OrdinalIgnoreCase) &&
												string.Equals(z.Username, username.Value, StringComparison.OrdinalIgnoreCase));
											if (account != null) {
												await IssueToken(context, requestId, account, scope.Split(' ').ToList(), includeRefreshToken, refreshToken, true);
												return;
											}
										}
									}
								}
							}
						}
					}
					else if (string.Equals("password", context.Request.Form["grant_type"], StringComparison.Ordinal)) {
						var username = context.Request.Form["username"].OneOrDefault();
						var password = context.Request.Form["password"].OneOrDefault();

						var account = _settings.TokenAuthentication.Accounts.FirstOrDefault(z
								=> string.Equals(z.Registry, service, StringComparison.OrdinalIgnoreCase) &&
								string.Equals(z.Username, username, StringComparison.OrdinalIgnoreCase) &&
								string.Equals(z.Password, password, StringComparison.Ordinal));
						if (account != null) {
							await IssueToken(context, requestId, account, scope.Split(' ').ToList(), includeRefreshToken, null, true);
							return;
						}
						else {
							_logger.LogInformation($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [{requestId}] Invalid credentials received");
						}
					}
				}
			}
			else {
				// https://docs.docker.com/registry/spec/auth/token/

				string authorization = context.Request.Headers["Authorization"];
				string service = context.Request.Query["service"];
				string offline_token = context.Request.Query["offline_token"];
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
							var includeRefreshToken = string.Equals("true", offline_token, StringComparison.Ordinal);
							await IssueToken(context, requestId, account, context.Request.Query["scope"].ToList(), includeRefreshToken, null, false);
							return;
						}
						else {
							_logger.LogInformation($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [{requestId}] Invalid credentials received");
						}
					}
				}
			}

			context.Response.StatusCode = 401;
			context.Response.Headers["WWW-Authenticate"] = "Basic realm=\"Docker token authentication\", charset=\"UTF-8\"";
			_logger.LogInformation($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [{requestId}] Request authorization required");
			return;
			//await _nextMiddleware(context);
		}

		private (string identity, List<Claim> claims, string issuer, DateTime validFrom, DateTime validTo, List<string> audiences) ReadTokenBody(byte[] body) {

			string issuer = null;
			string identity = null;
			long issuedAt = 0;
			long validFrom = 0;
			long validTo = 0;
			var audiences = new List<string>();
			var claims = new List<Claim>();

			var reader = new Utf8JsonReader(body, isFinalBlock: true, state: default);
			AssertRead(ref reader);
			AssertTokenType(ref reader, JsonTokenType.StartObject);

			do {
				AssertRead(ref reader);
				if (reader.TokenType == JsonTokenType.EndObject) {
					break;
				}

				AssertTokenType(ref reader, JsonTokenType.PropertyName);
				string property = reader.GetString();

				int colonIndex = property.IndexOf(':');
				if (colonIndex >= 0) {
					foreach (var claimValue in ReadStringOrArrayOfString(ref reader)) {
						claims.Add(new Claim(property, claimValue));
					}
				}
				else if (string.Equals("unique_name", property, StringComparison.Ordinal)) {
					AssertRead(ref reader);
					AssertTokenType(ref reader, JsonTokenType.String);
					identity = reader.GetString();
				}
				else if (string.Equals("iss", property, StringComparison.Ordinal)) {
					AssertRead(ref reader);
					AssertTokenType(ref reader, JsonTokenType.String);
					issuer = reader.GetString();
				}
				else if (string.Equals("iat", property, StringComparison.Ordinal)) {
					AssertRead(ref reader);
					AssertTokenType(ref reader, JsonTokenType.Number);
					issuedAt = reader.GetInt64();
				}
				else if (string.Equals("exp", property, StringComparison.Ordinal)) {
					AssertRead(ref reader);
					AssertTokenType(ref reader, JsonTokenType.Number);
					validTo = reader.GetInt64();
				}
				else if (string.Equals("nbf", property, StringComparison.Ordinal)) {
					AssertRead(ref reader);
					AssertTokenType(ref reader, JsonTokenType.Number);
					validFrom = reader.GetInt64();
				}
				else if (string.Equals("aud", property, StringComparison.Ordinal)) {
					foreach (var audience in ReadStringOrArrayOfString(ref reader)) {
						audiences.Add(audience);
					}
				}
				else if (string.Equals("sub", property, StringComparison.Ordinal)) {
					AssertRead(ref reader);
					AssertTokenType(ref reader, JsonTokenType.String);
					claims.Add(new Claim(ClaimsIdentity.DefaultNameClaimType, reader.GetString()));
				}
				else if (string.Equals("jti", property, StringComparison.Ordinal)) {
					AssertRead(ref reader);
					AssertTokenType(ref reader, JsonTokenType.String);
					claims.Add(new Claim("jti", reader.GetString()));
				}
				else if (string.Equals("role", property, StringComparison.Ordinal)) {
					foreach (var role in ReadStringOrArrayOfString(ref reader)) {
						claims.Add(new Claim(ClaimsIdentity.DefaultRoleClaimType, role));
					}
				}
				else if (string.Equals("upn", property, StringComparison.Ordinal)) {
					foreach (string upn in ReadStringOrArrayOfString(ref reader)) {
						claims.Add(new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn", upn));
					}
				}
				else {
					ThrowUnknownProperty(property);
				}
			}
			while (true);

			return (identity, claims, issuer, CommonUtility.GetDateTimeFromTimestamp(validFrom), CommonUtility.GetDateTimeFromTimestamp(validTo), audiences);
		}

		private static void ThrowUnknownProperty(string property) {
			throw new Exception($"Unexpected property '{property}'.");
		}

		private static void AssertTokenType(ref Utf8JsonReader reader, JsonTokenType tokenType) {
			if (reader.TokenType != tokenType) {
				throw new Exception($"Expected '{tokenType}', actual '{reader.TokenType}'.");
			}
		}

		private static void AssertRead(ref Utf8JsonReader reader) {
			bool read = reader.Read();
			if (!read) {
				throw new Exception("Expected more json data.");
			}
		}

		private static List<string> ReadStringOrArrayOfString(ref Utf8JsonReader reader) {
			AssertRead(ref reader);
			if (reader.TokenType == JsonTokenType.StartArray) {
				var result = new List<string>();
				do {
					AssertRead(ref reader);
					if (reader.TokenType == JsonTokenType.EndArray) {
						return result;
					}
					AssertTokenType(ref reader, JsonTokenType.String);
					result.Add(reader.GetString());
				}
				while (true);
			}
			else if (reader.TokenType == JsonTokenType.String) {
				return new List<string>() { reader.GetString() };
			}
			else {
				throw new Exception($"Unexpected token '{reader.TokenType}'.");
			}
		}

		private async Task IssueToken(HttpContext context, string requestId, IRegistryAccount account, List<string> scopes, bool includeRefreshToken, string currentRefreshToken, bool isOauth) {
			_logger.LogInformation($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [{requestId}] Account '{account.Username}'.");

			context.Response.StatusCode = 200;
			context.Response.ContentType = "application/json";

			var requests = new Dictionary<string, AccessRequest>(StringComparer.Ordinal);
			foreach (var scope in scopes) {
				if (scope != null && scope.StartsWith("repository:", StringComparison.Ordinal)) {
					var x = scope.LastIndexOf(':');
					if (x > 0) {
						var type = "repository";
						var name = scope.Substring(11, x - 11);
						var requestedAccess = scope.Substring(x + 1).Split(',');

						if (requests.TryGetValue(type + name, out var request)) {
							request.RequestedAccess.AddRange(requestedAccess);
						}
						else {
							request = new AccessRequest() {
								Type = type,
								Name = name,
								Access = account.RepositoryAccess
							};
							request.RequestedAccess.AddRange(requestedAccess);
							requests.Add(type + name, request);
						}
					}
				}
				else if (scope != null && scope.StartsWith("registry:", StringComparison.Ordinal)) {
					var x = scope.LastIndexOf(':');
					if (x > 0) {
						var type = "registry";
						var name = scope.Substring(9, x - 9);
						var requestedAccess = scope.Substring(x + 1).Split(',');

						if (requests.TryGetValue(type + name, out var request)) {
							request.RequestedAccess.AddRange(requestedAccess);
						}
						else {
							request = new AccessRequest() {
								Type = type,
								Name = name,
								Access = account.RegistryAccess
							};
							request.RequestedAccess.AddRange(requestedAccess);
							requests.Add(type + name, request);
						}
					}
				}
			}

			//var ecdsa = ECDsa.Create();
			//ecdsa.ImportPkcs8PrivateKey(_settings.TokenAuthentication.EccKey, out _);

			//List<Claim> claims = new List<Claim>();
			//claims.Add(new Claim(ClaimTypes.Name, account.Username));
			//var tokenCredentials = new SigningCredentials(new ECDsaSecurityKey(ecdsa), "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", "http://www.w3.org/2001/04/xmlenc#sha256");
			//var securityToken = new JwtSecurityToken(_settings.TokenAuthentication.Issuer, account.Registry, claims, expires: DateTime.UtcNow.AddMinutes(5), signingCredentials: tokenCredentials);
			//var jwt = new JwtSecurityTokenHandler().WriteToken(securityToken);

			var token = CreateToken(requestId, account, includeRefreshToken && currentRefreshToken == null, requests.Values);
			var refreshToken = token.refreshToken == null ? (includeRefreshToken && currentRefreshToken != null ? $",\"refresh_token\":\"{currentRefreshToken}\"" : string.Empty) : $",\"refresh_token\":\"{token.refreshToken}\"";
			var tokenName = isOauth ? "access_token" : "token";
			var scopeResult = isOauth ? $",\"scope\":\"{JavaScriptEncoder.UnsafeRelaxedJsonEscaping.Encode(token.scope)}\"" : string.Empty;
			var issuedAt = isOauth ? string.Empty : $",\"issued_at\":\"{token.iat}\"";
			await context.Response.WriteAsync($"{{\"{tokenName}\":\"{token.token}\",\"expires_in\":{token.ttl}{issuedAt}{refreshToken}{scopeResult}}}");
		}

		private (string token, int ttl, string iat, string refreshToken, string scope) CreateToken(string requestId, IRegistryAccount account, bool offlineToken, ICollection<AccessRequest> accessRequests) {
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

			int ttl = 300;
			string header = "{\"typ\":\"JWT\",\"alg\":\"ES256\",\"kid\":\"" + kid + "\"}";
			string claimset = "{";
			claimset += $"\"iss\":\"{JavaScriptEncoder.UnsafeRelaxedJsonEscaping.Encode(_settings.TokenAuthentication.Issuer)}\",";
			claimset += $"\"sub\":\"{account.Username}\",";
			claimset += $"\"aud\":\"{JavaScriptEncoder.UnsafeRelaxedJsonEscaping.Encode(account.Registry)}\",";
			claimset += $"\"exp\":{CommonUtility.GetTimestamp(now.AddSeconds(ttl))},";
			claimset += $"\"nbf\":{CommonUtility.GetTimestamp(now)},";
			claimset += $"\"iat\":{CommonUtility.GetTimestamp(now)},";
			claimset += $"\"jti\":\"{Guid.NewGuid():N}\"";
			if (accessRequests.Count > 0) {
				claimset += ",\"access\":[";
			}
			string scopeResult = "";
			bool firstRequest = true;
			foreach (var request in accessRequests) {
				if (firstRequest) {
					firstRequest = false;
				}
				else {
					claimset += ",";
				}
				claimset += "{";
				claimset += $"\"type\":\"{request.Type}\",";
				claimset += $"\"name\":\"{JavaScriptEncoder.UnsafeRelaxedJsonEscaping.Encode(request.Name)}\",";
				claimset += "\"actions\":[";
				if (request.Access != null) {
					if (request.Access.ScopedAccess == null || !request.Access.ScopedAccess.TryGetValue(request.Name, out var accountAccess)) {
						accountAccess = request.Access.Access;
					}
					if (accountAccess != null) {
						bool first = true;
						List<string> grantedAccess = new List<string>();
						foreach (var accessToken in request.RequestedAccess) {
							if (accountAccess.Contains(accessToken)) {
								if (first) { first = false; }
								else { claimset += ','; }
								claimset += $"\"{JavaScriptEncoder.UnsafeRelaxedJsonEscaping.Encode(accessToken)}\"";
								_logger.LogInformation($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [{requestId}] Granting access '{accessToken}' for '{request.Name}' (type '{request.Type}').");
								grantedAccess.Add(accessToken);
							}
							else {
								_logger.LogInformation($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [{requestId}] Requested access '{accessToken}' for '{request.Name}' (type '{request.Type}') is denied.");
							}
						}
						if (scopeResult.Length > 0) {
							scopeResult += " ";
						}
						if (grantedAccess.Count > 0) {
							scopeResult += $"{request.Type}:{request.Name}:{string.Join(",", grantedAccess)}";
						}
					}
				}
				claimset += "]}";
			}
			if (accessRequests.Count > 0) {
				claimset += "]";
			}
			claimset += "}";

			string headerData = Base64UrlEncode(Encoding.UTF8.GetBytes(header));
			string payloadData = Base64UrlEncode(Encoding.UTF8.GetBytes(claimset));
			string signInput = string.Concat(headerData, '.', payloadData);
			byte[] signBytes = Encoding.UTF8.GetBytes(signInput);

			byte[] signed = SignData(signBytes);
			string signedB64 = Base64UrlEncode(signed);
			string tokenValue = signInput + '.' + signedB64;

			string offlineTokenValue = null;
			if (offlineToken) {
				header = "{\"typ\":\"JWT\",\"alg\":\"ES256\",\"kid\":\"" + kid + "\"}";
				claimset = "{";
				claimset += $"\"iss\":\"{JavaScriptEncoder.UnsafeRelaxedJsonEscaping.Encode(_settings.TokenAuthentication.Issuer)}\",";
				claimset += $"\"sub\":\"{account.Username}\",";
				claimset += $"\"aud\":\"{JavaScriptEncoder.UnsafeRelaxedJsonEscaping.Encode(account.Registry)}\",";
				claimset += $"\"exp\":{CommonUtility.GetTimestamp(now.AddMonths(1))},";
				claimset += $"\"nbf\":{CommonUtility.GetTimestamp(now)},";
				claimset += $"\"iat\":{CommonUtility.GetTimestamp(now)},";
				claimset += $"\"jti\":\"{Guid.NewGuid():N}\"";
				claimset += "}";

				headerData = Base64UrlEncode(Encoding.UTF8.GetBytes(header));
				payloadData = Base64UrlEncode(Encoding.UTF8.GetBytes(claimset));
				signInput = string.Concat(headerData, '.', payloadData);
				signBytes = Encoding.UTF8.GetBytes(signInput);

				signed = SignData(signBytes);
				signedB64 = Base64UrlEncode(signed);
				offlineTokenValue = signInput + '.' + signedB64;
			}

			return (tokenValue, ttl, now.ToString("yyyy-MM-ddTHH:mm:ss.FFFFFFFK"), offlineTokenValue, scopeResult);
		}

		public byte[] SignData(byte[] input) {
			using (var ecdsa = ECDsa.Create()) {
				ecdsa.ImportPkcs8PrivateKey(_settings.TokenAuthentication.EccKey, out _);
				return ecdsa.SignData(input, HashAlgorithmName.SHA256);
			}
		}

		private static string Base64UrlEncode(byte[] arg) {
			string s = Convert.ToBase64String(arg); // regular base64 encoder
			s = s.Split('=')[0]; // remove any trailing '='s
			s = s.Replace('+', '-'); // 62nd char of encoding
			s = s.Replace('/', '_'); // 63rd char of encoding
			return s;
		}

		private sealed class AccessRequest {
			public string Type { get; set; }
			public string Name { get; set; }
			public IRegistryAccess Access { get; set; }
			public HashSet<string> RequestedAccess { get; } = new HashSet<string>(StringComparer.Ordinal);
		}

		private sealed class JwtHeader {
			[JsonPropertyName("alg")]
			public string Algorithm { get; set; }

			[JsonPropertyName("typ")]
			public string TokenType { get; set; }
		}
	}
}
