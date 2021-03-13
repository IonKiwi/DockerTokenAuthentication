using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using DockerTokenAuthentication.Config;
using DockerTokenAuthentication.PlatformSpecific;
using DockerTokenAuthentication.Utilities;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Net.Security;

namespace DockerTokenAuthentication {
	public class Program {
		public static void Main(string[] args) {
			CreateHostBuilder(args).Build().Run();
		}

		public static IWebHostEnvironment HostingEnvironment { get; private set; }

		internal enum ServerCertificateProviderType {
			Blob,
			File,
			WindowsStore,
		}

		internal enum ServerCertificatePasswordProviderType {
			None,
			Plain,
		}

		private static (X509Certificate2 server, Dictionary<string, X509Certificate2> serverNames) GetEndpointConfiguration(IEndpointConfiguration endpointConfiguration) {
			var server = GetServerCertificate(endpointConfiguration);
			var serverNames = new Dictionary<string, X509Certificate2>(StringComparer.OrdinalIgnoreCase);
			if (endpointConfiguration?.ServerName != null) {
				foreach (var kv in endpointConfiguration.ServerName) {
					serverNames.Add(kv.Key, GetServerCertificate(kv.Value));
				}
			}
			return (server, serverNames);
		}

		private static X509Certificate2 GetServerCertificate(IServerCertificateSettings serverCertificateSettings) {
			if (serverCertificateSettings == null || string.IsNullOrEmpty(serverCertificateSettings.ServerCertificateProvider)) {
				return null;
			}

			if (!CommonUtility.TryParseEnum<ServerCertificateProviderType>(serverCertificateSettings.ServerCertificateProvider, true, out var serverCertificateProvider)) {
				throw new ApplicationException($"Unsupported ServerCertificateProvider in config: {serverCertificateSettings.ServerCertificateProvider}");
			}

			var serverCertificatePasswordProvider = ServerCertificatePasswordProviderType.None;
			if (!string.IsNullOrEmpty(serverCertificateSettings.ServerCertificatePasswordProvider) && !CommonUtility.TryParseEnum(serverCertificateSettings.ServerCertificatePasswordProvider, true, out serverCertificatePasswordProvider)) {
				throw new ApplicationException($"Unsupported ServerCertificatePasswordProvider in config: {serverCertificateSettings.ServerCertificatePasswordProvider}");
			}

			string password = null;
			if (serverCertificatePasswordProvider == ServerCertificatePasswordProviderType.Plain) {
				password = serverCertificateSettings.ServerCertificatePassword;
			}

			X509Certificate2 certificate = null;
			if (serverCertificateProvider == ServerCertificateProviderType.Blob) {
				byte[] certificateData = Convert.FromBase64String(serverCertificateSettings.ServerCertificate);
				certificate = new X509Certificate2(certificateData, password, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.EphemeralKeySet);
			}
			else if (serverCertificateProvider == ServerCertificateProviderType.File) {
				certificate = new X509Certificate2(serverCertificateSettings.ServerCertificate, password, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.EphemeralKeySet);
			}
			else if (serverCertificateProvider == ServerCertificateProviderType.WindowsStore && RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) {
				certificate = WindowsCertificateHelper.GetCertificate(StoreName.My, StoreLocation.LocalMachine, serverCertificateSettings.ServerCertificate, DateTime.UtcNow, true, false, out var status);
				if (certificate == null || status != CertificateRetrievalStatus.None) {
					throw new Exception("Certificate '" + serverCertificateSettings.ServerCertificate + "' not found/valid. status: " + status.ToString());
				}
			}
			return certificate;
		}

		// from: https://raw.githubusercontent.com/dotnet/aspnetcore/master/src/Servers/Kestrel/Core/src/CertificateLoader.cs
		// Copyright (c) .NET Foundation. All rights reserved.
		// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.
		private const string ServerAuthenticationOid = "1.3.6.1.5.5.7.3.1";
		private static bool IsCertificateAllowedForServerAuth(X509Certificate2 certificate) {
			/* If the Extended Key Usage extension is included, then we check that the serverAuth usage is included. (http://oid-info.com/get/1.3.6.1.5.5.7.3.1)
			 * If the Extended Key Usage extension is not included, then we assume the certificate is allowed for all usages.
			 *
			 * See also https://blogs.msdn.microsoft.com/kaushal/2012/02/17/client-certificates-vs-server-certificates/
			 *
			 * From https://tools.ietf.org/html/rfc3280#section-4.2.1.13 "Certificate Extensions: Extended Key Usage"
			 *
			 * If the (Extended Key Usage) extension is present, then the certificate MUST only be used
			 * for one of the purposes indicated.  If multiple purposes are
			 * indicated the application need not recognize all purposes indicated,
			 * as long as the intended purpose is present.  Certificate using
			 * applications MAY require that a particular purpose be indicated in
			 * order for the certificate to be acceptable to that application.
			 */

			var hasEkuExtension = false;

			foreach (var extension in certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>()) {
				hasEkuExtension = true;
				foreach (var oid in extension.EnhancedKeyUsages) {
					if (string.Equals(oid.Value, ServerAuthenticationOid, StringComparison.Ordinal)) {
						return true;
					}
				}
			}

			return !hasEkuExtension;
		}

		// from: https://raw.githubusercontent.com/dotnet/aspnetcore/master/src/Servers/Kestrel/Core/src/Internal/SniOptionsSelector.cs
		// Copyright (c) .NET Foundation. All rights reserved.
		// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.
		private static SslServerAuthenticationOptions CreateServerOptions(X509Certificate2 server) {
			if (!IsCertificateAllowedForServerAuth(server)) {
				throw new InvalidOperationException($"Certificate {server.Subject} is not valid for server authentication");
			}

			SslProtocols sslProtocols;
			if (OperatingSystem.IsWindows()) {
				sslProtocols = SslProtocols.Tls12;
			}
			else {
				sslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
			}

			var options = new SslServerAuthenticationOptions() {
				ServerCertificate = server,
				EnabledSslProtocols = sslProtocols,
				CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
				ServerCertificateContext = SslStreamCertificateContext.Create(server, additionalCertificates: null),
				ApplicationProtocols = new List<SslApplicationProtocol>() {
					SslApplicationProtocol.Http2,
					SslApplicationProtocol.Http11
				},
				AllowRenegotiation = false,
				EncryptionPolicy = EncryptionPolicy.RequireEncryption,
				//CipherSuitesPolicy = new CipherSuitesPolicy(new[] {
				//	TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				//	TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				//	TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				//	TlsCipherSuite.TLS_AES_128_GCM_SHA256,
				//	TlsCipherSuite.TLS_AES_256_GCM_SHA384,
				//	TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256,
				//})
			};

			return options;
		}

		public static IHostBuilder CreateHostBuilder(string[] args) =>
				Host.CreateDefaultBuilder(args)
						.ConfigureWebHostDefaults(webBuilder => {
							webBuilder.ConfigureAppConfiguration((hostingContext, config) => {
								HostingEnvironment = hostingContext.HostingEnvironment;
							});
							webBuilder.UseStartup<Startup>();
							webBuilder.ConfigureServices((context, services) => {
								services.Configure<KestrelServerOptions>(options => {

									options.AddServerHeader = false;

									var logger = options.ApplicationServices.GetService<ILoggerFactory>().CreateLogger<Program>();
									var farmSettings = options.ApplicationServices.GetService<IFarmSettings>();
									var serverBindings = farmSettings.ServerBindings;
									if (serverBindings != null) {
										foreach (var kv in serverBindings) {
											var endpoint = GetEndpointConfiguration(kv.Config);
											if (endpoint.server == null) {
												// http binding
												logger.LogInformation($"HTTP {kv.Port}.");

												options.ListenAnyIP(kv.Port, listenOptions => {
													listenOptions.Protocols = HttpProtocols.Http1;
												});
											}
											else {
												// https binding
												var fallback = CreateServerOptions(endpoint.server);
												var serverNames = new Dictionary<string, SslServerAuthenticationOptions>(StringComparer.OrdinalIgnoreCase);
												foreach (var serverName in endpoint.serverNames) {
													serverNames.Add(serverName.Key, CreateServerOptions(serverName.Value));
												}

												logger.LogInformation($"HTTPS {kv.Port} with server certificate '{endpoint.server.Subject}'.");
												CommonUtility.Verify(endpoint.server, logger);

												foreach (var serverName in endpoint.serverNames) {
													logger.LogInformation($"HTTPS {kv.Port} for '{serverName.Key}' with server certificate '{serverName.Value.Subject}'.");
													CommonUtility.Verify(serverName.Value, logger);
												}

												options.ListenAnyIP(kv.Port, listenOptions => {
													listenOptions.Protocols = HttpProtocols.Http1AndHttp2;
													listenOptions.UseHttps((stream, clientHelloInfo, state, cancellationToken) => {
														if (!string.IsNullOrEmpty(clientHelloInfo.ServerName) && serverNames.TryGetValue(clientHelloInfo.ServerName, out var options)) {
															return new ValueTask<SslServerAuthenticationOptions>(options);
														}
														return new ValueTask<SslServerAuthenticationOptions>(fallback);
													}, null);
												});
											}
										}
									}
								});
							});
						});
	}
}
