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

		public static IHostBuilder CreateHostBuilder(string[] args) =>
				Host.CreateDefaultBuilder(args)
						.ConfigureWebHostDefaults(webBuilder => {
							webBuilder.ConfigureAppConfiguration((hostingContext, config) => {
								HostingEnvironment = hostingContext.HostingEnvironment;
							});
							webBuilder.UseStartup<Startup>();
							webBuilder.ConfigureServices((context, services) => {
								services.Configure<KestrelServerOptions>(options => {
									var farmSettings = options.ApplicationServices.GetService<IFarmSettings>();
									var serverBindings = farmSettings.ServerBindings;
									if (serverBindings != null) {
										foreach (var kv in serverBindings) {
											var certificate = GetServerCertificate(kv.Config);
											if (certificate == null) {
												// http binding
												options.ListenAnyIP(kv.Port, listenOptions => {
													listenOptions.Protocols = HttpProtocols.Http1;
												});
											}
											else {
												// https binding
												var isWindows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
												options.ListenAnyIP(kv.Port, listenOptions => {
													listenOptions.Protocols = HttpProtocols.Http1AndHttp2;
													listenOptions.UseHttps(certificate, options => {
														if (isWindows) {
															options.SslProtocols = SslProtocols.Tls12;
														}
														else {
															options.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
														}
														//options.OnAuthenticate = (context, sslOptions) => {
														//	sslOptions.CipherSuitesPolicy = new CipherSuitesPolicy(new[] {
														//		TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
														//		TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
														//		TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
														//		TlsCipherSuite.TLS_AES_128_GCM_SHA256,
														//		TlsCipherSuite.TLS_AES_256_GCM_SHA384,
														//		TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256,
														//	});
														//};
													});
												});
											}
										}
									}
								});
							});
						});
	}
}
