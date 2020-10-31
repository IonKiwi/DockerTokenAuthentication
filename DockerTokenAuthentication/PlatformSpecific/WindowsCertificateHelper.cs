using DockerTokenAuthentication.Utilities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace DockerTokenAuthentication.PlatformSpecific {
	public enum CertificateRetrievalStatus {
		None,
		NotFound,
		MultipleFound,
	}

	internal static class WindowsCertificateHelper {
		public static X509Certificate2 GetCertificate(StoreName name, StoreLocation location, string subjectName, DateTime? validOn, bool selectMaximumValidityOnMultipleFound, bool publicKeyOnly, out CertificateRetrievalStatus status) {
			status = CertificateRetrievalStatus.NotFound;
			if (string.IsNullOrEmpty(subjectName)) {
				return null;
			}
			var clockSkew = TimeSpan.FromMinutes(5);
			if (selectMaximumValidityOnMultipleFound && !validOn.HasValue) {
				throw new ArgumentException($"{nameof(selectMaximumValidityOnMultipleFound)} without {nameof(validOn)} specified", nameof(selectMaximumValidityOnMultipleFound));
			}

			X509Store store = new X509Store(name, location);
			X509Certificate2Collection certificates = null;
			store.Open(OpenFlags.ReadOnly);

			try {
				X509Certificate2 result = null;

				// note: X509Store.Certificates property created a new collection
				certificates = store.Certificates;

				for (int i = 0; i < certificates.Count; i++) {
					X509Certificate2 cert = certificates[i];

					if (string.Equals(cert.SubjectName.Name, subjectName, StringComparison.Ordinal)) {
						if (validOn.HasValue) {
							if (CommonUtility.IsDateTimeInRange(cert.NotBefore, cert.NotAfter, validOn.Value, clockSkew, clockSkew) != DateTimeRangeValidity.Valid) {
								continue;
							}
						}

						if (result != null) {
							if (selectMaximumValidityOnMultipleFound) {
								if (cert.NotAfter > result.NotAfter) {
									if (publicKeyOnly) {
										result = new X509Certificate2(cert.RawData);
									}
									else {
										result = new X509Certificate2(cert);
									}
								}
								continue;
							}
							status = CertificateRetrievalStatus.MultipleFound;
							return null;
						}

						if (publicKeyOnly) {
							result = new X509Certificate2(cert.RawData);
						}
						else {
							result = new X509Certificate2(cert);
						}
					}
				}

				if (result == null) {
					status = CertificateRetrievalStatus.NotFound;
					return null;
				}

				status = CertificateRetrievalStatus.None;
				return result;
			}
			finally {
				if (certificates != null) {
					for (int i = 0; i < certificates.Count; i++) {
						X509Certificate2 cert = certificates[i];
						cert.Reset();
					}
				}

				store.Close();
			}
		}
	}
}
