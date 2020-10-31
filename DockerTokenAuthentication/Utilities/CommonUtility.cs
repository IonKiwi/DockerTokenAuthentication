using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DockerTokenAuthentication.Utilities {
	public enum DateTimeRangeValidity {
		Valid,
		NotYetValid,
		Expired
	}

	public enum DateTimeHandling {
		Current,
		Utc,
		Local,
	}

	public enum UnspecifiedDateTimeHandling {
		AssumeLocal,
		AssumeUtc
	}

	public static class CommonUtility {

		private static readonly object _globalLock = new object();

		private static Tuple<Dictionary<string, Enum>, Dictionary<string, Enum>, Dictionary<string, ulong>, Dictionary<string, ulong>, Tuple<ulong, Enum>[]> CreateEnumValuesDictionary(Type enumType) {
			Dictionary<string, Enum> r1 = new Dictionary<string, Enum>(StringComparer.Ordinal);
			Dictionary<string, Enum> r2 = new Dictionary<string, Enum>(StringComparer.OrdinalIgnoreCase);
			Dictionary<string, ulong> r3 = new Dictionary<string, ulong>(StringComparer.Ordinal);
			Dictionary<string, ulong> r4 = new Dictionary<string, ulong>(StringComparer.OrdinalIgnoreCase);
			List<Tuple<ulong, Enum>> r5 = new List<Tuple<ulong, Enum>>();
			string[] nn = Enum.GetNames(enumType);
			bool isFlags = enumType.GetCustomAttribute<FlagsAttribute>() != null;
			foreach (string n in nn) {
				Enum ev = (Enum)Enum.Parse(enumType, n, false);
				r1.Add(n, ev);
				r2.Add(n, ev);
				if (isFlags) {
					ulong nev = (ulong)Convert.ChangeType(ev, typeof(ulong));
					r3.Add(n, nev);
					r4.Add(n, nev);
					r5.Add(new Tuple<ulong, Enum>(nev, ev));
				}
			}
			r5.Sort((x, y) => {
				if (x.Item1 > y.Item1) return -1;
				else if (x.Item1 < y.Item1) return 1;
				return 0;
			});
			return new Tuple<Dictionary<string, Enum>, Dictionary<string, Enum>, Dictionary<string, ulong>, Dictionary<string, ulong>, Tuple<ulong, Enum>[]>(r1, r2, r3, r4, r5.ToArray());
		}

		private static Dictionary<Type, Tuple<Dictionary<string, Enum>, Dictionary<string, Enum>, Dictionary<string, ulong>, Dictionary<string, ulong>, Tuple<ulong, Enum>[]>> _enumValues = new Dictionary<Type, Tuple<Dictionary<string, Enum>, Dictionary<string, Enum>, Dictionary<string, ulong>, Dictionary<string, ulong>, Tuple<ulong, Enum>[]>>();
		private static Tuple<Dictionary<string, Enum>, Dictionary<string, Enum>, Dictionary<string, ulong>, Dictionary<string, ulong>, Tuple<ulong, Enum>[]> GetEnumValues(Type enumType) {
			Tuple<Dictionary<string, Enum>, Dictionary<string, Enum>, Dictionary<string, ulong>, Dictionary<string, ulong>, Tuple<ulong, Enum>[]> r;
			if (!_enumValues.TryGetValue(enumType, out r)) {
				lock (_globalLock) {
					if (!_enumValues.TryGetValue(enumType, out r)) {
						Dictionary<Type, Tuple<Dictionary<string, Enum>, Dictionary<string, Enum>, Dictionary<string, ulong>, Dictionary<string, ulong>, Tuple<ulong, Enum>[]>> newDictionary = new Dictionary<Type, Tuple<Dictionary<string, Enum>, Dictionary<string, Enum>, Dictionary<string, ulong>, Dictionary<string, ulong>, Tuple<ulong, Enum>[]>>();
						foreach (KeyValuePair<Type, Tuple<Dictionary<string, Enum>, Dictionary<string, Enum>, Dictionary<string, ulong>, Dictionary<string, ulong>, Tuple<ulong, Enum>[]>> kv in _enumValues) {
							newDictionary.Add(kv.Key, kv.Value);
						}
						r = CreateEnumValuesDictionary(enumType);
						newDictionary.Add(enumType, r);
						Interlocked.MemoryBarrier();
						_enumValues = newDictionary;
					}
				}
			}
			return r;
		}

		public static bool TryParseEnum<T>(string stringValue, out T enumValue) where T : struct {
			return TryParseEnum<T>(stringValue, false, out enumValue);
		}

		public static bool TryParseEnum<T>(string stringValue, bool ignoreCase, out T enumValue) where T : struct {
			Type t = typeof(T);
			Enum v;
			if (TryParseEnum(t, stringValue, ignoreCase, out v)) {
				enumValue = (T)(object)v;
				return true;
			}
			enumValue = default(T);
			return false;
		}

		internal static bool TryParseEnum(Type enumType, string stringValue, bool ignoreCase, out Enum enumValue) {
			if (string.IsNullOrEmpty(stringValue)) {
				enumValue = default(Enum);
				return false;
			}

			var vv = GetEnumValues(enumType);
			if (vv.Item3.Count > 0 && stringValue.IndexOf(',') >= 0) {
				ulong ev = 0;
				string[] stringValueParts = stringValue.Split(',');
				for (int i = 0; i < stringValueParts.Length; i++) {
					string v;
					if (i == 0) {
						v = stringValueParts[i];
					}
					else {
						v = stringValueParts[i].Substring(1);
					}
					ulong sev;
					if (ignoreCase) {
						if (!vv.Item4.TryGetValue(v, out sev)) { enumValue = default(Enum); return false; }
					}
					else {
						if (!vv.Item3.TryGetValue(v, out sev)) { enumValue = default(Enum); return false; }
					}
					ev |= sev;
				}
				enumValue = (Enum)Enum.ToObject(enumType, (long)ev);
				return true;
			}
			else {
				if (ignoreCase) {
					return vv.Item2.TryGetValue(stringValue, out enumValue);
				}
				else {
					return vv.Item1.TryGetValue(stringValue, out enumValue);
				}
			}
		}

		public static DateTime EnsureDateTime(DateTime value, DateTimeHandling dateTimeHandling, UnspecifiedDateTimeHandling unspecifiedDateTimeHandling) {
			return EnsureDateTime(value, null, dateTimeHandling, unspecifiedDateTimeHandling);
		}

		private static void ThrowUnsupportedOption(string option) {
			throw new NotSupportedException(option);
		}

		public static DateTime EnsureDateTime(DateTime value, TimeZoneInfo timeZone, DateTimeHandling dateTimeHandling, UnspecifiedDateTimeHandling unspecifiedDateTimeHandling) {
			if (dateTimeHandling == DateTimeHandling.Utc) {
				if (timeZone == null) {
					return SwitchToUtcTime(value, unspecifiedDateTimeHandling);
				}
				return SwitchToUtcTime(value, timeZone, unspecifiedDateTimeHandling);
			}
			else if (dateTimeHandling == DateTimeHandling.Local) {
				if (timeZone == null) {
					return SwitchToLocalTime(value, unspecifiedDateTimeHandling);
				}
				return SwitchToLocalTime(value, timeZone, unspecifiedDateTimeHandling);
			}
			else if (dateTimeHandling == DateTimeHandling.Current) {
				if (value.Kind == DateTimeKind.Utc) {
					return EnsureDateTime(value, timeZone, DateTimeHandling.Utc, unspecifiedDateTimeHandling);
				}
				else if (value.Kind == DateTimeKind.Local) {
					return EnsureDateTime(value, timeZone, DateTimeHandling.Local, unspecifiedDateTimeHandling);
				}
				else {
					if (unspecifiedDateTimeHandling == UnspecifiedDateTimeHandling.AssumeUtc) {
						return EnsureDateTime(value, timeZone, DateTimeHandling.Utc, unspecifiedDateTimeHandling);
					}
					else if (unspecifiedDateTimeHandling == UnspecifiedDateTimeHandling.AssumeLocal) {
						return EnsureDateTime(value, timeZone, DateTimeHandling.Local, unspecifiedDateTimeHandling);
					}
					else {
						ThrowUnsupportedOption(unspecifiedDateTimeHandling.ToString());
						return value;
					}
				}
			}
			else {
				ThrowUnsupportedOption(dateTimeHandling.ToString());
				return value;
			}
		}

		private static DateTime SwitchToLocalTime(DateTime value, TimeZoneInfo timeZone, UnspecifiedDateTimeHandling dateTimeHandling) {
			switch (value.Kind) {
				case DateTimeKind.Unspecified:
					if (dateTimeHandling == UnspecifiedDateTimeHandling.AssumeLocal)
						return (string.Equals(timeZone.Id, TimeZoneInfo.Local.Id, StringComparison.Ordinal) ? new DateTime(value.Ticks, DateTimeKind.Local) : value);
					else
						return TimeZoneInfo.ConvertTimeFromUtc(new DateTime(value.Ticks, DateTimeKind.Utc), timeZone);

				case DateTimeKind.Utc:
					return TimeZoneInfo.ConvertTimeFromUtc(value, timeZone);

				case DateTimeKind.Local:
					return TimeZoneInfo.ConvertTime(value, timeZone);
			}
			return value;
		}

		private static DateTime SwitchToLocalTime(DateTime value, UnspecifiedDateTimeHandling dateTimeHandling) {
			switch (value.Kind) {
				case DateTimeKind.Unspecified:
					if (dateTimeHandling == UnspecifiedDateTimeHandling.AssumeLocal)
						return new DateTime(value.Ticks, DateTimeKind.Local);
					else
						return new DateTime(value.Ticks, DateTimeKind.Utc).ToLocalTime();

				case DateTimeKind.Utc:
					return value.ToLocalTime();

				case DateTimeKind.Local:
					return value;
			}
			return value;
		}

		private static DateTime SwitchToUtcTime(DateTime value, TimeZoneInfo timeZone, UnspecifiedDateTimeHandling dateTimeHandling) {
			switch (value.Kind) {
				case DateTimeKind.Unspecified:
					if (dateTimeHandling == UnspecifiedDateTimeHandling.AssumeUtc)
						return new DateTime(value.Ticks, DateTimeKind.Utc);
					else
						return TimeZoneInfo.ConvertTimeToUtc(value, timeZone);

				case DateTimeKind.Utc:
					return value;

				case DateTimeKind.Local:
					return value.ToUniversalTime();
			}
			return value;
		}

		private static DateTime SwitchToUtcTime(DateTime value, UnspecifiedDateTimeHandling dateTimeHandling) {
			switch (value.Kind) {
				case DateTimeKind.Unspecified:
					if (dateTimeHandling == UnspecifiedDateTimeHandling.AssumeUtc)
						return new DateTime(value.Ticks, DateTimeKind.Utc);
					else
						return new DateTime(value.Ticks, DateTimeKind.Local).ToUniversalTime();

				case DateTimeKind.Utc:
					return value;

				case DateTimeKind.Local:
					return value.ToUniversalTime();
			}
			return value;
		}

		public static DateTimeRangeValidity IsDateTimeInRange(DateTime? start, DateTime? end, DateTime? now = null, TimeSpan? clockSkewBefore = null, TimeSpan? clockSkewAfter = null, TimeZoneInfo timeZone = null) {
			TimeSpan clockSkewBeforev = clockSkewBefore ?? TimeSpan.FromMinutes(5);
			TimeSpan clockSkewAfterv = clockSkewAfter ?? TimeSpan.FromMinutes(5);
			DateTime nowv = now ?? DateTime.UtcNow;
			if (nowv.Kind == DateTimeKind.Local) {
				nowv = nowv.ToUniversalTime();
			}
			else if (nowv.Kind == DateTimeKind.Unspecified) {
				if (timeZone == null) {
					nowv = new DateTime(nowv.Ticks, DateTimeKind.Local).ToUniversalTime();
				}
				else {
					nowv = TimeZoneInfo.ConvertTimeToUtc(nowv, timeZone);
				}
			}
			if (start.HasValue) {
				if (start.Value.Kind == DateTimeKind.Local) {
					start = start.Value.ToUniversalTime();
				}
				else if (start.Value.Kind == DateTimeKind.Unspecified) {
					if (timeZone == null) {
						start = new DateTime(start.Value.Ticks, DateTimeKind.Local).ToUniversalTime();
					}
					else {
						start = TimeZoneInfo.ConvertTimeToUtc(start.Value, timeZone);
					}
				}
			}
			if (end.HasValue) {
				if (end.Value.Kind == DateTimeKind.Local) {
					end = end.Value.ToUniversalTime();
				}
				else if (end.Value.Kind == DateTimeKind.Unspecified) {
					if (timeZone == null) {
						end = new DateTime(end.Value.Ticks, DateTimeKind.Local).ToUniversalTime();
					}
					else {
						end = TimeZoneInfo.ConvertTimeToUtc(end.Value, timeZone);
					}
				}
			}

			if (start.HasValue && (AddToDateTime(nowv, clockSkewBeforev) < start.Value)) {
				return DateTimeRangeValidity.NotYetValid;
			}
			if (end.HasValue && (AddToDateTime(nowv, clockSkewAfterv.Negate()) >= end.Value)) {
				return DateTimeRangeValidity.Expired;
			}

			return DateTimeRangeValidity.Valid;
		}

		public static DateTime SubtractFromDateTime(DateTime time, TimeSpan timeout) {
			return AddToDateTime(time, TimeSpan.Zero - timeout);
		}

		public static DateTime AddToDateTime(DateTime time, TimeSpan timeout) {
			if ((timeout >= TimeSpan.Zero) && ((DateTime.MaxValue - time) <= timeout)) {
				return DateTime.MaxValue;
			}
			if ((timeout <= TimeSpan.Zero) && ((DateTime.MinValue - time) >= timeout)) {
				return DateTime.MinValue;
			}
			return (time + timeout);
		}

		public static string CombineWithCharacter(char separator, params string[] args) {
			if (args == null || args.Length == 0) {
				return string.Empty;
			}

			var nonEmptyArgs = args.Where(x => !string.IsNullOrEmpty(x)).ToArray();
			if (nonEmptyArgs.Length == 0) {
				return string.Empty;
			}
			else if (nonEmptyArgs.Length == 1) {
				return nonEmptyArgs[0];
			}
			else if (nonEmptyArgs.Length == 2) {
				return string.Concat(nonEmptyArgs[0].TrimEnd(separator), separator, nonEmptyArgs[1].TrimStart(separator));
			}
			else {
				StringBuilder sb = new StringBuilder();
				sb.Append(nonEmptyArgs[0].TrimEnd(separator));
				for (int i = 1; i < nonEmptyArgs.Length - 1; i++) {
					sb.Append(separator);
					sb.Append(nonEmptyArgs[i].Trim(separator));
				}
				sb.Append(separator);
				sb.Append(nonEmptyArgs[nonEmptyArgs.Length - 1].TrimStart(separator));
				return sb.ToString();
			}
		}

		public static string CombineWithSlash(params string[] args) {
			return CombineWithCharacter('/', args);
		}

		public static string CombineWithBackslash(params string[] args) {
			return CombineWithCharacter('\\', args);
		}

		public static bool AreByteArraysEqual(byte[] x, byte[] y) {
			if (x == null && y == null) {
				return true;
			}
			else if (x == null || y == null) {
				return false;
			}
			else if (x.Length != y.Length) {
				return false;
			}
			for (int i = 0; i < x.Length; i++) {
				if (x[i] != y[i]) {
					return false;
				}
			}
			return true;
		}

		public static string GetHexadecimalString(IEnumerable<byte> data, bool upperCase) {
			string format = (upperCase ? "X2" : "x2");
			return data.Aggregate(new StringBuilder(),
				(sb, v) => sb.Append(v.ToString(format))).ToString();
		}

		public static string GetReverseHexadecimalString(IEnumerable<byte> data, bool upperCase) {
			return GetHexadecimalString(data.Reverse(), upperCase);
		}

		public static string GetHexadecimalString(IEnumerable<byte> data, bool upperCase, bool withoutLeadingZeros) {
			if (!withoutLeadingZeros) {
				return GetHexadecimalString(data, upperCase);
			}
			else {
				StringBuilder sb = new StringBuilder();
				bool foundFirstByte = false;
				string format = (upperCase ? "X2" : "x2");
				string formatFirst = (upperCase ? "X" : "x");
				foreach (byte b in data) {
					if (foundFirstByte) {
						sb.Append(b.ToString(format));
					}
					else if (b != 0) {
						sb.Append(b.ToString(formatFirst));
						foundFirstByte = true;
					}
				}
				return sb.ToString();
			}
		}

		public static string GetReverseHexadecimalString(IEnumerable<byte> data, bool upperCase, bool withoutLeadingZeros) {
			return GetHexadecimalString(data.Reverse(), upperCase, withoutLeadingZeros);
		}

		public static byte[] GetByteArray(string hexString) {
			if (string.IsNullOrEmpty(hexString)) {
				return null;
			}
			int strLength = hexString.Length;
			if (strLength % 2 == 1) {
				return null;
			}
			strLength = strLength >> 1;
			byte[] tmpArray = new byte[strLength];
			for (int i = 0; i < strLength; i++) {
				bool valid;
				int z = GetByte(hexString[i << 1], out valid) << 4;
				if (!valid) {
					return null;
				}
				z += GetByte(hexString[(i << 1) + 1], out valid);
				if (!valid) {
					return null;
				}
				tmpArray[i] = (byte)z;
			}
			return tmpArray;
		}

		private static int GetByte(char x, out bool valid) {
			int z = (int)x;
			if (z >= 0x30 && z <= 0x39) {
				valid = true;
				return (byte)(z - 0x30);
			}
			else if (z >= 0x41 && z <= 0x46) {
				valid = true;
				return (byte)(z - 0x37);
			}
			else if (z >= 0x61 && z <= 0x66) {
				valid = true;
				return (byte)(z - 0x57);
			}
			valid = false;
			return 0;
		}

		public static long GetTimestamp(DateTime time) {
			if (time.Kind == DateTimeKind.Utc) {
				return (long)(time - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
			}
			else if (time.Kind == DateTimeKind.Local) {
				DateTime utcTime = time.ToUniversalTime();
				return (long)(utcTime - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
			}
			else {
				throw new InvalidOperationException();
			}
		}

		public static long GetTimestamp() {
			return (long)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
		}

		public static DateTime GetDateTimeFromTimestamp(long timestamp) {
			return new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(timestamp);
		}
	}
}
