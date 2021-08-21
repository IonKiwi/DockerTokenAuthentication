using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DockerTokenAuthentication.Extensions {
	public static class EnumerableExtensions {
		public static void AddRange<T>(this HashSet<T> set, IEnumerable<T> range) {
			foreach (var item in range) {
				set.Add(item);
			}
		}

		public static TSource OneOrDefault<TSource>(this IEnumerable<TSource> source) {
			if (source == null) {
				return default(TSource);
			}
			int count = 0;
			TSource result = default(TSource);
			foreach (TSource v in source) {
				result = v;
				count++;
			}
			if (count != 1) {
				return default(TSource);
			}
			return result;
		}

		public static TSource OneOrDefault<TSource>(this IEnumerable<TSource> source, Func<TSource, bool> predicate) {
			if (source == null) {
				return default(TSource);
			}
			else if (predicate == null) {
				throw new ArgumentNullException(nameof(predicate));
			}
			int count = 0;
			TSource result = default(TSource);
			foreach (TSource v in source) {
				if (predicate(v)) {
					result = v;
					count++;
				}
			}
			if (count != 1) {
				return default(TSource);
			}
			return result;
		}

		public static TSource? OneOrNull<TSource>(this IEnumerable<TSource> source) where TSource : struct {
			if (source == null) {
				return null;
			}
			int count = 0;
			TSource result = default(TSource);
			foreach (TSource v in source) {
				result = v;
				count++;
			}
			if (count != 1) {
				return null;
			}
			return result;
		}

		public static TSource? OneOrNull<TSource>(this IEnumerable<TSource> source, Func<TSource, bool> predicate) where TSource : struct {
			if (source == null) {
				return null;
			}
			else if (predicate == null) {
				throw new ArgumentNullException(nameof(predicate));
			}
			int count = 0;
			TSource result = default(TSource);
			foreach (TSource v in source) {
				if (predicate(v)) {
					result = v;
					count++;
				}
			}
			if (count != 1) {
				return null;
			}
			return result;
		}

		public static TSource? SingleOrNull<TSource>(this IEnumerable<TSource> source) where TSource : struct {
			if (source == null) {
				return null;
			}
			int count = 0;
			TSource result = default(TSource);
			foreach (TSource v in source) {
				result = v;
				count++;
			}
			if (count == 0) {
				return null;
			}
			else if (count != 1) {
				throw new InvalidOperationException("Sequence contains more than one matching element");
			}
			return result;
		}

		public static TSource? SingleOrNull<TSource>(this IEnumerable<TSource> source, Func<TSource, bool> predicate) where TSource : struct {
			if (source == null) {
				return null;
			}
			else if (predicate == null) {
				throw new ArgumentNullException(nameof(predicate));
			}
			int count = 0;
			TSource result = default(TSource);
			foreach (TSource v in source) {
				if (predicate(v)) {
					result = v;
					count++;
				}
			}
			if (count == 0) {
				return null;
			}
			else if (count != 1) {
				throw new InvalidOperationException("Sequence contains more than one matching element");
			}
			return result;
		}

		public static TSource? FirstOrNull<TSource>(this IEnumerable<TSource> source) where TSource : struct {
			if (source == null) {
				return null;
			}
			foreach (TSource v in source) {
				return v;
			}
			return null;
		}

		public static TSource? FirstOrNull<TSource>(this IEnumerable<TSource> source, Func<TSource, bool> predicate) where TSource : struct {
			if (source == null) {
				return null;
			}
			else if (predicate == null) {
				throw new ArgumentNullException(nameof(predicate));
			}
			foreach (TSource v in source) {
				if (predicate(v)) {
					return v;
				}
			}
			return null;
		}

		public static IEnumerable<TSource> ConcatSafe<TSource>(this IEnumerable<TSource> first, IEnumerable<TSource> second) {
			if (first != null) {
				foreach (TSource item in first) {
					yield return item;
				}
			}
			if (second != null) {
				foreach (TSource item in second) {
					yield return item;
				}
			}
		}

		public static IEnumerable<int> Indexes<TSource>(this IEnumerable<TSource> source, Func<TSource, bool> where) {
			if (source == null) {
				yield break;
			}

			int i = 0;
			foreach (TSource item in source) {
				if (where(item)) {
					yield return i;
				}
				i++;
			}
		}

		public static IEnumerable<int> Indexes<TSource>(this IEnumerable<TSource> source, Func<TSource, int, bool> where) {
			if (source == null) {
				yield break;
			}

			int i = 0;
			foreach (TSource item in source) {
				if (where(item, i)) {
					yield return i;
				}
				i++;
			}
		}

		public static int SingleIndex<TSource>(this IEnumerable<TSource> source, Func<TSource, bool> where) {
			if (source == null) {
				throw new ArgumentNullException(nameof(source));
			}
			int i = 0;
			int result = -1;
			foreach (TSource item in source) {
				if (where(item)) {
					if (result != -1) {
						throw new InvalidOperationException("Sequence contains more than one matching element");
					}
					result = i;
				}
				i++;
			}
			if (result == -1) {
				throw new InvalidOperationException("Sequence contains no matching element");
			}
			return result;
		}

		public static int SingleIndex<TSource>(this IEnumerable<TSource> source, Func<TSource, int, bool> where) {
			if (source == null) {
				throw new ArgumentNullException(nameof(source));
			}
			int i = 0;
			int result = -1;
			foreach (TSource item in source) {
				if (where(item, i)) {
					if (result != -1) {
						throw new InvalidOperationException("Sequence contains more than one matching element");
					}
					result = i;
				}
				i++;
			}
			if (result == -1) {
				throw new InvalidOperationException("Sequence contains no matching element");
			}
			return result;
		}

		public static int? SingleIndexOrNull<TSource>(this IEnumerable<TSource> source, Func<TSource, bool> where) {
			if (source == null) {
				return null;
			}
			int i = 0;
			int result = -1;
			foreach (TSource item in source) {
				if (where(item)) {
					if (result != -1) {
						throw new InvalidOperationException("Sequence contains more than one matching element");
					}
					result = i;
				}
				i++;
			}
			if (result == -1) {
				return null;
			}
			return result;
		}

		public static int? SingleIndexOrNull<TSource>(this IEnumerable<TSource> source, Func<TSource, int, bool> where) {
			if (source == null) {
				return null;
			}
			int i = 0;
			int result = -1;
			foreach (TSource item in source) {
				if (where(item, i)) {
					if (result != -1) {
						throw new InvalidOperationException("Sequence contains more than one matching element");
					}
					result = i;
				}
				i++;
			}
			if (result == -1) {
				return null;
			}
			return result;
		}

		public static int FirstIndex<TSource>(this IEnumerable<TSource> source, Func<TSource, bool> where) {
			if (source == null) {
				throw new ArgumentNullException(nameof(source));
			}
			int i = 0;
			foreach (TSource item in source) {
				if (where(item)) {
					return i;
				}
				i++;
			}
			throw new InvalidOperationException("Sequence contains no matching element");
		}

		public static int FirstIndex<TSource>(this IEnumerable<TSource> source, Func<TSource, int, bool> where) {
			if (source == null) {
				throw new ArgumentNullException(nameof(source));
			}
			int i = 0;
			foreach (TSource item in source) {
				if (where(item, i)) {
					return i;
				}
				i++;
			}
			throw new InvalidOperationException("Sequence contains no matching element");
		}

		public static int? FirstIndexOrNull<TSource>(this IEnumerable<TSource> source, Func<TSource, bool> where) {
			if (source == null) {
				return null;
			}
			int i = 0;
			foreach (TSource item in source) {
				if (where(item)) {
					return i;
				}
				i++;
			}
			return null;
		}

		public static int? FirstIndexOrNull<TSource>(this IEnumerable<TSource> source, Func<TSource, int, bool> where) {
			if (source == null) {
				return null;
			}
			int i = 0;
			foreach (TSource item in source) {
				if (where(item, i)) {
					return i;
				}
				i++;
			}
			return null;
		}
	}
}
