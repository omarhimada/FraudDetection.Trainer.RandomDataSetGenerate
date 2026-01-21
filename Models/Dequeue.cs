namespace FraudDetection.Trainer.RandomDataSetGenerate.Models {
	/// <summary>
	/// Represents a double-ended queue (deque) that allows elements to be added or removed from both ends.
	/// </summary>
	/// <remarks>A deque provides efficient insertion and removal of elements at both the front and back. This
	/// implementation maintains the order of elements and allows enumeration from front to back. The Deque<T> class is not
	/// thread-safe.</remarks>
	/// <typeparam name="T">The type of elements stored in the deque.</typeparam>
	public sealed class Deque<T> {
		private readonly LinkedList<T> _list = new();
		public int Count => _list.Count;

		public void AddLast(T item) => _list.AddLast(item);
		public T PeekFirst() => _list.First!.Value;
		public void RemoveFirst() => _list.RemoveFirst();

		public IEnumerator<T> GetEnumerator() => _list.GetEnumerator();
		public IEnumerable<T> AsEnumerable() => _list;

		public T? LastOrDefault() => _list.Count == 0 ? default : _list.Last!.Value;
	}

	/// <summary>
	/// Provides extension methods for querying and projecting elements in a Deque<T> collection.
	/// </summary>
	/// <remarks>These extension methods enable LINQ-style operations on Deque<T> instances, allowing for filtering,
	/// projection, and aggregation similar to standard LINQ methods available for other collection types. All methods
	/// enumerate the deque in order from front to back.</remarks>
	public static class DequeExtensions {
		public static IEnumerable<T> Where<T>(this Deque<T> q, Func<T, bool> pred) => q.AsEnumerable().Where(pred);
		public static IEnumerable<TResult> Select<T, TResult>(this Deque<T> q, Func<T, TResult> sel) => q.AsEnumerable().Select(sel);
		public static int Count<T>(this Deque<T> q, Func<T, bool> pred) => q.AsEnumerable().Count(pred);
		public static T? LastOrDefault<T>(this Deque<T> q) => q.AsEnumerable().LastOrDefault();
	}
}
