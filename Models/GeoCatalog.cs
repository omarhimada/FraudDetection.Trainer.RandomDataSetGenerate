using static FraudDetection.Trainer.RandomDataSetGenerate.Constants;

namespace FraudDetection.Trainer.RandomDataSetGenerate.Models {
	public sealed record GeoPoint(string Country, string Region, string City, double Lat, double Lon);

	/// <summary>
	/// Provides a catalog of geographic points representing major cities, with associated weights for probabilistic
	/// selection.
	/// </summary>
	/// <remarks>Use <see cref="GeoCatalog.Create"/> to obtain a catalog instance pre-populated with a set of global
	/// cities. The catalog supports weighted random selection and distance-based queries. This class is sealed and cannot
	/// be inherited.</remarks>
	public sealed class GeoCatalog {
		private readonly List<(GeoPoint P, double W)> _points;

		private GeoCatalog(List<(GeoPoint P, double W)> points) => _points = points;

		/// <summary>
		/// Creates a new instance of the GeoCatalog class pre-populated with a representative set of major world cities and
		/// associated weights.
		/// </summary>
		/// <remarks>The returned GeoCatalog includes a curated list of cities from various countries, intended for
		/// demonstration or testing purposes. The set of cities and their weights can be adjusted as needed to suit different
		/// scenarios.</remarks>
		/// <returns>A GeoCatalog containing a predefined collection of GeoPoint entries for selected global cities, each with an
		/// associated weight.</returns>
		public static GeoCatalog Create() {
			// Light set of cities with weights; tweak as you like.
			List<(GeoPoint, double)> pts =
			[
				(new GeoPoint(_ca, _on, _toronto, 43.6532, -79.3832), 9),
				(new GeoPoint(_ca, _bc, _vancouver, 49.2827, -123.1207), 6),
				(new GeoPoint(_us, _ca_us, _sanFrancisco, 37.7749, -122.4194), 9),
				(new GeoPoint(_us, _ny, _newYork, 40.7128, -74.0060), 8),
				(new GeoPoint(_us, _wa, _seattle, 47.6062, -122.3321), 7),
				(new GeoPoint(_gb, _eng, _London, 51.5074, -0.1278), 7),
				(new GeoPoint(_de, _be, _berlin, 52.5200, 13.4050), 5),
				(new GeoPoint(_fr, _idf, _paris, 48.8566, 2.3522), 5),
				(new GeoPoint(_in, _mh, _mumbai, 19.0760, 72.8777), 6),
				(new GeoPoint(_sg, _sg, _singapore, 1.3521, 103.8198), 6),
				(new GeoPoint(_br, _sp, _saoPaulo, -23.5505, -46.6333), 4),
				(new GeoPoint(_za, _gp, _johannesburg, -26.2041, 28.0473), 3),
				(new GeoPoint(_jp, _urbanCore, _tokyo, 35.6762, 139.6503), 6),
				(new GeoPoint(_au, _nsw, _sydney, -33.8688, 151.2093), 4),
				(new GeoPoint(_ru, _mow, _moscow, 55.7558, 37.6173), 2),
				(new GeoPoint(_ru, _mow, _moscow, 55.7558, 37.6173), 2),
			];

			return new GeoCatalog(pts);
		}

		public GeoPoint WeightedRandom(Random rng, bool preferNorthAmerica) {
			IEnumerable<(GeoPoint P, double W)> src = _points;
			if (preferNorthAmerica) {
				src = src.Select(x => {
					bool na = x.P.Country is "US" or "CA";
					return (x.P, na ? x.W * 1.8 : x.W * 0.7);
				});
			}

			double total = src.Sum(x => x.W);
			double r = rng.NextDouble() * total;
			double acc = 0;
			foreach ((GeoPoint p, double w) in src) {
				acc += w;
				if (r <= acc)
					return p;
			}
			return _points[^1].P;
		}

		public GeoPoint FarFrom(GeoPoint origin, double minKm, Random rng) {
			// pick a point far away from origin
			for (int i = 0; i < 30; i++) {
				GeoPoint p = _points[rng.Next(_points.Count)].P;
				double km = Haversine(origin.Lat, origin.Lon, p.Lat, p.Lon);
				if (km >= minKm)
					return p;
			}
			// fallback
			return _points[^1].P;

			static double Haversine(double lat1, double lon1, double lat2, double lon2) {
				double R = 6371.0;
				double dLat = (lat2 - lat1) * Math.PI / 180.0;
				double dLon = (lon2 - lon1) * Math.PI / 180.0;
				double a =
					(Math.Sin(dLat / 2) * Math.Sin(dLat / 2)) +
					(Math.Cos(lat1 * Math.PI / 180.0) * Math.Cos(lat2 * Math.PI / 180.0) *
					Math.Sin(dLon / 2) * Math.Sin(dLon / 2));
				double c = 2 * Math.Atan2(Math.Sqrt(a), Math.Sqrt(1 - a));
				return R * c;
			}
		}
	}
}
