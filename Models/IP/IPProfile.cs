namespace FraudDetection.Trainer.RandomDataSetGenerate.Models.IP;

using static FraudDetection.Trainer.RandomDataSetGenerate.Constants;

/// <summary>
/// Represents a network IP profile, including address, autonomous system number (ASN), network type, Tor status, and
/// reputation score.
/// </summary>
/// <param name="Ip">The IPv4 address associated with the profile, in dotted-decimal notation.</param>
/// <param name="Asn">The autonomous system number (ASN) that owns or routes the IP address.</param>
/// <param name="NetworkType">The type of network for the IP address, such as 'residential', 'mobile', or 'datacenter'.</param>
/// <param name="IsTor">true if the IP address is identified as a Tor exit node; otherwise, false.</param>
/// <param name="IpReputation">The reputation score for the IP address, typically on a scale where higher values indicate better reputation.</param>
public sealed record IpProfile(
	string Ip,
	string Asn,
	string NetworkType,
	bool IsTor,
	int IpReputation
) {
	/// <summary>
	/// Creates a new IpProfile instance with plausible values based on the specified geographic location and IP quality.
	/// </summary>
	/// <remarks>The generated IP address is plausible but not guaranteed to correspond to the provided geographic
	/// location. The method is intended for generating test or mock data rather than real-world geolocation
	/// mapping.</remarks>
	/// <param name="rng">The random number generator used to produce randomized profile attributes.</param>
	/// <param name="geo">The geographic location to associate with the generated IP profile.</param>
	/// <param name="quality">The desired quality level for the generated IP profile, which influences network type, ASN, and reputation.</param>
	/// <param name="forceTor">true to force the generated profile to _be marked as a Tor exit node; otherwise, false.</param>
	/// <returns>An IpProfile instance with randomized attributes corresponding to the specified geographic location and quality.</returns>
	public static IpProfile FromGeo(Random rng, GeoPoint geo, IpQuality quality, bool forceTor = false) {
		string asn = quality switch {
			IpQuality.Good => $"{_as}{rng.Next(1000, 9999)}",
			IpQuality.DatacenterMedium => $"{_as}{rng.Next(20000, 30000)}",
			IpQuality.DatacenterBad => $"{_as}{rng.Next(40000, 50000)}",
			_ => throw new ArgumentOutOfRangeException(nameof(quality), quality, _message)
		};

		string net = quality switch {
			IpQuality.Good => WeightedPick(rng, new[] { _residential, _mobile }, new[] { 0.75, 0.25 }),
			IpQuality.DatacenterMedium => _datacenter,
			IpQuality.DatacenterBad => _datacenter,
			_ => throw new ArgumentOutOfRangeException(nameof(quality), quality, _message)
		};

		int rep = quality switch {
			IpQuality.Good => 70 + rng.Next(25),
			IpQuality.DatacenterMedium => 45 + rng.Next(30),
			IpQuality.DatacenterBad => 5 + rng.Next(35),
			_ => throw new ArgumentOutOfRangeException(nameof(quality), quality, _message)
		};

		// make a plausible IP (not real geo-based)
		string ip = $"{rng.Next(1, 223)}.{rng.Next(0, 255)}.{rng.Next(0, 255)}.{rng.Next(1, 255)}";
		return new IpProfile(ip, asn, net, forceTor, rep);

		static string WeightedPick(Random rng, IReadOnlyList<string> items, IReadOnlyList<double> weights) {
			double total = weights.Sum();
			double r = new Random().NextDouble() * total;
			double acc = 0;
			for (int i = 0; i < items.Count; i++) {
				acc += weights[i];
				if (r <= acc)
					return items[i];
			}
			return items[^1];
		}
	}
}
