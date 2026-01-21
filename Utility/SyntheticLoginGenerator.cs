using FraudDetection.Trainer.RandomDataSetGenerate.Models;
using FraudDetection.Trainer.RandomDataSetGenerate.Models.IP;
using static FraudDetection.Trainer.RandomDataSetGenerate.Constants;

namespace FraudDetection.Trainer.RandomDataSetGenerate.Utility {
	/// <summary>
	/// Provides functionality to generate synthetic login events for multiple tenants, simulating both normal and
	/// fraudulent authentication activity for use in testing, analytics, or security research scenarios.
	/// </summary>
	/// <remarks>The SyntheticLoginGenerator creates realistic login event data, including a mix of typical user
	/// behavior and various attack patterns such as credential stuffing, password spraying, and account takeover attempts.
	/// Events are enriched with rolling features to support time-series analysis and anomaly detection. This class is
	/// intended for use in environments where representative authentication data is needed without exposing real user
	/// information. The generator is not thread-safe; if used concurrently, callers should provide their own
	/// synchronization.</remarks>
	public sealed class SyntheticLoginGenerator {
		private readonly Random _rng;
		private readonly List<Tenant> _tenants;
		private readonly List<AppClient> _apps;
		private readonly GeoCatalog _geo;
		private readonly Dictionary<string, UserState> _userStateById = new(StringComparer.OrdinalIgnoreCase);
		private readonly Dictionary<string, Deque<LoginEvent>> _recentByUser = new(StringComparer.OrdinalIgnoreCase);
		private readonly Dictionary<string, Deque<LoginEvent>> _recentByIp = new(StringComparer.OrdinalIgnoreCase);

		public SyntheticLoginGenerator() {
			_rng = new Random();
			_geo = GeoCatalog.Create();

			_tenants =
			[
				new Tenant(_tAcme, _acmeCo),
				new Tenant(_tZephyr, _zephyrLtd),
				new Tenant(_tNorthwind, _northwind)
			];

			_apps =
			[
				new AppClient(_appWeb, _webApp, _authorizatioeCode),
				new AppClient(_appMobile, _mobileApp, _authorizatioeCode),
				new AppClient(_appApi, _serviceApi, _clientCredentials)
			];

			// Create users across tenants.
			foreach (Tenant t in _tenants) {
				int userCount = 250 + _rng.Next(150);
				for (int i = 0; i < userCount; i++) {
					string userId = $"{t.Id}_u{i:D4}";
					string username = $"{_user}{i:D4}@{t.Name.ToLowerInvariant()}{_example}";
					string userType = (i % 40 == 0) ? _admin : _customer;

					GeoPoint home = _geo.WeightedRandom(_rng, preferNorthAmerica: true);
					string primaryDevice = $"{_dev}{userId}{_a}";

					_userStateById[userId] = new UserState(
						TenantId: t.Id,
						UserId: userId,
						Username: username,
						UserType: userType,
						Home: home,
						PrimaryDeviceId: primaryDevice
					);
				}
			}
		}

		/// <summary>
		/// Generates a list of synthetic login events within the specified UTC time range, simulating both normal and
		/// fraudulent activity.
		/// </summary>
		/// <remarks>The generated events include a mix of normal and various types of fraudulent login attempts, such
		/// as credential stuffing, password spraying, and targeted account takeovers. The method enriches each event with
		/// rolling features based on recent history to better simulate realistic login patterns.</remarks>
		/// <param name="utcStart">The start of the time range, in Coordinated Universal Time (UTC), for which to generate login events. Must be
		/// earlier than <paramref name="utcEnd"/>.</param>
		/// <param name="utcEnd">The end of the time range, in Coordinated Universal Time (UTC), for which to generate login events. Must be later
		/// than <paramref name="utcStart"/>.</param>
		/// <param name="eventsPerDay">The approximate number of login events to generate per day within the specified time range. Must be a non-negative
		/// integer.</param>
		/// <returns>A list of <see cref="LoginEvent"/> objects representing generated login events, sorted in chronological order by
		/// timestamp. The list may be empty if the specified time range or event count results in zero events.</returns>
		/// <exception cref="ArgumentException">Thrown if <paramref name="utcEnd"/> is less than or equal to <paramref name="utcStart"/>.</exception>
		public List<LoginEvent> Generate(DateTime utcStart, DateTime utcEnd, int eventsPerDay) {
			if (utcEnd <= utcStart) {
				throw new ArgumentException(_utcEndStartVerify);
			}

			int totalEvents = (int)Math.Ceiling((utcEnd - utcStart).TotalDays * eventsPerDay);
			List<LoginEvent> events = new(totalEvents);

			// Fraud actors / infrastructure
			FraudActor stuffingBot = new(_fraudStuffing01, behavior: FraudBehavior.CredentialStuffing);
			FraudActor sprayBot = new(_fraudSpray01, behavior: FraudBehavior.PasswordSpray);
			FraudActor takeoverBot = new(_fraudTakeover01, behavior: FraudBehavior.TargetedTakeover);

			for (int i = 0; i < totalEvents; i++) {
				DateTime ts = RandomTime(utcStart, utcEnd);

				// Choose normal vs fraud event mix
				double p = _rng.NextDouble();
				LoginEvent ev = p < 0.82
					? GenerateNormal(ts)
					: p < 0.90
						? GenerateCredentialStuffing(ts, stuffingBot)
						: p < 0.96 ? GeneratePasswordSpray(ts, sprayBot) : GenerateTakeoverOrMfaFatigue(ts, takeoverBot);

				// Compute rolling features based on recent history
				LoginEvent enriched = EnrichWithRollingFeatures(ev);
				events.Add(enriched);

				Remember(enriched);
			}

			// Sort for time-series ingestion
			events.Sort((a, b) => a.TimestampUtc.CompareTo(b.TimestampUtc));
			return events;
		}

		/// <summary>
		/// Generates a simulated normal login event for a user at the specified timestamp.
		/// </summary>
		/// <remarks>The generated login event reflects common login patterns, including user device usage, IP
		/// reputation, and multi-factor authentication scenarios. This method is intended for use in test data generation or
		/// simulation environments and does not represent actual authentication logic.</remarks>
		/// <param name="ts">The UTC timestamp to assign to the generated login event.</param>
		/// <returns>A <see cref="LoginEvent"/> object representing a typical successful or failed login attempt with realistic user,
		/// device, and network characteristics.</returns>
		private LoginEvent GenerateNormal(DateTime ts) {
			UserState u = RandomUser();
			Tenant t = _tenants.First(x => x.Id == u.TenantId);
			AppClient app = WeightedPick(_apps, x => x.Id == _appWeb ? 0.55 : (x.Id == _appMobile ? 0.35 : 0.10));

			// Most normal logins come from home-ish geo with decent reputation
			GeoPoint geo = JitterGeo(u.Home, maxKm: 80);
			IpProfile ip = IpProfile.FromGeo(_rng, geo, quality: IpQuality.Good);

			string deviceId = (_rng.NextDouble() < 0.90) ? u.PrimaryDeviceId : $"{_dev}{u.UserId}_B";
			bool isNewDevice = deviceId != u.PrimaryDeviceId;

			// Normal: success rate high, occasional fat-finger failures.
			bool success = _rng.NextDouble() < (u.UserType == _admin ? 0.92 : 0.95);
			string failureReason = success ? string.Empty : _invalidPassword;

			// MFA: admins more often, and step-up occasionally
			bool stepUp = u.UserType == _admin ? (_rng.NextDouble() < 0.60) : (_rng.NextDouble() < 0.15);
			string mfaMethod = stepUp ? WeightedPick(new[] { _push, _totp, _webAuthn }, new[] { 0.55, 0.30, 0.15 }) : _none;
			string mfaOutcome = stepUp ? (success ? _passed : _notChallenged) : _notChallenged;

			int riskScore = ClampToByte((int)Math.Round(
				8
				+ (isNewDevice ? 10f : 0f)
				+ (ip.IpReputation < 40 ? 10f : 0f)
				+ (u.UserType == _admin ? 5f : 0f)
				+ (_rng.NextDouble() < 0.03f ? 15f : 0f)
			));

			return new LoginEvent {
				TimestampUtc = ts,
				TenantId = t.Id,
				UserId = u.UserId,
				Username = u.Username,
				UserType = u.UserType,

				ClientId = app.Id,
				AuthFlow = app.AuthFlow,

				SourceIp = ip.Ip,
				Asn = ip.Asn,
				NetworkType = ip.NetworkType,
				IsTor = ip.IsTor,
				IpReputation = ip.IpReputation,

				Country = geo.Country,
				Region = geo.Region,
				City = geo.City,
				Latitude = geo.Lat,
				Longitude = geo.Lon,

				UserAgent = app.Id == _appMobile ? _oktaMobileIos : _mozillaWindows,
				DeviceId = deviceId,
				IsNewDevice = isNewDevice,

				PolicyId = u.UserType == _admin ? _policyAdminStrict : _polDefault,
				StepUpRequired = stepUp,
				MfaMethod = mfaMethod,
				MfaOutcome = mfaOutcome,
				MfaPromptCount = stepUp ? 1 : 0,

				Outcome = success ? _success : _fail,
				FailureReason = failureReason,
				RiskScore = riskScore,

				AttackType = _none
			};
		}

		/// <summary>
		/// Generates a simulated login event representing a credential stuffing attack attempt.
		/// </summary>
		/// <remarks>Credential stuffing attacks involve automated attempts to log in using large numbers of username
		/// and password combinations, typically resulting in many failed logins from a single IP address. The generated event
		/// reflects common characteristics of such attacks, including low success rates, use of datacenter or Tor IPs, and
		/// minimal multi-factor authentication interaction.</remarks>
		/// <param name="ts">The UTC timestamp to assign to the generated login event.</param>
		/// <param name="actor">The fraud actor responsible for initiating the credential stuffing attempt.</param>
		/// <returns>A <see cref="LoginEvent"/> object containing details of the simulated credential stuffing login attempt.</returns>
		private LoginEvent GenerateCredentialStuffing(DateTime ts, FraudActor actor) {
			// One IP targets many usernames rapidly with mostly failures.
			UserState victim = RandomUser();

			GeoPoint geo = _geo.WeightedRandom(_rng, preferNorthAmerica: false); // more global
			IpProfile ip = IpProfile.FromGeo(_rng, geo, quality: IpQuality.DatacenterBad, forceTor: _rng.NextDouble() < 0.25);

			bool success = _rng.NextDouble() < 0.01; // very rare success
			string failureReason = success ? string.Empty : _invalidPassword;

			// Often no MFA because failures never reach it; or policy requires step-up but not satisfied.
			bool stepUp = _rng.NextDouble() < 0.20;
			string mfaMethod = stepUp ? _push : _none;
			string mfaOutcome = stepUp ? (success ? _passed : _notChallenged) : _notChallenged;

			int riskScore = ClampToByte(70 + (ip.IsTor ? 10 : 0) + (_rng.NextDouble() < 0.4 ? 10 : 0));

			AppClient app = WeightedPick(_apps, x => x.Id == _appWeb ? 0.80 : 0.20);
			return new LoginEvent {
				TimestampUtc = ts,
				TenantId = victim.TenantId,
				UserId = victim.UserId,
				Username = victim.Username,
				UserType = victim.UserType,

				ClientId = app.Id,
				AuthFlow = app.AuthFlow,

				SourceIp = ip.Ip,
				Asn = ip.Asn,
				NetworkType = ip.NetworkType,
				IsTor = ip.IsTor,
				IpReputation = ip.IpReputation,

				Country = geo.Country,
				Region = geo.Region,
				City = geo.City,
				Latitude = geo.Lat,
				Longitude = geo.Lon,

				UserAgent = _pythonRequests,
				DeviceId = $"{_dev}{actor.Id}_{_rng.Next(1000, 9999)}",
				IsNewDevice = true,

				PolicyId = _polDefault,
				StepUpRequired = stepUp,
				MfaMethod = mfaMethod,
				MfaOutcome = mfaOutcome,
				MfaPromptCount = stepUp ? 1 : 0,

				Outcome = success ? _success : _fail,
				FailureReason = failureReason,
				RiskScore = riskScore,

				AttackType = _credentialStuffing
			};
		}

		private LoginEvent GeneratePasswordSpray(DateTime ts, FraudActor actor) {
			// One IP tries 1–2 attempts across many users: lower per-user volume, higher breadth.
			UserState victim = RandomUser();

			GeoPoint geo = _geo.WeightedRandom(_rng, preferNorthAmerica: false);
			IpProfile ip = IpProfile.FromGeo(_rng, geo, quality: IpQuality.DatacenterMedium, forceTor: _rng.NextDouble() < 0.10);

			bool success = _rng.NextDouble() < 0.03; // still rare but higher than stuffing
			string failureReason = success ? string.Empty : _invalidPassword;

			bool stepUp = _rng.NextDouble() < 0.10;
			string mfaMethod = stepUp ? _push : _none;
			string mfaOutcome = stepUp ? (success ? "Passed" : "NotChallenged") : "NotChallenged";

			int riskScore = ClampToByte(55 + (ip.IsTor ? 10 : 0) + (_rng.NextDouble() < 0.3 ? 10 : 0));

			AppClient app = WeightedPick(_apps, x => x.Id == _appWeb ? 0.85 : 0.15);
			return new LoginEvent {
				TimestampUtc = ts,
				TenantId = victim.TenantId,
				UserId = victim.UserId,
				Username = victim.Username,
				UserType = victim.UserType,

				ClientId = app.Id,
				AuthFlow = app.AuthFlow,

				SourceIp = ip.Ip,
				Asn = ip.Asn,
				NetworkType = ip.NetworkType,
				IsTor = ip.IsTor,
				IpReputation = ip.IpReputation,

				Country = geo.Country,
				Region = geo.Region,
				City = geo.City,
				Latitude = geo.Lat,
				Longitude = geo.Lon,

				UserAgent = "Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/120.0",
				DeviceId = $"{_dev}{actor.Id}_{_rng.Next(1000, 9999)}",
				IsNewDevice = true,

				PolicyId = _polDefault,
				StepUpRequired = stepUp,
				MfaMethod = mfaMethod,
				MfaOutcome = mfaOutcome,
				MfaPromptCount = stepUp ? 1 : 0,

				Outcome = success ? _success : _fail,
				FailureReason = failureReason,
				RiskScore = riskScore,

				AttackType = _passwordSpray
			};
		}

		private LoginEvent GenerateTakeoverOrMfaFatigue(DateTime ts, FraudActor actor) {
			UserState victim = RandomUser();

			// 50/50: impossible travel or MFA fatigue / takeover
			bool impossibleTravel = _rng.NextDouble() < 0.50;

			GeoPoint geo = impossibleTravel
				? _geo.FarFrom(victim.Home, minKm: 3000, rng: _rng)
				: _geo.WeightedRandom(_rng, preferNorthAmerica: false);

			IpProfile ip = IpProfile.FromGeo(_rng, geo, quality: IpQuality.DatacenterBad, forceTor: _rng.NextDouble() < 0.15);

			bool stepUp = true;
			string mfaMethod = _push;

			// MFA fatigue: many prompts denied/timeout then one passed
			int prompts = 1 + _rng.Next(2, 8);
			string mfaOutcome;
			bool success;

			if (_rng.NextDouble() < 0.35d) {
				// attacker succeeds after fatigue
				mfaOutcome = _passed;
				success = true;
			} else {
				mfaOutcome = WeightedPick([_denied, _timeout, _failed], [0.55d, 0.30d, 0.15d]);
				success = false;
			}

			string failureReason = success ? string.Empty : (mfaOutcome == _denied ? _mfaDenied : _mfaFailed);

			// New device takeover signal
			string deviceId = $"{_dev}{victim.UserId}_X";
			bool isNewDevice = true;

			int baseRisk = 80;
			if (impossibleTravel)
				baseRisk += 10;
			if (ip.IsTor)
				baseRisk += 5;
			if (ip.IpReputation < 30)
				baseRisk += 5;

			int riskScore = ClampToByte(baseRisk);

			AppClient app = WeightedPick(_apps, x => x.Id == _appMobile ? 0.60 : 0.40);
			return new LoginEvent {
				TimestampUtc = ts,
				TenantId = victim.TenantId,
				UserId = victim.UserId,
				Username = victim.Username,
				UserType = victim.UserType,

				ClientId = app.Id,
				AuthFlow = app.AuthFlow,

				SourceIp = ip.Ip,
				Asn = ip.Asn,
				NetworkType = ip.NetworkType,
				IsTor = ip.IsTor,
				IpReputation = ip.IpReputation,

				Country = geo.Country,
				Region = geo.Region,
				City = geo.City,
				Latitude = geo.Lat,
				Longitude = geo.Lon,

				UserAgent = app.Id == _appMobile ? _oktaMobileAndroid : _mozillaMacos,
				DeviceId = deviceId,
				IsNewDevice = isNewDevice,

				PolicyId = victim.UserType == _admin ? _policyAdminStrict : _polDefault,
				StepUpRequired = stepUp,
				MfaMethod = mfaMethod,
				MfaOutcome = mfaOutcome,
				MfaPromptCount = prompts,

				Outcome = success ? _success : _fail,
				FailureReason = failureReason,
				RiskScore = riskScore,

				AttackType = impossibleTravel ? "ImpossibleTravel" : "MFAFatigue"
			};
		}

		private LoginEvent EnrichWithRollingFeatures(LoginEvent ev) {
			// Create a copy to avoid mutating older instances if you reuse references.
			LoginEvent x = ev.Clone();

			// Per-user rolling windows
			Deque<LoginEvent> userQ = GetQueue(_recentByUser, x.UserId);
			Deque<LoginEvent> ipQ = GetQueue(_recentByIp, x.SourceIp);

			DateTime t = x.TimestampUtc;

			// Prune windows for queries
			PruneOlderThan(userQ, t.AddHours(-24));
			PruneOlderThan(ipQ, t.AddMinutes(-10));

			// Failed attempts last 5 minutes
			x.FailedAttempts5m = userQ
				.Where(e => e.TimestampUtc >= t.AddMinutes(-5))
				.Count(e => e.Outcome == _fail);

			// Unique IPs last 10 minutes for this user
			x.UniqueIps10m = userQ
				.Where(e => e.TimestampUtc >= t.AddMinutes(-10))
				.Select(e => e.SourceIp)
				.Distinct(StringComparer.OrdinalIgnoreCase)
				.Count();

			// Unique countries last 24h for this user
			x.UniqueCountries24h = userQ
				.Select(e => e.Country)
				.Distinct(StringComparer.OrdinalIgnoreCase)
				.Count();

			// distinct usernames from this IP last 10m (spray/stuffing)
			x.DistinctUsernamesFromIp10m = ipQ
				.Select(e => e.Username)
				.Distinct(StringComparer.OrdinalIgnoreCase)
				.Count();

			// Success-after-failures: if this is success and there were >=N fails in last 10m
			int fails10m = userQ.Where(e => e.TimestampUtc >= t.AddMinutes(-10)).Count(e => e.Outcome == _fail);
			x.SuccessAfterFailures10m = x.Outcome == _success && fails10m >= 5;

			// Distance and time since last login for user
			LoginEvent? last = userQ.LastOrDefault();
			if (last is not null) {
				x.MinutesSinceLastLogin = (int)Math.Round((t - last.TimestampUtc).TotalMinutes);
				x.DistanceKmFromLastLogin = (int)Math.Round(HaversineKm(last.Latitude, last.Longitude, x.Latitude, x.Longitude));
			} else {
				x.MinutesSinceLastLogin = -1;
				x.DistanceKmFromLastLogin = 0;
			}

			return x;
		}

		private void Remember(LoginEvent ev) {
			GetQueue(_recentByUser, ev.UserId).AddLast(ev);
			GetQueue(_recentByIp, ev.SourceIp).AddLast(ev);
		}

		private UserState RandomUser() {
			int idx = _rng.Next(_userStateById.Count - 1);
			return _userStateById.Values.ElementAt(idx);
		}

		private static DateTime RandomTime(DateTime start, DateTime end) {
			double rangeSeconds = (end - start).TotalSeconds;
			double offset = RandomShared.NextDouble() * rangeSeconds;
			return start.AddSeconds(offset);
		}

		private static readonly Random RandomShared = new(42);

		private static T WeightedPick<T>(IReadOnlyList<T> items, Func<T, double> weight) {
			double total = 0;
			for (int i = 0; i < items.Count; i++)
				total += weight(items[i]);

			double r = RandomShared.NextDouble() * total;
			double acc = 0;
			for (int i = 0; i < items.Count; i++) {
				acc += weight(items[i]);
				if (r <= acc)
					return items[i];
			}
			return items[items.Count - 1];
		}

		private static string WeightedPick(IReadOnlyList<string> items, IReadOnlyList<double> weights) {
			double total = weights.Sum();
			double r = RandomShared.NextDouble() * total;
			double acc = 0;
			for (int i = 0; i < items.Count; i++) {
				acc += weights[i];
				if (r <= acc)
					return items[i];
			}
			return items[^1];
		}

		private static GeoPoint JitterGeo(GeoPoint basePoint, double maxKm) {
			// crude random jitter: small offsets in lat/lon
			double kmPerDegreeLat = 111.0;
			double kmPerDegreeLon = 111.0 * Math.Cos(basePoint.Lat * Math.PI / 180.0);

			double dLat = ((RandomShared.NextDouble() * 2) - 1) * (maxKm / kmPerDegreeLat);
			double dLon = ((RandomShared.NextDouble() * 2) - 1) * (maxKm / Math.Max(1e-6, kmPerDegreeLon));

			return basePoint with { Lat = basePoint.Lat + dLat, Lon = basePoint.Lon + dLon };
		}

		private static double HaversineKm(double lat1, double lon1, double lat2, double lon2) {
			double R = 6371.0;
			double dLat = ToRad(lat2 - lat1);
			double dLon = ToRad(lon2 - lon1);

			double a =
				(Math.Sin(dLat / 2) * Math.Sin(dLat / 2)) +
				(Math.Cos(ToRad(lat1)) * Math.Cos(ToRad(lat2)) *
				Math.Sin(dLon / 2) * Math.Sin(dLon / 2));

			double c = 2 * Math.Atan2(Math.Sqrt(a), Math.Sqrt(1 - a));
			return R * c;

			static double ToRad(double deg) => deg * Math.PI / 180.0;
		}

		private static int ClampToByte(int v) => v < 0 ? 0 : (v > 100 ? 100 : v);

		private static Deque<LoginEvent> GetQueue(Dictionary<string, Deque<LoginEvent>> map, string key) {
			if (!map.TryGetValue(key, out Deque<LoginEvent>? q)) {
				q = new Deque<LoginEvent>();
				map[key] = q;
			}
			return q;
		}

		private static void PruneOlderThan(Deque<LoginEvent> q, DateTime cutoff) {
			while (q.Count > 0 && q.PeekFirst().TimestampUtc < cutoff) {
				q.RemoveFirst();
			}
		}
	}

}
