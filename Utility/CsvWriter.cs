using FraudDetection.Trainer.RandomDataSetGenerate.Models;
using System.Globalization;
using static FraudDetection.Trainer.RandomDataSetGenerate.Constants;

namespace FraudDetection.Trainer.RandomDataSetGenerate.Utility {

	/// <summary>
	/// Provides functionality to write a collection of login events to a CSV file in a standardized format.
	/// The CSV is the expected input to train a Fraud Detection model.
	/// </summary>
	/// <remarks>The CSV output includes a fixed set of columns representing various properties of each login event,
	/// such as timestamps, user information, authentication details, and risk metrics. All data is written with a header
	/// row followed by one row per event. This class is intended for exporting login event data for analysis or archival
	/// purposes.</remarks>
	public static class CsvWriter {
		public static void Write(string path, IReadOnlyList<LoginEvent> events) {
			using StreamWriter sw = new(path, append: false);

			// Header
			sw.WriteLine(string.Join(_separator,
				_timestampUtc,
				_tenantId,
				_userId,
				_username,
				_userType,
				_clientId,
				_authFlow,
				_sourceIp,
				_asn,
				_networkType,
				_isTor,
				_ipReputation,
				_country,
				_region,
				_city,
				_latitude,
				_longitude,
				_userAgent,
				_deviceId,
				_isNewDevice,
				_policyId,
				_stepUpRequired,
				_mfaMethod,
				_mfaOutcome,
				_mfaPromptCount,
				_outcome,
				_failureReason,
				_riskScore,
				_attackType,
				_failedAttempts5m,
				_uniqueIps10m,
				_uniqueCountries24h,
				_distinctUsernamesFromIp10m,
				_successAfterFailures10m,
				_minutesSinceLastLogin,
				_distanceKmFromLastLogin
			));

			foreach (LoginEvent e in events) {
				sw.WriteLine(string.Join(_separator,
					Csv(e.TimestampUtc.ToString(_o, CultureInfo.InvariantCulture)),
					Csv(e.TenantId),
					Csv(e.UserId),
					Csv(e.Username),
					Csv(e.UserType),
					Csv(e.ClientId),
					Csv(e.AuthFlow),
					Csv(e.SourceIp),
					Csv(e.Asn),
					Csv(e.NetworkType),
					e.IsTor ? _true : _false,
					e.IpReputation.ToString(CultureInfo.InvariantCulture),
					Csv(e.Country),
					Csv(e.Region),
					Csv(e.City),
					e.Latitude.ToString(_f6, CultureInfo.InvariantCulture),
					e.Longitude.ToString(_f6, CultureInfo.InvariantCulture),
					Csv(e.UserAgent),
					Csv(e.DeviceId),
					e.IsNewDevice ? _true : _false,
					Csv(e.PolicyId),
					e.StepUpRequired ? _true : _false,
					Csv(e.MfaMethod),
					Csv(e.MfaOutcome),
					e.MfaPromptCount.ToString(CultureInfo.InvariantCulture),
					Csv(e.Outcome),
					Csv(e.FailureReason),
					e.RiskScore.ToString(CultureInfo.InvariantCulture),
					Csv(e.AttackType),
					e.FailedAttempts5m.ToString(CultureInfo.InvariantCulture),
					e.UniqueIps10m.ToString(CultureInfo.InvariantCulture),
					e.UniqueCountries24h.ToString(CultureInfo.InvariantCulture),
					e.DistinctUsernamesFromIp10m.ToString(CultureInfo.InvariantCulture),
					e.SuccessAfterFailures10m ? _true : _false,
					e.MinutesSinceLastLogin.ToString(CultureInfo.InvariantCulture),
					e.DistanceKmFromLastLogin.ToString(CultureInfo.InvariantCulture)
				));
			}
		}

		/// <summary>
		/// Formats the specified string as a CSV field, escaping it if necessary according to CSV rules.
		/// </summary>
		/// <param name="s">The string to format as a CSV field. If null, an empty string is used.</param>
		/// <returns>A string formatted as a valid CSV field. If the input contains a comma, double quote, or line break, the field is
		/// enclosed in double quotes and any embedded double quotes are escaped.</returns>
		private static string Csv(string? s) {
			s ??= string.Empty;

			return s.IndexOfAny([',', '"', '\n', '\r']) >= 0
				? $"\"{s.Replace("\"", "\"\"")}\""
				: s;
		}
	}
}
