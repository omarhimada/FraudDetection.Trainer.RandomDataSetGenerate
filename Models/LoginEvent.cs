namespace FraudDetection.Trainer.RandomDataSetGenerate.Models {
	/// <summary>
	/// Represents a record of a user login event, including authentication details, user and device information, network
	/// context, and risk assessment data.
	/// </summary>
	/// <remarks>This class is typically used to capture and analyze authentication activity for security
	/// monitoring, auditing, or risk evaluation purposes. It includes properties for tracking the outcome of the login
	/// attempt, multi-factor authentication details, geolocation, device and network characteristics, and various risk
	/// indicators. All properties are mutable to support scenarios where event data is constructed incrementally before
	/// being logged or processed.</remarks>
	public sealed class LoginEvent {
		public DateTime TimestampUtc { get; set; }
		public string TenantId { get; set; } = string.Empty;
		public string UserId { get; set; } = string.Empty;
		public string Username { get; set; } = string.Empty;
		public string UserType { get; set; } = string.Empty;

		public string ClientId { get; set; } = string.Empty;
		public string AuthFlow { get; set; } = string.Empty;

		public string SourceIp { get; set; } = string.Empty;
		public string Asn { get; set; } = string.Empty;
		public string NetworkType { get; set; } = string.Empty;
		public bool IsTor { get; set; }
		public int IpReputation { get; set; }

		public string Country { get; set; } = string.Empty;
		public string Region { get; set; } = string.Empty;
		public string City { get; set; } = string.Empty;
		public double Latitude { get; set; }
		public double Longitude { get; set; }

		public string UserAgent { get; set; } = string.Empty;
		public string DeviceId { get; set; } = string.Empty;
		public bool IsNewDevice { get; set; }

		public string PolicyId { get; set; } = string.Empty;
		public bool StepUpRequired { get; set; }
		public string MfaMethod { get; set; } = string.Empty;
		public string MfaOutcome { get; set; } = string.Empty;
		public int MfaPromptCount { get; set; }

		// Success/Fail
		public string Outcome { get; set; } = string.Empty;

		// InvalidPassword/MFADenied/etc 
		public string FailureReason { get; set; } = string.Empty;

		/// <summary>
		/// Risk score from 0 (low) to 100 (high)
		/// </summary>
		public int RiskScore { get; set; }

		// None/CredentialStuffing/...
		public string AttackType { get; set; } = string.Empty;

		// Rolling features
		public int FailedAttempts5m { get; set; }
		public int UniqueIps10m { get; set; }
		public int UniqueCountries24h { get; set; }
		public int DistinctUsernamesFromIp10m { get; set; }
		public bool SuccessAfterFailures10m { get; set; }
		public int MinutesSinceLastLogin { get; set; }
		public int DistanceKmFromLastLogin { get; set; }

		public LoginEvent Clone() => (LoginEvent)MemberwiseClone();
	}
}
