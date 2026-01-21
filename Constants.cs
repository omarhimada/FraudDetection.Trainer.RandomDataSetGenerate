namespace FraudDetection.Trainer.RandomDataSetGenerate {
	/// <summary>
	/// Provides constant values used throughout the application for output formatting, synthetic login event generation,
	/// CSV column names, geolocation data, authentication flows, and related identifiers.
	/// </summary>
	/// <remarks>This class contains string and character constants intended for internal use, such as standard
	/// output messages, CSV formatting options, field names, and sample data values. These constants help ensure
	/// consistency and reduce duplication across the application's logic for generating and processing synthetic login
	/// events, especially in fraud detection and model training scenarios.</remarks>
	internal static class Constants {
		#region Output related
		internal const string _ansiReset = "\u001b[0m";
		internal const string _programStartGenerating = "Generating random synthetic login events for fraud detection model training...";
		internal const string _wroteText = "Wrote ";
		internal const string _writingToCsv = "Wrinting to CSV.";
		internal const string _finishText = "Done. Press any key to exit.";
		internal const string _csvLocation = "Located: ";
		internal const string _elapsed = "Elapsed (seconds): ";
		internal const string _loginEventsCsvName = "login_events.csv";
		internal const string _eventsGeneratedStringFormat = "N0";
		internal const string _generatedText = "Random synthetic login events generated: ";
		internal static readonly string _loginEventsCsvPrefix = $"{DateTime.UtcNow.ToString("yyyyMMddHHmmss_")}";
		#endregion

		internal const string _polDefault = "pol_default";
		internal const string _utcEndStartVerify = "UTC End must be after UTC Start.";

		#region Synthetic login generator
		internal const string _example = ".example";

		#region CSV
		internal const char _separator = ',';
		internal const string _f6 = "F6";
		internal const string _o = "O";

		internal const string _true = "true";
		internal const string _false = "false";
		#region CSV columns
		internal const string _timestampUtc = "timestamp_utc";
		internal const string _tenantId = "tenant_id";
		internal const string _userId = "user_id";
		internal const string _username = "username";
		internal const string _userType = "user_type";
		internal const string _clientId = "client_id";
		internal const string _authFlow = "auth_flow";
		internal const string _sourceIp = "source_ip";

		internal const string _message = "Unknown IP Quality";

		internal const string _asn = "asn";
		internal const string _networkType = "network_type";
		internal const string _isTor = "is_tor";
		internal const string _ipReputation = "ip_reputation";
		internal const string _country = "country";
		internal const string _region = "region";
		internal const string _city = "city";
		internal const string _latitude = "latitude";
		internal const string _longitude = "longitude";
		internal const string _userAgent = "user_agent";
		internal const string _deviceId = "device_id";
		internal const string _isNewDevice = "is_new_device";
		internal const string _policyId = "policy_id";
		internal const string _stepUpRequired = "step_up_required";
		internal const string _mfaMethod = "mfa_method";
		internal const string _mfaOutcome = "mfa_outcome";
		internal const string _mfaPromptCount = "mfa_prompt_count";
		internal const string _outcome = "outcome";
		internal const string _failureReason = "failure_reason";
		internal const string _riskScore = "risk_score";
		internal const string _attackType = "attack_type";
		internal const string _failedAttempts5m = "failed_attempts_5m";
		internal const string _uniqueIps10m = "unique_ips_10m";
		internal const string _uniqueCountries24h = "unique_countries_24h";
		internal const string _distinctUsernamesFromIp10m = "distinct_usernames_from_ip_10m";
		internal const string _successAfterFailures10m = "success_after_failures_10m";
		internal const string _minutesSinceLastLogin = "minutes_since_last_login";
		internal const string _distanceKmFromLastLogin = "distance_km_from_last_login";
		#endregion
		#endregion



		#region Geolocation Information
		internal const string _ca = "CA";
		internal const string _on = "ON";
		internal const string _toronto = "Toronto";

		internal const string _us = "US";
		internal const string _ca_us = "CA";
		internal const string _sanFrancisco = "San Francisco";
		internal const string _ny = "NY";
		internal const string _newYork = "New York";
		internal const string _wa = "WA";
		internal const string _seattle = "Seattle";

		internal const string _bc = "BC";
		internal const string _vancouver = "Vancouver";

		internal const string _gb = "GB";
		internal const string _eng = "ENG";
		internal const string _London = "London";

		internal const string _de = "DE";
		internal const string _be = "BE";
		internal const string _berlin = "Berlin";

		internal const string _fr = "FR";
		internal const string _idf = "IDF";
		internal const string _paris = "Paris";

		internal const string _in = "IN";
		internal const string _mh = "MH";
		internal const string _mumbai = "Mumbai";

		internal const string _sg = "SG";
		internal const string _singapore = "Singapore";

		internal const string _br = "BR";
		internal const string _sp = "SP";
		internal const string _saoPaulo = "São Paulo";

		internal const string _za = "ZA";
		internal const string _gp = "GP";
		internal const string _johannesburg = "Johannesburg";

		internal const string _jp = "JP";
		internal const string _tokyo = "Tokyo";
		internal const string _urbanCore = "UC";

		internal const string _au = "AU";
		internal const string _nsw = "NSW";
		internal const string _sydney = "Sydney";

		internal const string _ru = "RU";
		internal const string _mow = "MOW";
		internal const string _moscow = "Moscow";
		#endregion

		#region Auth-related
		internal const string _authorizatioeCode = "authorization_code";
		internal const string _clientCredentials = "client_credentials";
		internal const string _dev = "dev_";
		internal const string _a = "_A";
		internal const string _loginEvents = "login_events.csv";
		internal const string _admin = "admin";
		internal const string _user = "user";
		internal const string _customer = "customer";

		internal const string _policyAdminStrict = "pol_admin_strict";

		internal const string _none = "None";
		internal const string _push = "Push";
		internal const string _totp = "TOTP";
		internal const string _webAuthn = "WebAuthn";

		internal const string _passed = "Passed";
		internal const string _notChallenged = "NotChallenged";
		internal const string _denied = "Denied";
		internal const string _timeout = "Timeout";
		internal const string _failed = "Failed";

		internal const string _success = "Success";
		internal const string _fail = "Fail";

		internal const string _invalidPassword = "InvalidPassword";
		internal const string _mfaDenied = "MFADenied";
		internal const string _mfaFailed = "MFAFailed";

		internal const string _noneAttack = _none;
		internal const string _credentialStuffing = "CredentialStuffing";
		internal const string _passwordSpray = "PaswordSpray";
		internal const string _impossibleTravel = "ImpossibleTravel";
		internal const string _mkfaFatigue = "MFAFatigue";

		internal const string _residential = "residential";
		internal const string _mobile = "mobile";
		internal const string _datacenter = "datacenter";

		internal const string _acmeCo = "AcmeCo";
		internal const string _zephyrLtd = "ZephyrLtd";
		internal const string _northwind = "Northwind";
		internal const string _webApp = "WebApp";

		internal const string _pythonRequests = "python-requests/2.31";
		internal const string _oktaMobileIos = "okta-mobile/6.2 (iOS)";
		internal const string _oktaMobileAndroid = "okta-mobile/6.2 (Android)";
		internal const string _mozillaWindows = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
		internal const string _mozillaLinuxHeadless = "Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/120.0";
		internal const string _mozillaMacos = "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_2)";

		internal const string _tAcme = "t_acme";
		internal const string _tZephyr = "t_zephyr";
		internal const string _tNorthwind = "t_northwind";

		internal const string _appWeb = "app_web";
		internal const string _appMobile = "app_mobile";
		internal const string _appApi = "app_api";

		internal const string _mobileApp = "MobileApp";
		internal const string _serviceApi = "ServiceApi";

		internal const string _fraudStuffing01 = "fraud_stuffing_01";
		internal const string _fraudSpray01 = "fraud_spray_01";
		internal const string _fraudTakeover01 = "fraud_takeover_01";
		internal const string _as = "AS";
		#endregion
		#endregion
	}
}
