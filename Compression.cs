using System.IO.Hashing;
using System.Text;
using static FraudDetection.Trainer.RandomDataSetGenerate.Constants;

namespace FraudDetection.Trainer.RandomDataSetGenerate {
	public static class CompressionFunctions {
		public static string HashStringToUintString(string input) {
			byte[] data = Encoding.UTF8.GetBytes(input);
			// user_agent
			// e.g.:        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_2)"
			// becomes:     846327992

			// device_id
			// e.g.:        "dev_t_northwind_u0236_B"
			// becomes:     2684454613

			uint uint32 = XxHash32.HashToUInt32(data);
			return uint32.ToString();
		}


		public static string ConvertMFAOutcomeToUshort(string mfaOutcome) => mfaOutcome switch {
			_notChallenged => ((ushort)MFAOutcome.NotChallenged).ToString(),
			_passed => ((ushort)MFAOutcome.Passed).ToString(),
			_denied => ((ushort)MFAOutcome.Denied).ToString(),
			_failed => ((ushort)MFAOutcome.Failed).ToString(),
			_timeout => ((ushort)MFAOutcome.Timeout).ToString(),
			_ => string.Empty,
		};
	}

	// For conversion to ushort
	public enum MFAOutcome {
		Passed = 0,
		NotChallenged = 1,
		Failed = 2,
		Denied = 3,
		Timeout = 4
	}
}
