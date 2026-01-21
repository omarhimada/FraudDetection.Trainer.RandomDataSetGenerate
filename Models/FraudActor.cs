namespace FraudDetection.Trainer.RandomDataSetGenerate.Models {
	/// <summary>
	/// Specifies the type of fraudulent authentication behavior detected during a security analysis.
	/// </summary>
	/// <remarks>Use this enumeration to classify and respond to different types of credential-based attacks, such
	/// as credential stuffing, password spraying, or targeted account takeover attempts. The values can be used for
	/// logging, alerting, or applying specific mitigation strategies based on the detected behavior.</remarks>
	public enum FraudBehavior { CredentialStuffing, PasswordSpray, TargetedTakeover }

	/// <summary>
	/// Represents an entity involved in fraudulent activity, identified by a unique ID and associated behavior.
	/// </summary>
	/// <param name="Id">The unique identifier for the fraud actor. Cannot be null.</param>
	/// <param name="behavior">The behavior profile associated with the fraud actor, describing the type or pattern of fraudulent activity.</param>
	public sealed record FraudActor(string Id, FraudBehavior behavior);

	/// <summary>
	/// Specifies the assessed quality of an IP address for risk evaluation or filtering purposes.
	/// </summary>
	/// <remarks>Use this enumeration to categorize IP addresses based on their trustworthiness or likelihood of
	/// being associated with undesirable sources, such as datacenters or proxies. The values can be used to inform access
	/// control, logging, or risk analysis decisions.</remarks>
	public enum IpQuality { Good, DatacenterMedium, DatacenterBad }
}
