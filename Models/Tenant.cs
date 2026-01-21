namespace FraudDetection.Trainer.RandomDataSetGenerate.Models {
	/// <summary>
	/// Represents a tenant with a unique identifier and display name.
	/// </summary>
	/// <param name="Id">The unique identifier for the tenant. Cannot be null or empty.</param>
	/// <param name="Name">The display name of the tenant. Cannot be null or empty.</param>
	public sealed record Tenant(string Id, string Name);

	/// <summary>
	/// Represents an application client with a unique identifier, display name, and authentication flow configuration.
	/// </summary>
	/// <param name="Id">The unique identifier for the application client. Cannot be null.</param>
	/// <param name="Name">The display name of the application client. Cannot be null.</param>
	/// <param name="AuthFlow">The authentication flow type used by the client. Cannot be null.</param>
	public sealed record AppClient(string Id, string Name, string AuthFlow);

	/// <summary>
	/// Represents the immutable state of a user, including identity, type, home location, and primary device information.
	/// </summary>
	/// <param name="TenantId">The unique identifier of the tenant to which the user belongs. Cannot be null or empty.</param>
	/// <param name="UserId">The unique identifier of the user within the tenant. Cannot be null or empty.</param>
	/// <param name="Username">The display name or login name of the user. Cannot be null or empty.</param>
	/// <param name="UserType">The type or role of the user, such as 'admin', 'member', or 'guest'. Cannot be null or empty.</param>
	/// <param name="Home">The geographic location representing the user's home. Cannot be null.</param>
	/// <param name="PrimaryDeviceId">The unique identifier of the user's primary device. Cannot be null or empty.</param>
	public sealed record UserState(
		string TenantId,
		string UserId,
		string Username,
		string UserType,
		GeoPoint Home,
		string PrimaryDeviceId
	);
}
