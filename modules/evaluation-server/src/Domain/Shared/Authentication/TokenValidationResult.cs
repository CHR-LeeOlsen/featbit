namespace Domain.Shared.Authentication;

public sealed class TokenValidationResult
{
    public TokenValidationStatus Status { get; }
    public Guid EnvId { get; }
    public string Reason { get; }

    /// <summary>The token format that was validated. Defaults to <see cref="TokenVersion.V1"/>.</summary>
    public TokenVersion Version { get; }

    /// <summary>The matched secret for a valid v2 token; null for v1 structural results.</summary>
    public Secret? Secret { get; }

    /// <summary>The token timestamp (unix ms) for v2; 0 for v1. Callers use it for expiry checks.</summary>
    public long Timestamp { get; }

    private TokenValidationResult(
        TokenValidationStatus status,
        Guid envId,
        string reason,
        TokenVersion version = TokenVersion.V1,
        Secret? secret = null,
        long timestamp = 0)
    {
        Status = status;
        EnvId = envId;
        Reason = reason;
        Version = version;
        Secret = secret;
        Timestamp = timestamp;
    }

    public static TokenValidationResult Valid(Guid envId) =>
        new(TokenValidationStatus.Valid, envId, string.Empty);

    public static TokenValidationResult Valid(Guid envId, Secret secret, long timestamp) =>
        new(TokenValidationStatus.Valid, envId, string.Empty, TokenVersion.V2, secret, timestamp);

    public static TokenValidationResult Invalid(string reason) =>
        new(TokenValidationStatus.Invalid, Guid.Empty, reason);
}