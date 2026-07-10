using System.Security.Claims;
using Domain.Shared;

namespace Api.Authentication;

/// <summary>
/// Authorization policy names and secret-type matching for FeatBit HTTP endpoints.
/// Mirrors the secret-type check the streaming path enforces in
/// <c>RequestValidator</c>: a server endpoint must be called with a server secret and
/// a client endpoint with a client secret.
/// </summary>
public static class FeatBitAuthorizationPolicies
{
    /// <summary>Requires the caller to authenticate with a server-side secret.</summary>
    public const string ServerSecret = "featbit:server-secret";

    /// <summary>Requires the caller to authenticate with a client-side secret.</summary>
    public const string ClientSecret = "featbit:client-secret";

    /// <summary>
    /// Returns true when the principal is allowed to use an endpoint that requires
    /// <paramref name="requiredType"/>.
    /// v2 (HMAC) tokens carry a <see cref="FeatBitClaims.SecretType"/> claim (resolved from the
    /// store during signature verification) — that claim must match the required type.
    /// v1 tokens are validated structurally on the HTTP path and carry no secret-type claim, so
    /// they are not restricted here (that pre-existing v1 gap is out of scope for this check).
    /// </summary>
    public static bool MatchesSecretType(ClaimsPrincipal user, string requiredType)
    {
        var secretType = user.FindFirst(FeatBitClaims.SecretType)?.Value;
        return secretType is null || secretType == requiredType;
    }
}
