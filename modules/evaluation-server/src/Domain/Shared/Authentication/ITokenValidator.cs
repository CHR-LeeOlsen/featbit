namespace Domain.Shared.Authentication;

/// <summary>
/// Single source of truth for token validation.
/// v1: structural-only check (Secret.TryParse), no I/O.
/// v2: parses the HMAC token, reads the env's secrets from the store and verifies the signature.
/// </summary>
public interface ITokenValidator
{
    /// <summary>
    /// Validates the credential (HTTP Authorization header or streaming token secret string).
    /// v1: structural check only (Secret.TryParse), no I/O.
    /// v2: HMAC signature verification against the env's stored secrets. May throw if the store
    /// is unavailable; callers translate that to a transient failure. Expiry is enforced by callers.
    /// </summary>
    Task<TokenValidationResult> ValidateAsync(string? token, CancellationToken cancellationToken = default);
}
