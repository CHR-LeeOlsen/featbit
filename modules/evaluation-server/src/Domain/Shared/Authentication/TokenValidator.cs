namespace Domain.Shared.Authentication;

/// <summary>
/// Single source of truth for token validation.
/// v1: structural-only check (<see cref="Secret.TryParse"/>), no I/O.
/// v2: parses the HMAC token, reads the env's secrets from the store and verifies the signature
/// (constant-time). Expiry is enforced by the caller. Store failures propagate as exceptions so
/// callers can distinguish "store down" from "token invalid".
/// </summary>
public class TokenValidator(IStore store) : ITokenValidator
{
    public async Task<TokenValidationResult> ValidateAsync(string? token, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return TokenValidationResult.Invalid("Missing or empty token");
        }

        return TokenVersions.Detect(token) == TokenVersion.V2
            ? await ValidateV2Async(token)
            : ValidateV1(token);
    }

    private static TokenValidationResult ValidateV1(string token)
    {
        return Secret.TryParse(token, out var envId)
            ? TokenValidationResult.Valid(envId)
            : TokenValidationResult.Invalid("Invalid token format");
    }

    private async Task<TokenValidationResult> ValidateV2Async(string token)
    {
        var hmacToken = new HmacToken(token.AsSpan());
        if (!hmacToken.IsValid)
        {
            return TokenValidationResult.Invalid("Invalid token format");
        }

        // Read all secrets for the env (Redis-backed permanent replica) and match the signature.
        // Throws if the store is unavailable; callers translate that to 503 (HTTP) / Unavailable (streaming).
        var secrets = await store.GetSecretsAsync(hmacToken.EnvId);
        foreach (var secret in secrets)
        {
            if (hmacToken.VerifySignature(secret.Value))
            {
                return TokenValidationResult.Valid(hmacToken.EnvId, secret.AsSecret(), hmacToken.Timestamp);
            }
        }

        return TokenValidationResult.Invalid("Invalid v2 token signature");
    }
}
