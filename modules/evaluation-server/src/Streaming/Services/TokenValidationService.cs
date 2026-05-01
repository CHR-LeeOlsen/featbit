using Domain.Shared;
using Microsoft.Extensions.Internal;
using Microsoft.Extensions.Logging;

namespace Streaming.Services;

public class TokenValidationService(
    ISystemClock systemClock,
    IStore store,
    StreamingOptions options,
    ITokenResultCache tokenCache,
    ILogger<TokenValidationService> logger) : ITokenValidator
{
    public async Task<TokenValidationResult> ValidateAsync(string tokenString)
    {
        // Check cache first — if the same token was validated before and hasn't expired, return immediately
        var cached = await tokenCache.TryGetAsync(tokenString);
        if (cached is not null)
        {
            return cached;
        }

        var hmacToken = new HmacToken(tokenString.AsSpan());

        if (!hmacToken.IsValid)
        {
            logger.LogInformation("Token validation failed. Version: v2, Reason: malformed");
            return TokenValidationResult.Failed("Invalid v2 token");
        }

        var current = systemClock.UtcNow.ToUnixTimeMilliseconds();
        var elapsed = Math.Abs(current - hmacToken.Timestamp);
        var expiryWindowMs = options.TokenExpirySeconds * 1000L;

        if (elapsed > expiryWindowMs)
        {
            logger.LogInformation("Token validation failed. Version: v2, Reason: expired");
            return TokenValidationResult.Failed("v2 token is expired");
        }

        var envId = hmacToken.EnvId;
        var secrets = await store.GetSecretsAsync(envId);
        if (secrets.Length == 0)
        {
            logger.LogInformation(
                "Token validation failed. Version: v2, Reason: secret_not_found, EnvId: {EnvId}", envId);
            return TokenValidationResult.Failed($"No secrets found for envId: {envId}");
        }

        foreach (var secret in secrets)
        {
            if (hmacToken.VerifySignature(secret.Value))
            {
                logger.LogInformation("Token validated successfully. Version: v2, Type: {Type}", secret.Type);
                var result = TokenValidationResult.Ok(secret, envId);

                // Cache the result with TTL = remaining time until token expiry
                var remainingMs = expiryWindowMs - elapsed;
                if (remainingMs > 0)
                {
                    await tokenCache.SetAsync(tokenString, result, TimeSpan.FromMilliseconds(remainingMs));
                }

                return result;
            }
        }

        logger.LogInformation("Token validation failed. Version: v2, Reason: bad_signature, EnvId: {EnvId}", envId);
        return TokenValidationResult.Failed("Invalid v2 token signature");
    }
}
