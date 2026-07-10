using Domain.Shared;
using Domain.Shared.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Internal;
using Microsoft.Extensions.Logging;
using Streaming.Services;

namespace Streaming.Connections;

/// <summary>
/// Validates streaming requests pre-accept (before accepting the WebSocket).
/// v1: structural validation (type, version, token parse) and store lookup with fallback handling.
/// v2: HMAC signature verification (via ITokenValidator) plus expiry and secret-type checks.
/// </summary>
public sealed class RequestValidator(
    ISystemClock systemClock,
    IStore store,
    StreamingOptions options,
    IRelayProxyService rpService,
    ITokenValidator tokenValidator,
    ILogger<RequestValidator> logger)
    : IRequestValidator
{
    public async Task<ValidationResult> ValidateAsync(HttpContext httpContext)
    {
        try
        {
            return await ValidateCoreAsync(httpContext);
        }
        catch (Exception ex)
        {
            var query = httpContext.Request.QueryString.Value ?? string.Empty;
            logger.ErrorValidateRequest(query, ex);

            // Unexpected exception that escaped inner catches — treat as permanent rejection
            // (store/relay unavailability is already caught and returned as Unavailable by inner handlers)
            return ValidationResult.Invalid($"Malformed request: {ex.Message}");
        }
    }

    private async Task<ValidationResult> ValidateCoreAsync(HttpContext httpContext)
    {
        var query = httpContext.Request.Query;
        var type = query["type"].ToString();
        var version = query["version"].ToString();
        var tokenString = query["token"].ToString();

        // connection type
        if (!options.SupportedTypes.Contains(type))
        {
            return ValidationResult.Invalid($"Invalid type: {type}");
        }

        // connection version
        if (!options.SupportedVersions.Contains(version))
        {
            return ValidationResult.Invalid($"Invalid version: {version}");
        }

        if (string.IsNullOrWhiteSpace(tokenString))
        {
            return ValidationResult.Invalid("Missing token");
        }

        return type == ConnectionType.RelayProxy
            ? await ValidateRelayProxyAsync()
            : await ValidateSecretTokenAsync();

        async Task<ValidationResult> ValidateRelayProxyAsync()
        {
            try
            {
                var serverSecrets = await rpService.GetServerSecretsAsync(tokenString);
                return serverSecrets.Length == 0
                    ? ValidationResult.Invalid($"Invalid relay proxy token: {tokenString}")
                    : ValidationResult.Valid(serverSecrets);
            }
            catch (Exception ex)
            {
                logger.ErrorLookupRelayProxyToken(tokenString, ex);

                // Store unavailable → return Unavailable for transient retry
                return ValidationResult.Unavailable($"RelayProxy validation unavailable: {ex.Message}");
            }
        }

        Task<ValidationResult> ValidateSecretTokenAsync()
        {
            // v2 tokens are the raw "v2.…" string (not the v1 obfuscated envelope), so branch
            // on version before attempting to parse the v1 Token envelope.
            return TokenVersions.Detect(tokenString) == TokenVersion.V2
                ? ValidateV2TokenAsync()
                : ValidateV1TokenAsync();
        }

        async Task<ValidationResult> ValidateV2TokenAsync()
        {
            TokenValidationResult result;
            try
            {
                // v2: HMAC signature verification against the env's stored secrets (store lookup)
                result = await tokenValidator.ValidateAsync(tokenString);
            }
            catch (Exception ex)
            {
                logger.ErrorLookupSecretToken(tokenString, ex);

                // Store unavailable → return Unavailable for transient retry
                return ValidationResult.Unavailable($"Secret lookup unavailable: {ex.Message}");
            }

            if (result.Status == TokenValidationStatus.Invalid || result.Secret is null)
            {
                return ValidationResult.Invalid($"Invalid token: {tokenString}");
            }

            var current = systemClock.UtcNow.ToUnixTimeMilliseconds();
            if (Math.Abs(current - result.Timestamp) > options.TokenExpirySeconds * 1000)
            {
                return ValidationResult.Invalid($"Token is expired: {tokenString}");
            }

            if (result.Secret.Type != type)
            {
                return ValidationResult.Invalid($"Inconsistent secret used: {result.Secret.Type}. Request type: {type}");
            }

            return ValidationResult.Valid([result.Secret]);
        }

        async Task<ValidationResult> ValidateV1TokenAsync()
        {
            Token token;
            TokenValidationResult structuralValidation;
            try
            {
                // Validate token envelope first (timestamp + encoded secret payload)
                token = new Token(tokenString.AsSpan());

                if (!token.IsValid)
                {
                    return ValidationResult.Invalid($"Invalid token: {tokenString}");
                }

                // v1: structural-only validation of the parsed secret string
                structuralValidation = await tokenValidator.ValidateAsync(token.SecretString);
            }
            catch (Exception ex)
            {
                logger.FailedToParseToken(tokenString, ex);

                return ValidationResult.Invalid($"Invalid token: {tokenString}");
            }

            if (structuralValidation.Status == TokenValidationStatus.Invalid)
            {
                return ValidationResult.Invalid($"Invalid token: {structuralValidation.Reason}");
            }

            var current = systemClock.UtcNow.ToUnixTimeMilliseconds();
            if (Math.Abs(current - token.Timestamp) > options.TokenExpirySeconds * 1000)
            {
                return ValidationResult.Invalid($"Token is expired: {tokenString}");
            }

            // Store lookup with fallback handling (wrap in try/catch)
            try
            {
                var secret = await store.GetSecretAsync(token.SecretString);
                if (secret is null)
                {
                    return ValidationResult.Invalid($"Secret is not found: {token.SecretString}");
                }

                if (secret.Type != type)
                {
                    return ValidationResult.Invalid($"Inconsistent secret used: {secret.Type}. Request type: {type}");
                }

                return ValidationResult.Valid([secret]);
            }
            catch (Exception ex)
            {
                logger.ErrorLookupSecretToken(token.SecretString, ex);

                // Store unavailable → return Unavailable for transient retry
                return ValidationResult.Unavailable($"Secret lookup unavailable: {ex.Message}");
            }
        }
    }
}