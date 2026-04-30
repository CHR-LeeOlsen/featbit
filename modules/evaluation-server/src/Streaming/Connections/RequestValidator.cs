using System.Net.WebSockets;
using Domain.Shared;
using Microsoft.Extensions.Internal;
using Microsoft.Extensions.Logging;
using Streaming.Services;

namespace Streaming.Connections;

public sealed class RequestValidator(
    ISystemClock systemClock,
    IStore store,
    StreamingOptions options,
    IRelayProxyService rpService,
    ILogger<RequestValidator> logger)
    : IRequestValidator
{
    public async Task<ValidationResult> ValidateAsync(ConnectionContext context)
    {
        try
        {
            return await ValidateCoreAsync(context);
        }
        catch (Exception ex)
        {
            logger.ErrorValidateRequest(context.RawQuery, ex);

            // throw original exception
            throw;
        }
    }

    private async Task<ValidationResult> ValidateCoreAsync(ConnectionContext context)
    {
        var (ws, type, version, tokenString) = context;

        // connection type
        if (!options.SupportedTypes.Contains(type))
        {
            return ValidationResult.Failed($"Invalid type: {type}");
        }

        // connection version
        if (!options.SupportedVersions.Contains(version))
        {
            return ValidationResult.Failed($"Invalid version: {version}");
        }

        // websocket state
        if (ws is not { State: WebSocketState.Open })
        {
            return ValidationResult.Failed($"Invalid websocket state: {ws?.State}");
        }

        return type == ConnectionType.RelayProxy
            ? await ValidateRelayProxyAsync()
            : await ValidateSecretTokenAsync();

        async Task<ValidationResult> ValidateRelayProxyAsync()
        {
            var serverSecrets = await rpService.GetServerSecretsAsync(tokenString);
            return serverSecrets.Length == 0
                ? ValidationResult.Failed($"Invalid relay proxy token: {tokenString}")
                : ValidationResult.Ok(serverSecrets);
        }

        async Task<ValidationResult> ValidateSecretTokenAsync()
        {
            return TokenVersion.Detect(tokenString) == TokenVersion.V2
                ? await ValidateV2TokenAsync()
                : await ValidateV1TokenAsync();
        }

        async Task<ValidationResult> ValidateV1TokenAsync()
        {
            var token = new Token(tokenString.AsSpan());
            var current = systemClock.UtcNow.ToUnixTimeMilliseconds();
            if (!token.IsValid)
            {
                logger.LogInformation("Token validation failed. Version: v1, Reason: malformed, Token: {Token}", tokenString);
                return ValidationResult.Failed($"Invalid token: {tokenString}");
            }

            if (Math.Abs(current - token.Timestamp) > options.TokenExpirySeconds * 1000)
            {
                logger.LogInformation("Token validation failed. Version: v1, Reason: expired, Token: {Token}", tokenString);
                return ValidationResult.Failed($"Token is expired: {tokenString}");
            }

            var secret = await store.GetSecretAsync(token.SecretString);
            if (secret is null)
            {
                logger.LogInformation("Token validation failed. Version: v1, Reason: secret_not_found, Secret: {Secret}", token.SecretString);
                return ValidationResult.Failed($"Secret is not found: {token.SecretString}");
            }

            if (secret.Type != type)
            {
                logger.LogInformation("Token validation failed. Version: v1, Reason: type_mismatch, SecretType: {SecretType}, RequestType: {RequestType}", secret.Type, type);
                return ValidationResult.Failed($"Inconsistent secret used: {secret.Type}. Request type: {type}");
            }

            logger.LogInformation("Token validated successfully. Version: v1");
            return ValidationResult.Ok([secret]);
        }

        async Task<ValidationResult> ValidateV2TokenAsync()
        {
            var hmacToken = new HmacToken(tokenString.AsSpan());
            var current = systemClock.UtcNow.ToUnixTimeMilliseconds();

            if (!hmacToken.IsValid)
            {
                logger.LogInformation("Token validation failed. Version: v2, Reason: malformed, Token: {Token}", tokenString);
                return ValidationResult.Failed($"Invalid v2 token: {tokenString}");
            }

            if (Math.Abs(current - hmacToken.Timestamp) > options.TokenExpirySeconds * 1000)
            {
                logger.LogInformation("Token validation failed. Version: v2, Reason: expired, Token: {Token}", tokenString);
                return ValidationResult.Failed($"v2 token is expired: {tokenString}");
            }

            var secret = await store.GetSecretAsync(hmacToken.SecretString);
            if (secret is null)
            {
                logger.LogInformation("Token validation failed. Version: v2, Reason: secret_not_found, Secret: {Secret}", hmacToken.SecretString);
                return ValidationResult.Failed($"Secret is not found: {hmacToken.SecretString}");
            }

            if (!hmacToken.VerifySignature())
            {
                logger.LogInformation("Token validation failed. Version: v2, Reason: bad_signature, Secret: {Secret}", hmacToken.SecretString);
                return ValidationResult.Failed($"Invalid v2 token signature: {tokenString}");
            }

            if (secret.Type != type)
            {
                logger.LogInformation("Token validation failed. Version: v2, Reason: type_mismatch, SecretType: {SecretType}, RequestType: {RequestType}", secret.Type, type);
                return ValidationResult.Failed($"Inconsistent secret used: {secret.Type}. Request type: {type}");
            }

            logger.LogInformation("Token validated successfully. Version: v2");
            return ValidationResult.Ok([secret]);
        }
    }
}