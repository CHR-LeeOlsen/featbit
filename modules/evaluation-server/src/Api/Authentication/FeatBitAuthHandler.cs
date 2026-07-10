using System.Security.Claims;
using System.Text.Encodings.Web;
using Domain.Shared;
using Domain.Shared.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Streaming;

namespace Api.Authentication;

/// <summary>
/// Authentication handler for FeatBit tokens.
/// v1: structural validation only (Secret.TryParse).
/// v2: HMAC signature verification against the env's stored secrets, plus expiry check.
/// A transient store failure is surfaced as a 503 challenge (not a 401) so clients retry.
/// </summary>
public class FeatBitAuthHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    Microsoft.Extensions.Internal.ISystemClock systemClock,
    StreamingOptions streamingOptions,
    ITokenValidator tokenValidator)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    private const string StoreUnavailableItemKey = "featbit:token-store-unavailable";

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var token = Request.Headers.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(token))
        {
            return AuthenticateResult.NoResult();
        }

        TokenValidationResult result;
        try
        {
            result = await tokenValidator.ValidateAsync(token);
        }
        catch (Exception ex)
        {
            // v2 store lookup failed → transient. Flag it so the challenge returns 503, not 401.
            Context.Items[StoreUnavailableItemKey] = true;
            return AuthenticateResult.Fail(ex);
        }

        if (result.Status != TokenValidationStatus.Valid)
        {
            return AuthenticateResult.Fail(result.Reason);
        }

        // v2 tokens carry a timestamp — enforce expiry (v1 tokens have no timestamp).
        if (result.Version == TokenVersion.V2)
        {
            var current = systemClock.UtcNow.ToUnixTimeMilliseconds();
            if (Math.Abs(current - result.Timestamp) > streamingOptions.TokenExpirySeconds * 1000)
            {
                return AuthenticateResult.Fail("Token is expired");
            }
        }

        var claims = new List<Claim>
        {
            new(FeatBitClaims.EnvId, result.EnvId.ToString())
        };

        if (result.Secret is not null)
        {
            claims.Add(new Claim(FeatBitClaims.SecretType, result.Secret.Type));
            claims.Add(new Claim(FeatBitClaims.ProjectKey, result.Secret.ProjectKey));
            claims.Add(new Claim(FeatBitClaims.EnvKey, result.Secret.EnvKey));
        }

        var identity = new ClaimsIdentity(claims, Scheme.Name);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);

        return AuthenticateResult.Success(ticket);
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        // Distinguish a transient store failure (503) from an invalid/missing token (401).
        Response.StatusCode = Context.Items.ContainsKey(StoreUnavailableItemKey)
            ? StatusCodes.Status503ServiceUnavailable
            : StatusCodes.Status401Unauthorized;
        return Task.CompletedTask;
    }
}