using Domain.Shared;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Api.Public;

/// <summary>
/// Action filter that validates the Authorization header for public API endpoints.
/// Supports both v1 (raw secret) and v2 (HMAC token) formats.
/// Stores the resolved EnvId in <see cref="HttpContext.Items"/> for downstream use.
/// </summary>
public sealed class TokenAuthFilter(ITokenValidator tokenValidator) : IAsyncActionFilter
{
    internal const string EnvIdKey = "AuthenticatedEnvId";

    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        string? authorization = context.HttpContext.Request.Headers.Authorization;
        if (!string.IsNullOrEmpty(authorization))
        {
            if (TokenVersion.Detect(authorization) == TokenVersion.V2)
            {
                var result = await tokenValidator.ValidateAsync(authorization);
                if (result.IsValid)
                {
                    context.HttpContext.Items[EnvIdKey] = result.EnvId;
                }
            }
            else if (Secret.TryParse(authorization, out var envId))
            {
                context.HttpContext.Items[EnvIdKey] = envId;
            }
        }

        await next();
    }
}
