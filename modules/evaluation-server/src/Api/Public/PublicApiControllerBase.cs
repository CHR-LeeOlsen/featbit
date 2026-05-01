using Microsoft.AspNetCore.Mvc;

namespace Api.Public;

[ApiController]
[Route("api/public/[controller]")]
[ServiceFilter(typeof(TokenAuthFilter))]
public class PublicApiControllerBase : ControllerBase
{
    protected Guid EnvId =>
        HttpContext.Items.TryGetValue(TokenAuthFilter.EnvIdKey, out var value) && value is Guid id
            ? id
            : Guid.Empty;

    protected bool Authenticated => EnvId != Guid.Empty;
}