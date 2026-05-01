using Domain.Shared;
using Microsoft.Extensions.Caching.Memory;

namespace Infrastructure.Caches;

public class MemoryTokenResultCache(MemoryCache cache) : ITokenResultCache
{
    public Task<TokenValidationResult?> TryGetAsync(string tokenString)
    {
        cache.TryGetValue(tokenString, out TokenValidationResult? result);
        return Task.FromResult(result);
    }

    public Task SetAsync(string tokenString, TokenValidationResult result, TimeSpan expiry)
    {
        var options = new MemoryCacheEntryOptions
        {
            Size = 1,
            AbsoluteExpirationRelativeToNow = expiry
        };
        cache.Set(tokenString, result, options);
        return Task.CompletedTask;
    }
}
