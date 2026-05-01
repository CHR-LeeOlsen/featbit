using System.Text.Json;
using Domain.Shared;
using Infrastructure.Caches.Redis;
using StackExchange.Redis;

namespace Infrastructure.Caches;

public class RedisTokenResultCache(IRedisClient redisClient) : ITokenResultCache
{
    private const string KeyPrefix = "featbit:token-result:";

    private IDatabase Redis => redisClient.GetDatabase();

    public async Task<TokenValidationResult?> TryGetAsync(string tokenString)
    {
        var key = GetKey(tokenString);
        var value = await Redis.StringGetAsync(key);
        if (value.IsNullOrEmpty)
        {
            return null;
        }

        return JsonSerializer.Deserialize<CachedTokenResult>((string)value!) is { } cached
            ? TokenValidationResult.Ok(
                new SecretWithValue(cached.Type, cached.ProjectKey, cached.EnvId, cached.EnvKey, cached.Value),
                cached.EnvId)
            : null;
    }

    public async Task SetAsync(string tokenString, TokenValidationResult result, TimeSpan expiry)
    {
        if (!result.IsValid || result.MatchedSecret is null)
        {
            return;
        }

        var key = GetKey(tokenString);
        var secret = result.MatchedSecret;
        var cached = new CachedTokenResult
        {
            Type = secret.Type,
            ProjectKey = secret.ProjectKey,
            EnvId = secret.EnvId,
            EnvKey = secret.EnvKey,
            Value = secret.Value
        };

        var json = JsonSerializer.Serialize(cached);
        await Redis.StringSetAsync(key, json, expiry);
    }

    private static string GetKey(string tokenString)
    {
        // Use a hash of the token string as the key to avoid storing long token strings in Redis
        var hash = Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes(tokenString))).ToLowerInvariant();
        return $"{KeyPrefix}{hash}";
    }

    private sealed class CachedTokenResult
    {
        public string Type { get; set; } = string.Empty;
        public string ProjectKey { get; set; } = string.Empty;
        public Guid EnvId { get; set; }
        public string EnvKey { get; set; } = string.Empty;
        public string Value { get; set; } = string.Empty;
    }
}
