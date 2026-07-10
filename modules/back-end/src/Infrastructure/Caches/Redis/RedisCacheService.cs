using Application.Caches;
using Domain.Environments;
using Domain.FeatureFlags;
using Domain.Segments;
using Domain.Utils;
using Domain.Workspaces;
using StackExchange.Redis;

namespace Infrastructure.Caches.Redis;

public class RedisCacheService(IRedisClient redis) : ICacheService
{
    private IDatabase Redis => redis.GetDatabase();

    public async Task UpsertFlagAsync(FeatureFlag flag)
    {
        // upsert flag
        var cache = RedisCaches.Flag(flag);
        await Redis.StringSetAsync(cache.Key, cache.Value);

        // upsert index
        var index = RedisCaches.FlagIndex(flag);
        await Redis.SortedSetAddAsync(index.Key, index.Member, index.Score);
    }

    public async Task DeleteFlagAsync(Guid envId, Guid flagId)
    {
        // delete index first
        var index = RedisKeys.FlagIndex(envId);
        await Redis.SortedSetRemoveAsync(index, flagId.ToString());

        // delete cache
        var cacheKey = RedisKeys.Flag(flagId);
        await Redis.KeyDeleteAsync(cacheKey);
    }

    public async Task UpsertSegmentAsync(ICollection<Guid> envIds, Segment segment)
    {
        // upsert cache
        var cache = RedisCaches.Segment(segment);
        await Redis.StringSetAsync(cache.Key, cache.Value);

        // upsert index
        foreach (var envId in envIds)
        {
            var index = RedisCaches.SegmentIndex(envId, segment);
            await Redis.SortedSetAddAsync(index.Key, index.Member, index.Score);
        }
    }

    public async Task DeleteSegmentAsync(ICollection<Guid> envIds, Guid segmentId)
    {
        // delete index first
        foreach (var envId in envIds)
        {
            var index = RedisKeys.SegmentIndex(envId);
            await Redis.SortedSetRemoveAsync(index, segmentId.ToString());
        }

        // delete cache
        var cacheKey = RedisKeys.Segment(segmentId);
        await Redis.KeyDeleteAsync(cacheKey);
    }

    public async Task UpsertLicenseAsync(Workspace workspace)
    {
        var key = RedisKeys.License(workspace.Id);
        var value = workspace.License;

        await Redis.StringSetAsync(key, value);
    }

    public async Task UpsertSecretAsync(ResourceDescriptor resourceDescriptor, Secret secret)
    {
        var key = RedisKeys.Secret(secret.Value);

        var organization = resourceDescriptor.Organization;
        var project = resourceDescriptor.Project;
        var environment = resourceDescriptor.Environment;

        var fields = new HashEntry[]
        {
            new("type", secret.Type),
            new("organizationId", organization.Id.ToString()),
            new("organizationKey", organization.Key),
            new("projectId", project.Id.ToString()),
            new("projectKey", project.Key),
            new("envId", environment.Id.ToString()),
            new("envKey", environment.Key)
        };

        await Redis.HashSetAsync(key, fields);

        // maintain the env->secrets index so a v2 token (carrying only the envId) can
        // enumerate this env's secrets. Idempotent: SADD is a no-op if already present.
        await Redis.SetAddAsync(RedisKeys.EnvSecrets(environment.Id), secret.Value);
    }

    public async Task DeleteSecretAsync(Secret secret)
    {
        var key = RedisKeys.Secret(secret.Value);

        // remove from the env->secrets index first, then the secret hash. Redis drops the
        // set automatically once it is empty.
        if (TryGetEnvId(secret.Value, out var envId))
        {
            await Redis.SetRemoveAsync(RedisKeys.EnvSecrets(envId), secret.Value);
        }

        await Redis.KeyDeleteAsync(key);
    }

    public async Task<string> GetOrSetLicenseAsync(Guid workspaceId, Func<Task<string>> licenseGetter)
    {
        var key = RedisKeys.License(workspaceId);
        if (await Redis.KeyExistsAsync(key))
        {
            var value = await Redis.StringGetAsync(key);
            return value.ToString();
        }

        var license = await licenseGetter();
        await Redis.StringSetAsync(key, license);
        return license;
    }

    // A secret value is "{22-char header}{22-char base64url(envId)}". The env index is
    // keyed by envId, so derive it from the value when only the Secret is available
    // (e.g. on delete). Returns false for any value that is not in the expected shape.
    private static bool TryGetEnvId(string secretValue, out Guid envId)
    {
        envId = Guid.Empty;

        if (string.IsNullOrEmpty(secretValue) || secretValue.Length != 44)
        {
            return false;
        }

        try
        {
            envId = GuidHelper.Decode(secretValue[22..]);
            return envId != Guid.Empty;
        }
        catch
        {
            return false;
        }
    }
}