using System.Text;
using Domain.Shared;
using Infrastructure.Caches.Redis;
using Microsoft.Extensions.Logging;
using StackExchange.Redis;

namespace Infrastructure.Store;

public class RedisStore(IRedisClient redisClient, ILogger<RedisStore> logger) : IDbStore
{
    public string Name => Stores.Redis;

    private IDatabase Redis => redisClient.GetDatabase();

    public Task<bool> IsAvailableAsync() => redisClient.IsHealthyAsync();

    public async Task<IEnumerable<byte[]>> GetFlagsAsync(Guid envId, long timestamp)
    {
        // get flag keys
        var index = RedisKeys.FlagIndex(envId);
        var ids = await Redis.SortedSetRangeByScoreAsync(index, timestamp, exclude: Exclude.Start);

        var keys = new RedisKey[ids.Length];
        for (var i = 0; i < ids.Length; i++)
        {
            keys[i] = RedisKeys.Flag(ids[i]!);
        }

        // get flags
        var tasks = new Task<RedisValue>[keys.Length];
        for (var i = 0; i < keys.Length; i++)
        {
            tasks[i] = Redis.StringGetAsync(keys[i]);
        }

        var values = await Task.WhenAll(tasks);

        return FilterOrphans(values, keys, envId, "flag");
    }

    public async Task<IEnumerable<byte[]>> GetFlagsAsync(string[] ids)
    {
        var keys = new RedisKey[ids.Length];
        for (var i = 0; i < ids.Length; i++)
        {
            keys[i] = RedisKeys.Flag(ids[i]);
        }

        var tasks = new Task<RedisValue>[keys.Length];
        for (var i = 0; i < keys.Length; i++)
        {
            tasks[i] = Redis.StringGetAsync(keys[i]);
        }

        var values = await Task.WhenAll(tasks);

        return FilterOrphans(values, keys, envId: null, "flag");
    }

    public async Task<byte[]> GetSegmentAsync(string id)
    {
        var key = RedisKeys.Segment(id);
        var segment = await Redis.StringGetAsync(key);

        return (byte[])segment!;
    }

    public async Task<IEnumerable<byte[]>> GetSegmentsAsync(Guid envId, long timestamp)
    {
        // get segment keys
        var index = RedisKeys.SegmentIndex(envId);
        var ids = await Redis.SortedSetRangeByScoreAsync(index, timestamp, exclude: Exclude.Start);
        var keys = new RedisKey[ids.Length];
        for (var i = 0; i < ids.Length; i++)
        {
            keys[i] = RedisKeys.Segment(ids[i]!);
        }

        // get segments
        var tasks = new Task<RedisValue>[keys.Length];
        for (var i = 0; i < keys.Length; i++)
        {
            tasks[i] = Redis.StringGetAsync(keys[i]);
        }

        var values = await Task.WhenAll(tasks);

        // for shared segments, replace empty envId with actual envId
        const string emptyEnvId = "\"envId\":\"\",";

        var orphans = new List<string>();
        var jsonBytes = new List<byte[]>(values.Length);
        for (var i = 0; i < values.Length; i++)
        {
            // skip orphan values
            if (!values[i].HasValue)
            {
                orphans.Add(keys[i].ToString());
                continue;
            }

            var strValue = (string)values[i]!;
            if (strValue.Contains(emptyEnvId))
            {
                var newStrValue = strValue.Replace(emptyEnvId, $"\"envId\":\"{envId}\",");
                jsonBytes.Add(Encoding.UTF8.GetBytes(newStrValue));
            }
            else
            {
                jsonBytes.Add((byte[])values[i]!);
            }
        }

        LogOrphans(orphans, values.Length, envId, "segment");

        return jsonBytes;
    }

    public async Task<Secret?> GetSecretAsync(string secretString)
    {
        var key = RedisKeys.Secret(secretString);
        if (!await Redis.KeyExistsAsync(key))
        {
            return null;
        }

        var entries = await Redis.HashGetAsync(key, new RedisValue[] { "type", "projectKey", "envId", "envKey" });
        return new Secret(
            type: entries[0].ToString(),
            entries[1].ToString(),
            Guid.Parse(entries[2].ToString()),
            entries[3].ToString()
        );
    }

    public async Task<SecretWithValue[]> GetSecretsAsync(Guid envId)
    {
        // the env->secrets index is a Redis set of the env's secret strings, maintained by the back-end
        var index = RedisKeys.EnvSecrets(envId);
        var members = await Redis.SetMembersAsync(index);
        if (members.Length == 0)
        {
            return [];
        }

        // read each secret hash to recover type/projectKey/envKey; the value is the set member itself
        var tasks = new Task<RedisValue[]>[members.Length];
        for (var i = 0; i < members.Length; i++)
        {
            tasks[i] = Redis.HashGetAsync(
                RedisKeys.Secret(members[i]!),
                new RedisValue[] { "type", "projectKey", "envKey" });
        }

        var hashes = await Task.WhenAll(tasks);

        var secrets = new List<SecretWithValue>(members.Length);
        var orphans = new List<string>();
        for (var i = 0; i < members.Length; i++)
        {
            var entries = hashes[i];

            // orphan: an index member whose backing secret hash is missing
            if (entries[0].IsNull)
            {
                orphans.Add(members[i].ToString());
                continue;
            }

            secrets.Add(new SecretWithValue(
                entries[0].ToString(),
                entries[1].ToString(),
                envId,
                entries[2].ToString(),
                members[i].ToString()
            ));
        }

        LogOrphans(orphans, members.Length, envId, "secret");

        return secrets.ToArray();
    }

    // Filters out RedisValues whose backing key was missing (HasValue == false) and logs the
    // orphan keys so operators can spot accumulating drift between an env's index and its values.
    // Without this filter, a single orphan index member produces a null byte[] that crashes
    // JsonDocument.Parse downstream and aborts the entire env's data-sync.
    private IEnumerable<byte[]> FilterOrphans(
        RedisValue[] values,
        RedisKey[] keys,
        Guid? envId,
        string entityName)
    {
        var orphans = new List<string>();
        var jsonBytes = new List<byte[]>(values.Length);
        for (var i = 0; i < values.Length; i++)
        {
            if (values[i].HasValue)
            {
                jsonBytes.Add((byte[])values[i]!);
            }
            else
            {
                orphans.Add(keys[i].ToString());
            }
        }

        LogOrphans(orphans, values.Length, envId, entityName);

        return jsonBytes;
    }

    private void LogOrphans(List<string> orphans, int totalCount, Guid? envId, string entityName)
    {
        if (orphans.Count == 0)
        {
            return;
        }

        if (envId.HasValue)
        {
            logger.LogWarning(
                "Orphan {EntityName} index members in env {EnvId}: {OrphanCount} of {TotalCount}. Missing keys: {MissingKeys}",
                entityName, envId.Value, orphans.Count, totalCount, string.Join(", ", orphans)
            );
        }
        else
        {
            logger.LogWarning(
                "Orphan {EntityName} ids requested: {OrphanCount} of {TotalCount}. Missing keys: {MissingKeys}",
                entityName, orphans.Count, totalCount, string.Join(", ", orphans)
            );
        }
    }
}