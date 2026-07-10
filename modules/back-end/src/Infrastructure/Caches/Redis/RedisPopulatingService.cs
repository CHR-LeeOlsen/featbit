using System.Diagnostics;
using Application.Caches;
using Domain.Environments;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Infrastructure.Caches.Redis;

public class RedisPopulatingService(
    IRedisClient redisClient,
    ICacheService cacheService,
    IFeatureFlagService flagService,
    ISegmentService segmentService,
    IEnvironmentService envService,
    IOptions<RedisOptions> redisOptions,
    ILogger<RedisPopulatingService> logger)
    : ICachePopulatingService
{
    private const string IsPopulatedKey = "featbit:redis-is-populated";
    private const string PopulateLockKey = "featbit:populate-redis";

    public async Task PopulateAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("Verifying redis population status on startup...");

        var lockTtl = TimeSpan.FromSeconds(redisOptions.Value.PopulateLockTtlSeconds);
        var maxWait = TimeSpan.FromSeconds(redisOptions.Value.PopulateMaxWaitSeconds);
        var pollInterval = TimeSpan.FromSeconds(2);
        var lockValue = Guid.NewGuid().ToString();

        var waitStopwatch = Stopwatch.StartNew();

        var redis = redisClient.GetDatabase();
        while (!stoppingToken.IsCancellationRequested)
        {
            if (await redis.StringGetAsync(IsPopulatedKey) == "true")
            {
                logger.LogInformation("Redis has been populated, proceeding with service startup.");
                return;
            }

            if (await redis.LockTakeAsync(PopulateLockKey, lockValue, lockTtl))
            {
                try
                {
                    // Re-check the marker inside the lock. Closes the race where another
                    // instance finished writing the marker between our StringGet above and our
                    // LockTake. Without this we'd run a redundant populate immediately after
                    // the previous instance just completed one.
                    if (await redis.StringGetAsync(IsPopulatedKey) == "true")
                    {
                        logger.LogInformation("Redis populated by another instance, proceeding with service startup.");
                        return;
                    }

                    logger.LogInformation("Start to populate redis. Lock TTL: {LockTtl}s.", lockTtl.TotalSeconds);

                    var stopwatch = Stopwatch.StartNew();
                    await PopulateFlagsAsync();
                    await PopulateSegmentAsync();
                    await PopulateSecretsAsync();

                    // mark redis as populated
                    await redis.StringSetAsync(IsPopulatedKey, "true");

                    logger.LogInformation("Populate redis finished in {Elapsed} ms.", stopwatch.ElapsedMilliseconds);
                }
                finally
                {
                    await redis.LockReleaseAsync(PopulateLockKey, lockValue);
                }

                return;
            }

            // Another instance holds the lock. Wait and retry both the marker and the lock
            // take. Instances that arrive while a populate is in progress used to silently
            // no-op here and start serving against a partially-populated Redis. Looping
            // prevents that.
            if (waitStopwatch.Elapsed > maxWait)
            {
                throw new InvalidOperationException(
                    $"Timed out waiting for another instance to finish populating Redis " +
                    $"after {maxWait.TotalSeconds} seconds. This instance will not start. " +
                    $"Investigate whether the populating instance is stuck or crashed."
                );
            }

            logger.LogInformation(
                "Another instance is populating Redis. Waiting {PollIntervalSeconds}s before " +
                "re-checking (elapsed: {ElapsedSeconds:F0}s).",
                pollInterval.TotalSeconds,
                waitStopwatch.Elapsed.TotalSeconds
            );

            await Task.Delay(pollInterval, stoppingToken);
        }
    }

    private async Task PopulateFlagsAsync()
    {
        var flags = await flagService.FindManyAsync(_ => true);
        var tasks = flags.Select(flag => cacheService.UpsertFlagAsync(flag));

        await Task.WhenAll(tasks);

        logger.LogInformation("Populate flag success, total count: {Total}", flags.Count);
    }

    private async Task PopulateSegmentAsync()
    {
        var caches = await segmentService.GetCachesAsync();
        var tasks = caches.Select(cache => cacheService.UpsertSegmentAsync(cache.EnvIds, cache.Segment));

        await Task.WhenAll(tasks);

        logger.LogInformation("Populate segment success, total count: {Total}", caches.Count);
    }

    private async Task PopulateSecretsAsync()
    {
        var caches = await envService.GetSecretCachesAsync();

        // upsert current DB secrets (the source of truth). Rebuilds each secret hash and
        // (re)adds it to its env->secrets index.
        var tasks = caches.Select(x => cacheService.UpsertSecretAsync(x.Descriptor, x.Secret));
        await Task.WhenAll(tasks);

        // populate is otherwise additive-only: it never removes entries. Reconcile against
        // the DB so secrets that were deleted or rotated while a delete event was missed
        // (e.g. the back-end was down) do not linger in Redis and keep validating tokens.
        var removed = await ReconcileSecretsAsync(caches);

        logger.LogInformation(
            "Populate secrets success, total count: {Total}, stale entries removed: {Removed}",
            caches.Count,
            removed
        );
    }

    // Removes env->secrets index members (and their backing secret hashes) that are no
    // longer present in the DB. Scans every env->secrets index key so indexes belonging to
    // fully deleted environments are cleaned up too, not just rotated secrets in live envs.
    private async Task<int> ReconcileSecretsAsync(ICollection<SecretCache> caches)
    {
        var desiredByEnv = caches
            .GroupBy(x => x.Descriptor.Environment.Id)
            .ToDictionary(
                g => g.Key,
                g => g.Select(x => x.Secret.Value).ToHashSet(StringComparer.Ordinal)
            );

        var redis = redisClient.GetDatabase();
        var removed = 0;

        foreach (var endpoint in redisClient.Connection.GetEndPoints())
        {
            var server = redisClient.Connection.GetServer(endpoint);

            // only enumerate keys from reachable primaries to avoid duplicate work and
            // failures against replicas or disconnected nodes.
            if (!server.IsConnected || server.IsReplica)
            {
                continue;
            }

            await foreach (var indexKey in server.KeysAsync(pattern: RedisKeys.EnvSecretsPattern))
            {
                if (!RedisKeys.TryParseEnvSecretsKey(indexKey, out var envId))
                {
                    continue;
                }

                desiredByEnv.TryGetValue(envId, out var desired);

                var members = await redis.SetMembersAsync(indexKey);
                foreach (var member in members)
                {
                    var value = member.ToString();
                    if (desired != null && desired.Contains(value))
                    {
                        continue;
                    }

                    // stale: remove from the index and drop the backing secret hash. Redis
                    // deletes the set automatically once its last member is removed.
                    await redis.SetRemoveAsync(indexKey, member);
                    await redis.KeyDeleteAsync(RedisKeys.Secret(value));
                    removed++;
                }
            }
        }

        return removed;
    }
}