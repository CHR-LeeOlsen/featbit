using StackExchange.Redis;

namespace Infrastructure.Caches.Redis;

public static class RedisKeys
{
    private const string FlagPrefix = "featbit:flag:";
    private const string FlagIndexPrefix = "featbit:flag-index:";
    private const string SegmentPrefix = "featbit:segment:";
    private const string SegmentIndexPrefix = "featbit:segment-index:";
    private const string LicensePrefix = "featbit:license:";
    private const string SecretPrefix = "featbit:secret:";
    private const string EnvSecretsPrefix = "featbit:env-secrets:";

    public static RedisKey License(Guid id) => new($"{LicensePrefix}{id}");

    public static RedisKey Flag(Guid id) => new($"{FlagPrefix}{id}");

    public static RedisKey FlagIndex(Guid envId) => new($"{FlagIndexPrefix}{envId}");

    public static RedisKey Segment(Guid id) => new($"{SegmentPrefix}{id}");

    public static RedisKey SegmentIndex(Guid envId) => new($"{SegmentIndexPrefix}{envId}");

    public static RedisKey Secret(string secretString) => new($"{SecretPrefix}{secretString}");

    // Set of an environment's secret strings. Lets a v2 token (which carries only the
    // envId) enumerate the env's secrets without an env->secrets DB lookup.
    public static RedisKey EnvSecrets(Guid envId) => new($"{EnvSecretsPrefix}{envId}");

    // Glob pattern matching every env->secrets index key. Used to enumerate all indexes
    // (including those of deleted environments) during reconciliation.
    public static string EnvSecretsPattern => $"{EnvSecretsPrefix}*";

    // Extracts the environment id embedded in an env->secrets index key. Returns false for
    // any key that does not match the expected prefix + guid shape.
    public static bool TryParseEnvSecretsKey(RedisKey key, out Guid envId)
    {
        envId = Guid.Empty;

        var value = key.ToString();
        if (value is null || !value.StartsWith(EnvSecretsPrefix, StringComparison.Ordinal))
        {
            return false;
        }

        return Guid.TryParse(value.AsSpan(EnvSecretsPrefix.Length), out envId);
    }
}