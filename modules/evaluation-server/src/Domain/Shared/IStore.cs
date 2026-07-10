namespace Domain.Shared;

public interface IStore
{
    string Name { get; }

    Task<bool> IsAvailableAsync();

    Task<IEnumerable<byte[]>> GetFlagsAsync(Guid envId, long timestamp);

    Task<IEnumerable<byte[]>> GetFlagsAsync(string[] ids);

    Task<byte[]> GetSegmentAsync(string id);

    Task<IEnumerable<byte[]>> GetSegmentsAsync(Guid envId, long timestamp);

    Task<Secret?> GetSecretAsync(string secretString);

    // Returns all secrets (with their values) for an environment. Used by v2 HMAC token
    // validation, which carries only the envId and must enumerate the env's secrets to
    // find the one whose value produces a matching signature.
    Task<SecretWithValue[]> GetSecretsAsync(Guid envId);
}

public interface IDbStore : IStore;