namespace Domain.Shared;

public interface ITokenValidator
{
    Task<TokenValidationResult> ValidateAsync(string tokenString);
}

public sealed class TokenValidationResult
{
    public bool IsValid { get; init; }

    public string Reason { get; init; } = string.Empty;

    public SecretWithValue? MatchedSecret { get; init; }

    public Guid EnvId { get; init; }

    public static TokenValidationResult Ok(SecretWithValue matchedSecret, Guid envId) => new()
    {
        IsValid = true,
        MatchedSecret = matchedSecret,
        EnvId = envId
    };

    public static TokenValidationResult Failed(string reason) => new()
    {
        IsValid = false,
        Reason = reason
    };
}
