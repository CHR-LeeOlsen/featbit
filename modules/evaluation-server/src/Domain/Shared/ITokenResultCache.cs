namespace Domain.Shared;

public interface ITokenResultCache
{
    Task<TokenValidationResult?> TryGetAsync(string tokenString);

    Task SetAsync(string tokenString, TokenValidationResult result, TimeSpan expiry);
}
