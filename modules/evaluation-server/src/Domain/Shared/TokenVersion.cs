namespace Domain.Shared;

public static class TokenVersion
{
    public const string V1 = "v1";
    public const string V2 = "v2";

    private const string V2Prefix = "v2.";

    public static string Detect(string tokenString)
    {
        return tokenString.StartsWith(V2Prefix, StringComparison.Ordinal) ? V2 : V1;
    }
}
