namespace Domain.Shared;

public enum TokenVersion
{
    /// <summary>Legacy secret-string token (obfuscated envelope or raw secret string).</summary>
    V1,

    /// <summary>HMAC-signed token: <c>v2.&lt;base64url-payload&gt;.&lt;base64url-signature&gt;</c>.</summary>
    V2
}

public static class TokenVersions
{
    /// <summary>
    /// Detects the token format. A token is <see cref="TokenVersion.V2"/> only when it starts with
    /// the <c>v2.</c> prefix; everything else is treated as <see cref="TokenVersion.V1"/>.
    /// </summary>
    public static TokenVersion Detect(string? token) =>
        token is not null && token.StartsWith(HmacToken.Prefix, StringComparison.Ordinal)
            ? TokenVersion.V2
            : TokenVersion.V1;
}
