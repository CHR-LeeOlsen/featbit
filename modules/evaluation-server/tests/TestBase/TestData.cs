using Domain.Shared;
using System.Security.Cryptography;
using System.Text;

namespace TestBase;

/// <summary>
/// Test-side aggregator for fake-mode constants. Forwards the production seed values from
/// <see cref="FakeSeedData"/> and adds the test-only <see cref="Token"/> instances and
/// token strings that tests use to drive the streaming/HTTP entry points.
/// </summary>
public static class TestData
{
    // ---- Forwarded production seed values ----

    public static Guid ClientEnvId => FakeSeedData.ClientEnvId;
    public static Secret ClientSecret => FakeSeedData.ClientSecret;
    public const string ClientSecretString = FakeSeedData.ClientSecretString;

    public static Guid ServerEnvId => FakeSeedData.ServerEnvId;
    public static Secret ServerSecret => FakeSeedData.ServerSecret;
    public const string ServerSecretString = FakeSeedData.ServerSecretString;

    public const string RelayProxyTokenString = FakeSeedData.RelayProxyTokenString;

    // ---- Test-only token fixtures ----

    public const string ClientTokenString = "QWSBHgpnOV3wI3kKAO9q9viC0wQWQQBDDDQBZWPXDQSdKZrVAf2U6gAnxl4lSH3w";

    public static readonly Token ClientToken = new()
    {
        Position = 23,
        ContentLength = 15,
        Timestamp = 1666018247603,
        SecretString = ClientSecretString,
        IsValid = true
    };

    public const string ServerTokenString = "QBPBHv3faJy3RCUO8d-QQBDDDQBZZQQXHPEJiVdN6waRfGjfNan02Ms9c0LiTD6w";

    public static readonly Token ServerToken = new()
    {
        Position = 14,
        ContentLength = 15,
        Timestamp = 1666018800754,
        SecretString = ServerSecretString,
        IsValid = true
    };

    // ---- Test-only v2 (HMAC) token fixtures ----
    //
    // Generated the same way real clients will: sign the exact payload bytes with HMAC-SHA256(secret)
    // and emit "v2.<base64url(payload)>.<base64url(signature)>". The signature is over the raw payload
    // bytes, so we base64url-encode the very same bytes we sign. Timestamps reuse the v1 fixtures so
    // tests can pin the same clock for expiry assertions.

    public static readonly string ClientV2TokenString =
        GenerateV2Token(ClientEnvId, ClientToken.Timestamp, ClientSecretString);

    public static readonly string ServerV2TokenString =
        GenerateV2Token(ServerEnvId, ServerToken.Timestamp, ServerSecretString);

    /// <summary>
    /// Produces a valid v2 HMAC token for the given environment, timestamp and secret.
    /// Mirrors the client-side signing that a later PR will implement in the SDKs.
    /// </summary>
    public static string GenerateV2Token(Guid envId, long timestamp, string secretString)
    {
        var eid = GuidHelper.Encode(envId);
        var payloadJson = $"{{\"eid\":\"{eid}\",\"timestamp\":{timestamp}}}";
        var payloadBytes = Encoding.UTF8.GetBytes(payloadJson);

        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secretString));
        var signature = hmac.ComputeHash(payloadBytes);

        return $"v2.{Base64UrlEncode(payloadBytes)}.{Base64UrlEncode(signature)}";
    }

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
