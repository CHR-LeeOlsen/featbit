using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Domain.Shared;

public struct HmacToken
{
    private const string Prefix = "v2.";

    public Guid EnvId { get; set; }

    public long Timestamp { get; set; }

    public bool IsValid { get; set; }

    // Raw payload bytes preserved for signature verification
    private byte[]? _payloadBytes;
    private byte[]? _signatureBytes;

    public HmacToken(ReadOnlySpan<char> tokenSpan)
    {
        EnvId = Guid.Empty;
        Timestamp = 0;
        IsValid = false;
        _payloadBytes = null;
        _signatureBytes = null;

        if (tokenSpan.IsEmpty || !tokenSpan.StartsWith(Prefix.AsSpan(), StringComparison.Ordinal))
        {
            return;
        }

        var withoutPrefix = tokenSpan[Prefix.Length..];

        // Find the separator between payload and signature
        var separatorIndex = withoutPrefix.IndexOf('.');
        if (separatorIndex < 1 || separatorIndex >= withoutPrefix.Length - 1)
        {
            return;
        }

        var payloadPart = withoutPrefix[..separatorIndex];
        var signaturePart = withoutPrefix[(separatorIndex + 1)..];

        // Decode payload from base64url
        _payloadBytes = Base64UrlDecode(payloadPart);
        if (_payloadBytes is null || _payloadBytes.Length == 0)
        {
            return;
        }

        // Decode signature from base64url
        _signatureBytes = Base64UrlDecode(signaturePart);
        if (_signatureBytes is null || _signatureBytes.Length == 0)
        {
            return;
        }

        // Parse JSON payload
        try
        {
            var payload = JsonSerializer.Deserialize<HmacTokenPayload>(_payloadBytes);
            if (payload.Eid is null || payload.Eid.Length != 22)
            {
                return;
            }

            var envId = GuidHelper.Decode(payload.Eid.AsSpan());
            if (envId == Guid.Empty)
            {
                return;
            }

            EnvId = envId;
            Timestamp = payload.Timestamp;
        }
        catch
        {
            return;
        }

        IsValid = true;
    }

    public bool VerifySignature(string secretString)
    {
        if (!IsValid || _payloadBytes is null || _signatureBytes is null)
        {
            return false;
        }

        var keyBytes = Encoding.UTF8.GetBytes(secretString);
        var expectedSignature = HMACSHA256.HashData(keyBytes, _payloadBytes);

        return CryptographicOperations.FixedTimeEquals(expectedSignature, _signatureBytes);
    }

    private static byte[]? Base64UrlDecode(ReadOnlySpan<char> input)
    {
        try
        {
            // Convert base64url to base64
            var len = input.Length;
            var remainder = len % 4;
            int padded;
            if (remainder == 2)
                padded = len + 2;
            else if (remainder == 3)
                padded = len + 1;
            else
                padded = len;

            Span<char> base64Chars = padded <= 256 ? stackalloc char[padded] : new char[padded];
            for (var i = 0; i < len; i++)
            {
                base64Chars[i] = input[i] switch
                {
                    '-' => '+',
                    '_' => '/',
                    var c => c
                };
            }

            for (var i = len; i < padded; i++)
            {
                base64Chars[i] = '=';
            }

            return Convert.FromBase64String(new string(base64Chars));
        }
        catch
        {
            return null;
        }
    }

    private struct HmacTokenPayload
    {
        [JsonPropertyName("eid")]
        public string? Eid { get; set; }

        [JsonPropertyName("timestamp")]
        public long Timestamp { get; set; }
    }
}
