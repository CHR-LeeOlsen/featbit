using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Domain.Shared;

/// <summary>
/// Immutable v2 HMAC token: <c>v2.&lt;base64url(payload)&gt;.&lt;base64url(HMAC-SHA256(payload))&gt;</c>.
/// The payload is a JSON object <c>{ "eid": "&lt;22-char base64url envId&gt;", "timestamp": &lt;unix ms&gt; }</c>.
/// Parsing never throws for attacker-controlled input: any malformed input yields <see cref="IsValid"/> == false.
/// </summary>
public readonly struct HmacToken
{
    public const string Prefix = "v2.";

    private const int SignatureLength = 32; // HMAC-SHA256 => 32 bytes

    public Guid EnvId { get; }

    public long Timestamp { get; }

    public bool IsValid { get; }

    // The exact payload bytes that were signed. Signature verification must run over these raw bytes,
    // never over a re-serialized payload (re-serialization can reorder keys / change whitespace).
    private readonly byte[] _payloadBytes;

    private readonly byte[] _signatureBytes;

    public HmacToken(ReadOnlySpan<char> tokenSpan)
    {
        EnvId = Guid.Empty;
        Timestamp = 0;
        IsValid = false;
        _payloadBytes = [];
        _signatureBytes = [];

        // 1. Require the "v2." prefix.
        if (!tokenSpan.StartsWith(Prefix))
        {
            return;
        }

        var body = tokenSpan[Prefix.Length..];

        // 2. Split into exactly two dot-delimited parts: payload and signature.
        var dot = body.IndexOf('.');
        if (dot <= 0 || dot >= body.Length - 1)
        {
            return;
        }

        var payloadSpan = body[..dot];
        var signatureSpan = body[(dot + 1)..];

        // reject any extra '.' in the signature segment
        if (signatureSpan.IndexOf('.') >= 0)
        {
            return;
        }

        // 3. base64url-decode payload and signature.
        if (!TryBase64UrlDecode(payloadSpan, out var payloadBytes) ||
            !TryBase64UrlDecode(signatureSpan, out var signatureBytes))
        {
            return;
        }

        if (payloadBytes.Length == 0 || signatureBytes.Length != SignatureLength)
        {
            return;
        }

        // 4. Parse the payload JSON: { eid, timestamp }.
        if (!TryParsePayload(payloadBytes, out var envId, out var timestamp))
        {
            return;
        }

        EnvId = envId;
        Timestamp = timestamp;
        _payloadBytes = payloadBytes;
        _signatureBytes = signatureBytes;
        IsValid = true;
    }

    /// <summary>
    /// Verifies the token signature against <paramref name="secretString"/> using a constant-time compare.
    /// Returns false for an invalid token or any mismatch.
    /// </summary>
    public bool VerifySignature(string secretString)
    {
        if (!IsValid || string.IsNullOrEmpty(secretString))
        {
            return false;
        }

        Span<byte> computed = stackalloc byte[SignatureLength];
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secretString));
        if (!hmac.TryComputeHash(_payloadBytes, computed, out var written) || written != _signatureBytes.Length)
        {
            return false;
        }

        // constant-time comparison to avoid a timing side-channel (see Security Requirements)
        return CryptographicOperations.FixedTimeEquals(computed, _signatureBytes);
    }

    private static bool TryParsePayload(byte[] payloadBytes, out Guid envId, out long timestamp)
    {
        envId = Guid.Empty;
        timestamp = 0;

        try
        {
            using var doc = JsonDocument.Parse(payloadBytes);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            if (!root.TryGetProperty("eid", out var eidProp) || eidProp.ValueKind != JsonValueKind.String ||
                !root.TryGetProperty("timestamp", out var tsProp) || tsProp.ValueKind != JsonValueKind.Number)
            {
                return false;
            }

            var eid = eidProp.GetString();
            if (string.IsNullOrEmpty(eid) || eid.Length != 22 || !tsProp.TryGetInt64(out timestamp))
            {
                return false;
            }

            envId = GuidHelper.Decode(eid);
            return envId != Guid.Empty;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool TryBase64UrlDecode(ReadOnlySpan<char> input, out byte[] bytes)
    {
        bytes = [];

        var length = input.Length;
        if (length == 0)
        {
            return false;
        }

        var padding = (4 - length % 4) % 4;
        var total = length + padding;

        Span<char> chars = total <= 256 ? stackalloc char[total] : new char[total];
        for (var i = 0; i < length; i++)
        {
            var c = input[i];
            chars[i] = c switch
            {
                '-' => '+',
                '_' => '/',
                _ => c
            };
        }

        for (var i = length; i < total; i++)
        {
            chars[i] = '=';
        }

        Span<byte> buffer = stackalloc byte[total / 4 * 3];
        if (!Convert.TryFromBase64Chars(chars, buffer, out var written))
        {
            return false;
        }

        bytes = buffer[..written].ToArray();
        return true;
    }
}
