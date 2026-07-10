using Domain.Shared;
using TestBase;

namespace Domain.UnitTests.Shared;

public class HmacTokenTests
{
    [Fact]
    public void Constructor_ValidClientToken_ParsesEnvIdAndTimestamp()
    {
        var token = new HmacToken(TestData.ClientV2TokenString.AsSpan());

        Assert.True(token.IsValid);
        Assert.Equal(TestData.ClientEnvId, token.EnvId);
        Assert.Equal(TestData.ClientToken.Timestamp, token.Timestamp);
    }

    [Fact]
    public void VerifySignature_CorrectSecret_ReturnsTrue()
    {
        var token = new HmacToken(TestData.ServerV2TokenString.AsSpan());

        Assert.True(token.IsValid);
        Assert.True(token.VerifySignature(TestData.ServerSecretString));
    }

    [Fact]
    public void VerifySignature_WrongSecret_ReturnsFalse()
    {
        var token = new HmacToken(TestData.ServerV2TokenString.AsSpan());

        // A valid token signed with the server secret must not verify against the client secret.
        Assert.False(token.VerifySignature(TestData.ClientSecretString));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void VerifySignature_NullOrEmptySecret_ReturnsFalse(string? secret)
    {
        var token = new HmacToken(TestData.ClientV2TokenString.AsSpan());

        Assert.False(token.VerifySignature(secret!));
    }

    [Fact]
    public void VerifySignature_TamperedPayload_ReturnsFalse()
    {
        var original = TestData.ClientV2TokenString;

        // Flip a single character in the payload segment; the signature no longer matches.
        const int firstPayloadIndex = 3; // length of "v2."
        var payloadChar = original[firstPayloadIndex];
        var replacement = payloadChar == 'A' ? 'B' : 'A';
        var tampered = original[..firstPayloadIndex] + replacement + original[(firstPayloadIndex + 1)..];

        var token = new HmacToken(tampered.AsSpan());

        // The token may still parse structurally, but the signature must fail.
        Assert.False(token.IsValid && token.VerifySignature(TestData.ClientSecretString));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("v1.token")]                       // wrong prefix
    [InlineData("v2.")]                            // no payload/signature
    [InlineData("v2.payloadonly")]                 // missing signature separator
    [InlineData("v2..signature")]                  // empty payload
    [InlineData("v2.payload.")]                    // empty signature
    [InlineData("v2.payload.sig.extra")]           // extra dot
    [InlineData("v2.!!!.@@@")]                      // invalid base64url
    public void Constructor_MalformedInput_IsNotValid(string? input)
    {
        var token = new HmacToken(input.AsSpan());

        Assert.False(token.IsValid);
        Assert.Equal(Guid.Empty, token.EnvId);
    }

    [Fact]
    public void Constructor_WrongSignatureLength_IsNotValid()
    {
        // Well-formed base64url payload + a base64url signature that decodes to fewer than 32 bytes.
        var token = new HmacToken("v2.eyJhIjoxfQ.AAAA".AsSpan());

        Assert.False(token.IsValid);
    }

    [Fact]
    public void Constructor_ValidBase64ButNotJsonPayload_IsNotValid()
    {
        // "AAAAAAAA..." decodes to bytes that are not a JSON object.
        var token = new HmacToken("v2.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".AsSpan());

        Assert.False(token.IsValid);
    }
}
