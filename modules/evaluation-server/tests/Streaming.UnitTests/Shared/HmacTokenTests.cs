using Domain.Shared;

namespace Streaming.UnitTests.Shared;

public class HmacTokenTests
{
    [Theory]
    [InlineData(TestData.ClientV2TokenString, "ad99d259-1f50-4ed9-a002-7c65e25487df", 1666018247603L)]
    [InlineData(TestData.ServerV2TokenString, "8dc61769-5af3-4d9f-8cb3-d7342e24c3eb", 1666018800754L)]
    public void ParseValidV2Token(string tokenString, string expectedEnvId, long expectedTimestamp)
    {
        var token = new HmacToken(tokenString);

        Assert.True(token.IsValid);
        Assert.Equal(new Guid(expectedEnvId), token.EnvId);
        Assert.Equal(expectedTimestamp, token.Timestamp);
    }

    [Theory]
    [InlineData(TestData.ClientV2TokenString, TestData.ClientSecretString)]
    [InlineData(TestData.ServerV2TokenString, TestData.ServerSecretString)]
    public void VerifySignature_ValidToken_ReturnsTrue(string tokenString, string secretKey)
    {
        var token = new HmacToken(tokenString);

        Assert.True(token.IsValid);
        Assert.True(token.VerifySignature(secretKey));
    }

    [Fact]
    public void VerifySignature_TamperedPayload_ReturnsFalse()
    {
        // Take a valid token and tamper with the payload (change a character in the middle
        // where all base64 bits are significant)
        var parts = TestData.ClientV2TokenString.Split('.');
        var payloadChars = parts[1].ToCharArray();
        payloadChars[payloadChars.Length / 2] = payloadChars[payloadChars.Length / 2] == 'A' ? 'B' : 'A';
        var tampered = $"v2.{new string(payloadChars)}.{parts[2]}";

        var token = new HmacToken(tampered);

        // Token may or may not parse depending on whether tampered base64 is valid JSON
        // If it does parse, signature should not verify
        if (token.IsValid)
        {
            Assert.False(token.VerifySignature(TestData.ClientSecretString));
        }
    }

    [Fact]
    public void VerifySignature_TamperedSignature_ReturnsFalse()
    {
        // Take a valid token and tamper with the signature (flip a character in the middle)
        var parts = TestData.ClientV2TokenString.Split('.');
        var sigChars = parts[2].ToCharArray();
        // Flip a character in the middle of the signature
        sigChars[sigChars.Length / 2] = sigChars[sigChars.Length / 2] == 'A' ? 'B' : 'A';
        var tampered = $"v2.{parts[1]}.{new string(sigChars)}";

        var token = new HmacToken(tampered);

        // The token structure is still parseable (payload unchanged), but signature won't verify
        Assert.True(token.IsValid);
        Assert.False(token.VerifySignature(TestData.ClientSecretString));
    }

    [Fact]
    public void VerifySignature_WrongKey_ReturnsFalse()
    {
        var token = new HmacToken(TestData.ClientV2TokenString);

        Assert.True(token.IsValid);
        // Use a different secret key — should fail
        Assert.False(token.VerifySignature(TestData.ServerSecretString));
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("v2.")]
    [InlineData("v2..")]
    [InlineData("v2.abc.")]
    [InlineData("v2..abc")]
    [InlineData("v1.something.else")]
    [InlineData("notavalidtoken")]
    [InlineData("QWSBHgpnOV3wI3kKAO9q9viC0wQWQQBDDDQBZWPXDQSdKZrVAf2U6gAnxl4lSH3w")] // v1 token
    public void ParseInvalidToken_IsNotValid(string tokenString)
    {
        var token = new HmacToken(tokenString);

        Assert.False(token.IsValid);
    }

    [Fact]
    public void VerifySignature_InvalidToken_ReturnsFalse()
    {
        var token = new HmacToken("invalid");

        Assert.False(token.IsValid);
        Assert.False(token.VerifySignature("anykey"));
    }

    [Fact]
    public void ParseToken_InvalidJsonPayload_IsNotValid()
    {
        // base64url of "not json" = "bm90IGpzb24"
        var token = new HmacToken("v2.bm90IGpzb24.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

        Assert.False(token.IsValid);
    }

    [Fact]
    public void ParseToken_PayloadWithShortEid_IsNotValid()
    {
        // JSON payload with an eid that's too short
        // {"eid":"short","timestamp":1234}
        // base64url: eyJlaWQiOiJzaG9ydCIsInRpbWVzdGFtcCI6MTIzNH0
        var token = new HmacToken("v2.eyJlaWQiOiJzaG9ydCIsInRpbWVzdGFtcCI6MTIzNH0.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

        Assert.False(token.IsValid);
    }
}
