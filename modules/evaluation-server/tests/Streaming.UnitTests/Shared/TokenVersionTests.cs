using Domain.Shared;

namespace Streaming.UnitTests.Shared;

public class TokenVersionTests
{
    [Theory]
    [InlineData(TestData.ClientTokenString, TokenVersion.V1)]
    [InlineData(TestData.ServerTokenString, TokenVersion.V1)]
    [InlineData("QDUBHYWVkLWNiZT", TokenVersion.V1)]
    [InlineData("someRandomString", TokenVersion.V1)]
    [InlineData(TestData.ClientV2TokenString, TokenVersion.V2)]
    [InlineData(TestData.ServerV2TokenString, TokenVersion.V2)]
    [InlineData("v2.payload.signature", TokenVersion.V2)]
    public void DetectsCorrectVersion(string tokenString, string expectedVersion)
    {
        var result = TokenVersion.Detect(tokenString);

        Assert.Equal(expectedVersion, result);
    }

    [Fact]
    public void V2Prefix_CaseSensitive()
    {
        // "V2." should NOT be detected as v2
        Assert.Equal(TokenVersion.V1, TokenVersion.Detect("V2.something.else"));
    }
}
