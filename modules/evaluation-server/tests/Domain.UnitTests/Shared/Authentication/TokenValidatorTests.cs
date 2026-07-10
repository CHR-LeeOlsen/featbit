using Domain.Shared;
using Domain.Shared.Authentication;
using Moq;

namespace Domain.UnitTests.Shared.Authentication;

public class TokenValidatorTests
{
    // v1 validation is structural-only and never touches the store.
    private readonly TokenValidator _validator = new(Mock.Of<IStore>());

    [Fact]
    public async Task ValidateAsync_WithValidSecret_ReturnsValid()
    {
        var secret = TestData.ServerSecretString;

        var result = await _validator.ValidateAsync(secret);

        Assert.Equal(TokenValidationStatus.Valid, result.Status);
        Assert.Equal(TestData.ServerEnvId, result.EnvId);
        Assert.Empty(result.Reason);
    }

    [Theory]
    [InlineData("invalid-secret-string")]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("   ")]
    public async Task ValidateAsync_WithInvalidSecret_ReturnsInvalid(string? secret)
    {
        var result = await _validator.ValidateAsync(secret);

        Assert.Equal(TokenValidationStatus.Invalid, result.Status);
        Assert.Equal(Guid.Empty, result.EnvId);

        Assert.NotEmpty(result.Reason);
    }

    [Fact]
    public async Task ValidateAsync_ClientSecret_ExtractsCorrectEnvId()
    {
        var result = await _validator.ValidateAsync(TestData.ClientSecretString);

        Assert.Equal(TokenValidationStatus.Valid, result.Status);
        Assert.Equal(TestData.ClientEnvId, result.EnvId);
    }

    // ---- v2 (HMAC) token cases ----

    private static TokenValidator SetupValidator(
        Func<Guid, Task<SecretWithValue[]>>? getSecrets = null)
    {
        var store = new Mock<IStore>();
        store
            .Setup(x => x.GetSecretsAsync(It.IsAny<Guid>()))
            .Returns((Guid envId) => getSecrets is null
                ? Task.FromResult(FakeSeedData.GetSecrets(envId))
                : getSecrets(envId));

        return new TokenValidator(store.Object);
    }

    [Fact]
    public async Task ValidateAsync_ValidClientV2Token_ReturnsValidWithSecret()
    {
        var validator = SetupValidator();

        var result = await validator.ValidateAsync(TestData.ClientV2TokenString);

        Assert.Equal(TokenValidationStatus.Valid, result.Status);
        Assert.Equal(TokenVersion.V2, result.Version);
        Assert.Equal(TestData.ClientEnvId, result.EnvId);
        Assert.Equal(TestData.ClientToken.Timestamp, result.Timestamp);
        Assert.NotNull(result.Secret);
        Assert.Equal(SecretTypes.Client, result.Secret!.Type);
        Assert.Equal(TestData.ClientEnvId, result.Secret.EnvId);
    }

    [Fact]
    public async Task ValidateAsync_ValidServerV2Token_ReturnsValidWithSecret()
    {
        var validator = SetupValidator();

        var result = await validator.ValidateAsync(TestData.ServerV2TokenString);

        Assert.Equal(TokenValidationStatus.Valid, result.Status);
        Assert.Equal(TokenVersion.V2, result.Version);
        Assert.Equal(TestData.ServerEnvId, result.EnvId);
        Assert.NotNull(result.Secret);
        Assert.Equal(SecretTypes.Server, result.Secret!.Type);
    }

    [Fact]
    public async Task ValidateAsync_UnknownEnv_NoSecrets_ReturnsInvalid()
    {
        // Env resolves structurally but the store has no secrets for it.
        var validator = SetupValidator(_ => Task.FromResult(Array.Empty<SecretWithValue>()));

        var result = await validator.ValidateAsync(TestData.ClientV2TokenString);

        Assert.Equal(TokenValidationStatus.Invalid, result.Status);
        Assert.Null(result.Secret);
    }

    [Fact]
    public async Task ValidateAsync_SecretPresentButSignatureMismatch_ReturnsInvalid()
    {
        // Return a secret whose value does not match the one used to sign the token.
        var validator = SetupValidator(envId => Task.FromResult<SecretWithValue[]>(
        [
            new SecretWithValue(SecretTypes.Client, "webapp", envId, "dev", "a-different-secret-value")
        ]));

        var result = await validator.ValidateAsync(TestData.ClientV2TokenString);

        Assert.Equal(TokenValidationStatus.Invalid, result.Status);
        Assert.Null(result.Secret);
    }

    [Theory]
    [InlineData("v2.")]
    [InlineData("v2.garbage")]
    [InlineData("v2.!!!.@@@")]
    public async Task ValidateAsync_MalformedV2Token_ReturnsInvalidWithoutStoreLookup(string token)
    {
        var store = new Mock<IStore>();

        var validator = new TokenValidator(store.Object);

        var result = await validator.ValidateAsync(token);

        Assert.Equal(TokenValidationStatus.Invalid, result.Status);
        // Malformed tokens must never hit the store.
        store.Verify(x => x.GetSecretsAsync(It.IsAny<Guid>()), Times.Never);
    }

    [Fact]
    public async Task ValidateAsync_StoreThrows_PropagatesException()
    {
        var validator = SetupValidator(_ => throw new InvalidOperationException("store down"));

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => validator.ValidateAsync(TestData.ClientV2TokenString));
    }
}
