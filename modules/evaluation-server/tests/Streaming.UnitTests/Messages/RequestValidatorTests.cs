using Domain.Shared;
using Domain.Shared.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Internal;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Streaming.Connections;
using Streaming.Services;

namespace Streaming.UnitTests.Messages;

public class RequestValidatorTests
{
    [Fact]
    public async Task ValidateAsync_ValidClientRequest_ReturnsSecretForEnvironment()
    {
        var context = SetupTestContext();
        var validator = SetupValidator();

        var validationResult = await validator.ValidateAsync(context);

        Assert.Equal(ValidationResultStatus.Valid, validationResult.Status);
        Assert.Empty(validationResult.Reason);

        Assert.Single(validationResult.Secrets);
        Assert.Equivalent(TestData.ClientSecret, validationResult.Secrets[0], strict: true);
    }

    [Fact]
    public async Task ValidateAsync_ValidRelayProxyRequest_ReturnsAllServerSecretsForProxy()
    {
        var rpService = new Mock<IRelayProxyService>();

        Secret[] secrets =
        [
            new(SecretTypes.Server, "p1", Guid.NewGuid(), "prod"),
            new(SecretTypes.Server, "p2", Guid.NewGuid(), "prod")
        ];

        rpService.Setup(x => x.GetServerSecretsAsync(It.IsAny<string>())).ReturnsAsync(secrets);

        var context = SetupTestContext(type: ConnectionType.RelayProxy);
        var validator = SetupValidator(rpService: rpService.Object);

        var validationResult = await validator.ValidateAsync(context);
        Assert.Equal(ValidationResultStatus.Valid, validationResult.Status);
        Assert.Empty(validationResult.Reason);

        Assert.Equal(2, validationResult.Secrets.Length);
        Assert.Equivalent(secrets[0], validationResult.Secrets[0], strict: true);
        Assert.Equivalent(secrets[1], validationResult.Secrets[1], strict: true);
    }

    [Theory]
    [InlineData("")]
    [InlineData("unknown")]
    public async Task ValidateAsync_UnknownOrEmptyConnectionType_FailsWithInvalidType(string type)
    {
        await EnsureInvalidAsync(
            expectedReason: $"Invalid type: {type}",
            type: type
        );
    }

    [Theory]
    [InlineData("unknown")]
    public async Task ValidateAsync_UnsupportedProtocolVersion_FailsWithInvalidVersion(string version)
    {
        await EnsureInvalidAsync(
            expectedReason: $"Invalid version: {version}",
            version: version
        );
    }

    [Fact]
    public async Task ValidateAsync_EmptyToken_FailsWithInvalidToken()
    {
        await EnsureInvalidAsync(
            expectedReason: "Missing token",
            token: string.Empty
        );
    }

    [Fact]
    public async Task ValidateAsync_MalformedToken_FailsWithInvalidToken()
    {
        await EnsureInvalidAsync(
            expectedReason: "Invalid token: 123456",
            token: "123456"
        );
    }

    [Fact]
    public async Task ValidateAsync_TokenIssuedTooFarInPast_FailsWithExpired()
    {
        await EnsureInvalidAsync(
            expectedReason: $"Token is expired: {TestData.ClientTokenString}",
            current: TestData.ClientToken.Timestamp + 31 * 1000
        );
    }

    [Fact]
    public async Task ValidateAsync_TokenIssuedTooFarInFuture_FailsWithExpired()
    {
        await EnsureInvalidAsync(
            expectedReason: $"Token is expired: {TestData.ClientTokenString}",
            current: TestData.ClientToken.Timestamp - 31 * 1000
        );
    }

    [Fact]
    public async Task ValidateAsync_SecretNotFoundInStore_FailsWithSecretNotFound()
    {
        var nullStore = new Mock<IStore>();
        nullStore.Setup(x => x.GetSecretAsync(It.IsAny<string>())).ReturnsAsync(() => null);

        await EnsureInvalidAsync(
            expectedReason: $"Secret is not found: {TestData.ClientSecretString}",
            store: nullStore.Object
        );
    }

    [Fact]
    public async Task ValidateAsync_ClientSecretUsedAsServerConnection_FailsWithInconsistentSecret()
    {
        await EnsureInvalidAsync(
            expectedReason: $"Inconsistent secret used: {SecretTypes.Client}. Request type: {ConnectionType.Server}",
            type: ConnectionType.Server
        );
    }

    [Fact]
    public async Task ValidateAsync_RelayProxyTokenNotInService_FailsWithInvalidRelayProxyToken()
    {
        var rpService = new Mock<IRelayProxyService>();
        rpService.Setup(x => x.GetServerSecretsAsync(It.IsAny<string>()))
            .ReturnsAsync([]);

        await EnsureInvalidAsync(
            expectedReason: "Invalid relay proxy token: rp-xxx",
            type: ConnectionType.RelayProxy,
            token: "rp-xxx",
            rpService: rpService.Object
        );
    }

    [Fact]
    public async Task ValidateAsync_StoreThrowsException_ReturnsUnavailable()
    {
        var errorStoreMock = new Mock<IStore>();
        errorStoreMock.Setup(x => x.GetSecretAsync(It.IsAny<string>()))
            .Throws(new Exception("Test exception"));

        var context = SetupTestContext();
        var validator = SetupValidator(store: errorStoreMock.Object);

        var validationResult = await validator.ValidateAsync(context);

        Assert.Equal(ValidationResultStatus.Unavailable, validationResult.Status);
        Assert.Equal("Secret lookup unavailable: Test exception", validationResult.Reason);
    }

    [Fact]
    public async Task ParseTokenThrows()
    {
        // A throwing ITokenValidator simulates a parsing-stage failure.
        // It must produce Failed (permanent rejection / WS 4003), never Unavailable (transient / WS 1011).
        var throwingValidator = new Mock<ITokenValidator>();
        throwingValidator
            .Setup(x => x.ValidateAsync(It.IsAny<string?>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new FormatException("Simulated parse error"));

        var context = SetupTestContext();
        var validator = SetupValidator(tokenValidator: throwingValidator.Object);

        var validationResult = await validator.ValidateAsync(context);

        Assert.Equal(ValidationResultStatus.Invalid, validationResult.Status);
        Assert.Empty(validationResult.Secrets);
    }

    // ---- v2 (HMAC) token cases ----

    private static Mock<IStore> SetupV2Store() =>
        SetupV2Store((Guid envId) => Task.FromResult(FakeSeedData.GetSecrets(envId)));

    private static Mock<IStore> SetupV2Store(Func<Guid, Task<SecretWithValue[]>> getSecrets)
    {
        var store = new Mock<IStore>();
        store.Setup(x => x.GetSecretsAsync(It.IsAny<Guid>())).Returns(getSecrets);
        return store;
    }

    [Fact]
    public async Task ValidateAsync_ValidClientV2Request_ReturnsSecretForEnvironment()
    {
        var context = SetupTestContext(token: TestData.ClientV2TokenString);
        var validator = SetupValidator(
            current: TestData.ClientToken.Timestamp,
            store: SetupV2Store().Object);

        var validationResult = await validator.ValidateAsync(context);

        Assert.Equal(ValidationResultStatus.Valid, validationResult.Status);
        Assert.Single(validationResult.Secrets);
        Assert.Equal(SecretTypes.Client, validationResult.Secrets[0].Type);
        Assert.Equal(TestData.ClientEnvId, validationResult.Secrets[0].EnvId);
    }

    [Fact]
    public async Task ValidateAsync_ValidServerV2Request_ReturnsSecretForEnvironment()
    {
        var context = SetupTestContext(type: ConnectionType.Server, token: TestData.ServerV2TokenString);
        var validator = SetupValidator(
            current: TestData.ServerToken.Timestamp,
            store: SetupV2Store().Object);

        var validationResult = await validator.ValidateAsync(context);

        Assert.Equal(ValidationResultStatus.Valid, validationResult.Status);
        Assert.Single(validationResult.Secrets);
        Assert.Equal(SecretTypes.Server, validationResult.Secrets[0].Type);
    }

    [Fact]
    public async Task ValidateAsync_V2TokenExpired_FailsWithExpired()
    {
        var context = SetupTestContext(token: TestData.ClientV2TokenString);
        var validator = SetupValidator(
            current: TestData.ClientToken.Timestamp + 31 * 1000,
            store: SetupV2Store().Object);

        var validationResult = await validator.ValidateAsync(context);

        Assert.Equal(ValidationResultStatus.Invalid, validationResult.Status);
        Assert.Equal($"Token is expired: {TestData.ClientV2TokenString}", validationResult.Reason);
    }

    [Fact]
    public async Task ValidateAsync_V2ClientSecretUsedAsServerConnection_FailsWithInconsistentSecret()
    {
        var context = SetupTestContext(type: ConnectionType.Server, token: TestData.ClientV2TokenString);
        var validator = SetupValidator(
            current: TestData.ClientToken.Timestamp,
            store: SetupV2Store().Object);

        var validationResult = await validator.ValidateAsync(context);

        Assert.Equal(ValidationResultStatus.Invalid, validationResult.Status);
        Assert.Equal(
            $"Inconsistent secret used: {SecretTypes.Client}. Request type: {ConnectionType.Server}",
            validationResult.Reason);
    }

    [Fact]
    public async Task ValidateAsync_V2SignatureMismatch_FailsWithInvalidToken()
    {
        var store = SetupV2Store(envId => Task.FromResult<SecretWithValue[]>(
        [
            new SecretWithValue(SecretTypes.Client, "webapp", envId, "dev", "a-different-secret-value")
        ]));
        var context = SetupTestContext(token: TestData.ClientV2TokenString);
        var validator = SetupValidator(current: TestData.ClientToken.Timestamp, store: store.Object);

        var validationResult = await validator.ValidateAsync(context);

        Assert.Equal(ValidationResultStatus.Invalid, validationResult.Status);
        Assert.Equal($"Invalid token: {TestData.ClientV2TokenString}", validationResult.Reason);
    }

    [Fact]
    public async Task ValidateAsync_V2StoreThrows_ReturnsUnavailable()
    {
        var store = SetupV2Store(_ => throw new Exception("Test exception"));
        var context = SetupTestContext(token: TestData.ClientV2TokenString);
        var validator = SetupValidator(current: TestData.ClientToken.Timestamp, store: store.Object);

        var validationResult = await validator.ValidateAsync(context);

        Assert.Equal(ValidationResultStatus.Unavailable, validationResult.Status);
        Assert.Equal("Secret lookup unavailable: Test exception", validationResult.Reason);
    }

    private static async Task EnsureInvalidAsync(
        string expectedReason,
        string? type = null,
        string? version = null,
        string? token = null,
        long? current = null,
        IStore? store = null,
        StreamingOptions? streamingOptions = null,
        IRelayProxyService? rpService = null)
    {
        var context = SetupTestContext(type, version, token);
        var validator = SetupValidator(current, store, streamingOptions, rpService);

        var validationResult = await validator.ValidateAsync(context);

        Assert.Equal(ValidationResultStatus.Invalid, validationResult.Status);
        Assert.Equal(expectedReason, validationResult.Reason);
        Assert.Empty(validationResult.Secrets);
    }

    private static RequestValidator SetupValidator(
        long? current = null,
        IStore? store = null,
        StreamingOptions? streamingOptions = null,
        IRelayProxyService? rpService = null,
        ITokenValidator? tokenValidator = null,
        ILogger<RequestValidator>? logger = null)
    {
        var mockedStore = Mock.Of<IStore>(x =>
            x.GetSecretAsync(TestData.ClientSecretString) == Task.FromResult(TestData.ClientSecret)
        );

        var resolvedStore = store ?? mockedStore;

        var validator = new RequestValidator(
            new TestSystemClock(current ?? TestData.ClientToken.Timestamp),
            resolvedStore,
            streamingOptions ?? new StreamingOptions(),
            rpService ?? Mock.Of<IRelayProxyService>(),
            tokenValidator ?? new TokenValidator(resolvedStore),
            logger ?? NullLogger<RequestValidator>.Instance
        );

        return validator;
    }

    private static HttpContext SetupTestContext(
        string? type = null,
        string? version = null,
        string? token = null)
    {
        var httpContext = new DefaultHttpContext
        {
            Request =
            {
                QueryString = QueryString.Create([
                    new KeyValuePair<string, string?>("type", type ?? ConnectionType.Client),
                    new KeyValuePair<string, string?>("version", version ?? ConnectionVersion.V2),
                    new KeyValuePair<string, string?>("token", token ?? TestData.ClientTokenString)
                ])
            }
        };

        return httpContext;
    }
}

internal class TestSystemClock(long current) : ISystemClock
{
    public DateTimeOffset UtcNow { get; } = DateTimeOffset.FromUnixTimeMilliseconds(current);
}