using Application.Caches;
using Application.Services;
using Domain.Environments;
using Domain.FeatureFlags;
using Domain.Segments;
using Infrastructure.Caches.Redis;
using Infrastructure.IntegrationTests.Fixtures;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using StackExchange.Redis;

namespace Infrastructure.IntegrationTests.Caches.Redis;

[Collection(RedisCollection.Name)]
public class RedisPopulatingServiceReconcileTests : IntegrationTestBase, IAsyncLifetime
{
    private readonly RedisFixture _fixture;
    private ConnectionMultiplexer _connection = null!;
    private RedisCacheService _cacheService = null!;
    private Mock<IRedisClient> _clientMock = null!;
    private Mock<IEnvironmentService> _envService = null!;

    public RedisPopulatingServiceReconcileTests(RedisFixture fixture)
    {
        _fixture = fixture;
    }

    public async Task InitializeAsync()
    {
        if (!DockerAvailability.IsAvailable)
        {
            return;
        }

        var options = ConfigurationOptions.Parse(_fixture.ConnectionString);
        options.AllowAdmin = true;
        _connection = await ConnectionMultiplexer.ConnectAsync(options);

        var server = _connection.GetServer(_connection.GetEndPoints().Single());
        await server.FlushDatabaseAsync();

        _clientMock = new Mock<IRedisClient>();
        _clientMock.Setup(x => x.GetDatabase()).Returns(() => _connection.GetDatabase());
        _clientMock.Setup(x => x.Connection).Returns(() => _connection);

        _cacheService = new RedisCacheService(_clientMock.Object);
        _envService = new Mock<IEnvironmentService>();
    }

    public Task DisposeAsync()
    {
        _connection?.Dispose();
        return Task.CompletedTask;
    }

    [DockerFact]
    public async Task PopulateAsync_RemovesRotatedSecretButKeepsCurrentSecret()
    {
        var envId = Guid.NewGuid();
        var descriptor = DescriptorFor(envId);
        var currentSecret = new Secret(envId, "current", SecretTypes.Server);
        var rotatedSecret = new Secret(envId, "rotated", SecretTypes.Server);

        // simulate a secret rotation whose delete event was missed: both secrets are in
        // Redis, but only the current one still exists in the DB.
        await _cacheService.UpsertSecretAsync(descriptor, currentSecret);
        await _cacheService.UpsertSecretAsync(descriptor, rotatedSecret);

        _envService
            .Setup(x => x.GetSecretCachesAsync())
            .ReturnsAsync([new SecretCache(descriptor, currentSecret)]);

        await CreateSut().PopulateAsync(CancellationToken.None);

        var db = _connection.GetDatabase();

        // current secret survives
        Assert.True(await db.KeyExistsAsync(RedisKeys.Secret(currentSecret.Value)));
        Assert.True(await db.SetContainsAsync(RedisKeys.EnvSecrets(envId), currentSecret.Value));

        // rotated (stale) secret is fully removed
        Assert.False(await db.KeyExistsAsync(RedisKeys.Secret(rotatedSecret.Value)));
        Assert.False(await db.SetContainsAsync(RedisKeys.EnvSecrets(envId), rotatedSecret.Value));
    }

    [DockerFact]
    public async Task PopulateAsync_RemovesSecretsOfDeletedEnvironment()
    {
        var deletedEnvId = Guid.NewGuid();
        var deletedDescriptor = DescriptorFor(deletedEnvId);
        var orphanSecret = new Secret(deletedEnvId, "orphan", SecretTypes.Server);

        // secret whose environment was deleted while the delete event was missed.
        await _cacheService.UpsertSecretAsync(deletedDescriptor, orphanSecret);

        // the environment no longer exists in the DB.
        _envService
            .Setup(x => x.GetSecretCachesAsync())
            .ReturnsAsync([]);

        await CreateSut().PopulateAsync(CancellationToken.None);

        var db = _connection.GetDatabase();

        Assert.False(await db.KeyExistsAsync(RedisKeys.Secret(orphanSecret.Value)));
        Assert.False(await db.KeyExistsAsync(RedisKeys.EnvSecrets(deletedEnvId)));
    }

    private RedisPopulatingService CreateSut()
    {
        var flagService = new Mock<IFeatureFlagService>();
        flagService
            .Setup(x => x.FindManyAsync(It.IsAny<System.Linq.Expressions.Expression<Func<FeatureFlag, bool>>>()))
            .ReturnsAsync([]);

        var segmentService = new Mock<ISegmentService>();
        segmentService
            .Setup(x => x.GetCachesAsync())
            .ReturnsAsync([]);

        var options = Options.Create(new RedisOptions
        {
            PopulateLockTtlSeconds = 60,
            PopulateMaxWaitSeconds = 90
        });

        return new RedisPopulatingService(
            _clientMock.Object,
            _cacheService,
            flagService.Object,
            segmentService.Object,
            _envService.Object,
            options,
            NullLogger<RedisPopulatingService>.Instance);
    }

    private static ResourceDescriptor DescriptorFor(Guid envId) => new()
    {
        Organization = new IdNameKeyProps { Id = Guid.NewGuid(), Name = "org", Key = "org" },
        Project = new IdNameKeyProps { Id = Guid.NewGuid(), Name = "proj", Key = "proj" },
        Environment = new IdNameKeyProps { Id = envId, Name = "env", Key = "env" }
    };
}
