using Domain.Environments;
using Infrastructure.Caches.Redis;
using Moq;
using StackExchange.Redis;

namespace Infrastructure.UnitTests.Caches.Redis;

public class RedisCacheServiceSecretIndexTests
{
    private readonly Mock<IDatabase> _db = new();
    private readonly RedisCacheService _sut;

    public RedisCacheServiceSecretIndexTests()
    {
        _db.Setup(x => x.HashSetAsync(It.IsAny<RedisKey>(), It.IsAny<HashEntry[]>(), It.IsAny<CommandFlags>()))
            .Returns(Task.CompletedTask);
        _db.Setup(x => x.SetAddAsync(It.IsAny<RedisKey>(), It.IsAny<RedisValue>(), It.IsAny<CommandFlags>()))
            .ReturnsAsync(true);
        _db.Setup(x => x.SetRemoveAsync(It.IsAny<RedisKey>(), It.IsAny<RedisValue>(), It.IsAny<CommandFlags>()))
            .ReturnsAsync(true);
        _db.Setup(x => x.KeyDeleteAsync(It.IsAny<RedisKey>(), It.IsAny<CommandFlags>()))
            .ReturnsAsync(true);

        var redis = new Mock<IRedisClient>();
        redis.Setup(x => x.GetDatabase()).Returns(_db.Object);

        _sut = new RedisCacheService(redis.Object);
    }

    [Fact]
    public async Task UpsertSecret_AddsValueToEnvIndex()
    {
        var envId = Guid.NewGuid();
        var secret = new Secret(envId, "Server Key", "server");
        var descriptor = DescriptorFor(envId);

        await _sut.UpsertSecretAsync(descriptor, secret);

        _db.Verify(
            x => x.SetAddAsync(
                RedisKeys.EnvSecrets(envId),
                secret.Value,
                It.IsAny<CommandFlags>()),
            Times.Once);
    }

    [Fact]
    public async Task DeleteSecret_RemovesValueFromEnvIndex()
    {
        var envId = Guid.NewGuid();
        var secret = new Secret(envId, "Server Key", "server");

        await _sut.DeleteSecretAsync(secret);

        _db.Verify(
            x => x.SetRemoveAsync(
                RedisKeys.EnvSecrets(envId),
                secret.Value,
                It.IsAny<CommandFlags>()),
            Times.Once);
    }

    [Fact]
    public async Task DeleteSecret_DeletesSecretHash()
    {
        var envId = Guid.NewGuid();
        var secret = new Secret(envId, "Server Key", "server");

        await _sut.DeleteSecretAsync(secret);

        _db.Verify(
            x => x.KeyDeleteAsync(RedisKeys.Secret(secret.Value), It.IsAny<CommandFlags>()),
            Times.Once);
    }

    [Fact]
    public async Task DeleteSecret_MalformedValue_SkipsIndexRemoval()
    {
        var secret = new Secret { Id = Guid.NewGuid().ToString(), Type = "server", Value = "not-a-valid-secret" };

        await _sut.DeleteSecretAsync(secret);

        _db.Verify(
            x => x.SetRemoveAsync(It.IsAny<RedisKey>(), It.IsAny<RedisValue>(), It.IsAny<CommandFlags>()),
            Times.Never);
        _db.Verify(
            x => x.KeyDeleteAsync(RedisKeys.Secret(secret.Value), It.IsAny<CommandFlags>()),
            Times.Once);
    }

    private static ResourceDescriptor DescriptorFor(Guid envId) => new()
    {
        Organization = new IdNameKeyProps { Id = Guid.NewGuid(), Name = "org", Key = "org" },
        Project = new IdNameKeyProps { Id = Guid.NewGuid(), Name = "proj", Key = "proj" },
        Environment = new IdNameKeyProps { Id = envId, Name = "env", Key = "env" }
    };
}
