using System.Net;
using System.Net.Http.Json;
using Domain.Shared;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Internal;

namespace Application.IntegrationTests.Http;

[Trait("Category", "Host")]
[Collection(nameof(TestApp))]
public class HttpAuthenticationTests
{
    private readonly TestApp _app;

    public HttpAuthenticationTests(TestApp app)
    {
        _app = app;
    }

    [Fact]
    public async Task GetServerSideSdkPayload_WithValidAuthHeader_Returns200()
    {
        var client = _app.CreateClient();
        client.DefaultRequestHeaders.Add("Authorization", TestData.ServerSecretString);

        var response = await client.GetAsync("/api/public/sdk/server/latest-all");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task GetServerSideSdkPayload_WithoutAuthHeader_Returns401()
    {
        var client = _app.CreateClient();

        var response = await client.GetAsync("/api/public/sdk/server/latest-all");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task GetServerSideSdkPayload_WithMalformedAuthHeader_Returns401()
    {
        var client = _app.CreateClient();
        client.DefaultRequestHeaders.Add("Authorization", "malformed-secret");

        var response = await client.GetAsync("/api/public/sdk/server/latest-all");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task GetServerSideSdkPayload_WithClientSecret_Returns200()
    {
        var client = _app.CreateClient();
        client.DefaultRequestHeaders.Add("Authorization", TestData.ClientSecretString);

        var response = await client.GetAsync("/api/public/sdk/server/latest-all");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task GetClientSideSdkPayload_WithValidAuthHeader_IsNotUnauthorized()
    {
        var client = _app.CreateClient();
        client.DefaultRequestHeaders.Add("Authorization", TestData.ServerSecretString);

        var request = new
        {
            user = new
            {
                key = "test-user",
                name = "Test User"
            }
        };

        var response = await client.PostAsJsonAsync("/api/public/sdk/client/latest-all?timestamp=0", request);

        Assert.NotEqual(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task GetClientSideSdkPayload_WithoutAuthHeader_Returns401()
    {
        var client = _app.CreateClient();

        var request = new
        {
            user = new
            {
                key = "test-user",
                name = "Test User"
            }
        };

        var response = await client.PostAsJsonAsync("/api/public/sdk/client/latest-all?timestamp=0", request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task TrackInsight_WithValidAuthHeader_Returns200()
    {
        var client = _app.CreateClient();
        client.DefaultRequestHeaders.Add("Authorization", TestData.ServerSecretString);

        var response = await client.PostAsJsonAsync("/api/public/insight/track", Array.Empty<object>());

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task TrackInsight_WithoutAuthHeader_Returns401()
    {
        var client = _app.CreateClient();

        var response = await client.PostAsJsonAsync("/api/public/insight/track", Array.Empty<object>());

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task EvaluateFeatureFlag_WithValidAuthHeader_IsNotUnauthorized()
    {
        var client = _app.CreateClient();
        client.DefaultRequestHeaders.Add("Authorization", TestData.ServerSecretString);

        var request = new
        {
            user = new
            {
                key = "test-user",
                name = "Test User"
            }
        };

        var response = await client.PostAsJsonAsync("/api/public/feature-flag/evaluate", request);

        Assert.NotEqual(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task EvaluateFeatureFlag_WithoutAuthHeader_Returns401()
    {
        var client = _app.CreateClient();

        var request = new
        {
            user = new
            {
                key = "test-user",
                name = "Test User"
            }
        };

        var response = await client.PostAsJsonAsync("/api/public/feature-flag/evaluate", request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task HealthCheck_WithoutAuthHeader_Returns200()
    {
        var client = _app.CreateClient();

        var response = await client.GetAsync("/health/liveness");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task AgentRegister_WithoutAuthHeader_Returns401()
    {
        // Agent uses a different auth model (relay-proxy key lookup)
        // Without auth, should fail but with a different path (no AuthenticationHandler involved)
        var client = _app.CreateClient();

        var response = await client.PostAsJsonAsync("/api/public/agent/register", "agent-id");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // ---- v2 (HMAC) token cases ----

    private HttpClient CreateClientWithClock(long timestamp, IStore? store = null)
    {
        var app = _app.WithWebHostBuilder(builder =>
        {
            builder.ConfigureTestServices(collection =>
            {
                collection.Replace(ServiceDescriptor.Singleton<ISystemClock>(new TestClock(timestamp)));
                if (store is not null)
                {
                    collection.Replace(ServiceDescriptor.Singleton(store));
                }
            });
        });

        return app.CreateClient();
    }

    [Fact]
    public async Task GetServerSideSdkPayload_WithValidV2Token_Returns200()
    {
        var client = CreateClientWithClock(TestData.ServerToken.Timestamp);
        client.DefaultRequestHeaders.Add("Authorization", TestData.ServerV2TokenString);

        var response = await client.GetAsync("/api/public/sdk/server/latest-all");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task GetServerSideSdkPayload_WithValidClientV2Token_Returns403()
    {
        // A client secret must not authenticate against the server endpoint. The token is a valid,
        // non-expired HMAC token, so authentication succeeds, but the server-secret policy rejects
        // the client secret type with 403 (matching the streaming path's secret-type check).
        var client = CreateClientWithClock(TestData.ClientToken.Timestamp);
        client.DefaultRequestHeaders.Add("Authorization", TestData.ClientV2TokenString);

        var response = await client.GetAsync("/api/public/sdk/server/latest-all");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task GetClientSideSdkPayload_WithValidServerV2Token_Returns403()
    {
        // A server secret must not authenticate against the client endpoint.
        var client = CreateClientWithClock(TestData.ServerToken.Timestamp);
        client.DefaultRequestHeaders.Add("Authorization", TestData.ServerV2TokenString);

        var request = new
        {
            user = new
            {
                key = "test-user",
                name = "Test User"
            }
        };

        var response = await client.PostAsJsonAsync("/api/public/sdk/client/latest-all?timestamp=0", request);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task GetClientSideSdkPayload_WithValidClientV2Token_IsNotUnauthorizedOrForbidden()
    {
        var client = CreateClientWithClock(TestData.ClientToken.Timestamp);
        client.DefaultRequestHeaders.Add("Authorization", TestData.ClientV2TokenString);

        var request = new
        {
            user = new
            {
                key = "test-user",
                name = "Test User"
            }
        };

        var response = await client.PostAsJsonAsync("/api/public/sdk/client/latest-all?timestamp=0", request);

        Assert.NotEqual(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.NotEqual(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task GetServerSideSdkPayload_WithExpiredV2Token_Returns401()
    {
        // Move the clock well past the token's expiry window.
        var expiredClock = TestData.ServerToken.Timestamp + 31 * 1000;
        var client = CreateClientWithClock(expiredClock);
        client.DefaultRequestHeaders.Add("Authorization", TestData.ServerV2TokenString);

        var response = await client.GetAsync("/api/public/sdk/server/latest-all");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task GetServerSideSdkPayload_WithMalformedV2Token_Returns401()
    {
        var client = CreateClientWithClock(TestData.ServerToken.Timestamp);
        client.DefaultRequestHeaders.Add("Authorization", "v2.garbage.signature");

        var response = await client.GetAsync("/api/public/sdk/server/latest-all");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task GetServerSideSdkPayload_V2TokenStoreUnavailable_Returns503()
    {
        // A store that throws on the v2 secrets lookup simulates a transient outage.
        // The auth handler must surface this as 503 (retryable), not 401.
        var faultyStore = new Mock<IStore>();
        faultyStore
            .Setup(store => store.GetSecretsAsync(It.IsAny<Guid>()))
            .ThrowsAsync(new Exception("store outage"));

        var client = CreateClientWithClock(TestData.ServerToken.Timestamp, faultyStore.Object);
        client.DefaultRequestHeaders.Add("Authorization", TestData.ServerV2TokenString);

        var response = await client.GetAsync("/api/public/sdk/server/latest-all");

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
    }
}
