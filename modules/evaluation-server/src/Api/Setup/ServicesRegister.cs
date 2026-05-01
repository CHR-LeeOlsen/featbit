using Api.Cors;
using Api.Public;
using Api.RateLimiting;
using Api.Services;
using Domain.Shared;
using Domain.Workspaces;
using Infrastructure;
using Infrastructure.Caches;
using Infrastructure.Caches.Redis;
using Infrastructure.Services;
using Serilog;
using Streaming;
using Streaming.DependencyInjection;
using Streaming.Services;

namespace Api.Setup;

public static class ServicesRegister
{
    public static WebApplicationBuilder RegisterServices(this WebApplicationBuilder builder)
    {
        var services = builder.Services;
        var configuration = builder.Configuration;

        services.AddControllers();

        // serilog
        builder.Services.AddSerilog((_, lc) => ConfigureSerilog.Configure(lc, builder.Configuration));

        // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
        services.AddEndpointsApiExplorer();
        services.AddSwaggerGen();

        // health check dependencies
        services.AddHealthChecks().AddReadinessChecks(configuration);

        // cors
        builder.AddCustomCors();

        // add bounded memory cache
        services.AddSingleton<BoundedMemoryCache>();

        // streaming services
        services
            .AddStreamingCore(options => configuration.GetSection(StreamingOptions.Streaming).Bind(options))
            .UseStore(configuration)
            .UseMq(configuration);

        // rate limiting
        if (configuration.IsRateLimitingEnabled())
        {
            builder.AddRateLimiting();
        }

        // application services
        LicenseVerifier.ImportPublicKey(configuration["PublicKey"]);
        services.AddTransient<IRelayProxyAppService, RelayProxyAppService>();
        services.AddTransient<IFeatureFlagService, FeatureFlagService>();

        // token result cache — Redis when available, otherwise in-process memory
        var cacheProvider = configuration.GetCacheProvider();
        if (cacheProvider == CacheProvider.Redis)
        {
            services.AddSingleton<ITokenResultCache>(sp =>
                new RedisTokenResultCache(sp.GetRequiredService<IRedisClient>()));
        }
        else
        {
            services.AddSingleton<ITokenResultCache>(sp =>
                new MemoryTokenResultCache(sp.GetRequiredService<BoundedMemoryCache>().Instance));
        }

        // token validation service (shared by WebSocket and REST auth)
        services.AddSingleton<ITokenValidator, TokenValidationService>();

        // action filter for public API token auth
        services.AddScoped<TokenAuthFilter>();

        return builder;
    }
}