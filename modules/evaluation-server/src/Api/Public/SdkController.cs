using Api.Authentication;
using Api.RateLimiting;
using Domain.EndUsers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Streaming.Services;

namespace Api.Public;

[EnableRateLimiting(RateLimitingPolicies.Sdk)]
public class SdkController : PublicApiControllerBase
{
    private readonly IDataSyncService _dataSyncService;

    public SdkController(IDataSyncService dataSyncService)
    {
        _dataSyncService = dataSyncService;
    }

    [Authorize(Policy = FeatBitAuthorizationPolicies.ServerSecret)]
    [HttpGet("server/latest-all")]
    public async Task<IActionResult> GetServerSideSdkPayloadAsync([FromQuery] long timestamp = 0)
    {
        var payload = await _dataSyncService.GetServerSdkPayloadAsync(EnvId, timestamp);
        if (payload.IsEmpty())
        {
            return Ok();
        }

        var bootstrap = new
        {
            messageType = "data-sync",
            data = payload
        };

        return new JsonResult(bootstrap);
    }

    [Authorize(Policy = FeatBitAuthorizationPolicies.ClientSecret)]
    [HttpPost("client/latest-all")]
    public async Task<IActionResult> GetClientSdkPayloadAsync(EndUser endUser, [FromQuery] long timestamp = 0)
    {
        if (!endUser.IsValid())
        {
            return BadRequest("invalid end user");
        }

        var payload = await _dataSyncService.GetClientSdkPayloadAsync(EnvId, endUser, timestamp);
        if (payload.IsEmpty())
        {
            return Ok();
        }

        var bootstrap = new
        {
            messageType = "data-sync",
            data = payload
        };

        return new JsonResult(bootstrap);
    }
}