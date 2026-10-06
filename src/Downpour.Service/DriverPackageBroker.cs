using Downpour.Contracts;
using Downpour.Core;
using Microsoft.Extensions.Logging;

namespace Downpour.Service;

/// <summary>Prepares driver package operations for review and records intent in the operation journal.</summary>
public sealed class DriverPackageBroker
{
    private readonly ILogger<DriverPackageBroker> _logger;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public DriverPackageBroker(ILogger<DriverPackageBroker> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Prepares a driver package operation: validates the request and records intent.
    /// This does not execute the operation; the user must consent before execution.
    /// </summary>
    public async Task<DriverPackageResponse> PrepareAsync(
        DriverPackageRequest request,
        CancellationToken cancellationToken = default)
    {
        if (request == null) throw new ArgumentNullException(nameof(request));

        var catalog = DefaultDriverActionCatalog.GetCatalog();
        var featureSwitches = DefaultDriverActionCatalog.GetDefaultFeatureSwitches();
        var validator = new DriverActionPolicyValidator(catalog, featureSwitches, DefaultDriverActionCatalog.CurrentPolicyVersion);

        var validation = validator.Validate(request);
        if (!validation.Valid)
        {
            return new DriverPackageResponse(
                SchemaVersion: 1,
                RequestId: request.RequestId,
                Accepted: false,
                ResultCode: validation.RejectionReason ?? ActionResultCodes.RejectedPolicy,
                OperationId: null,
                RespondedAtUtc: DateTimeOffset.UtcNow,
                Details: new Dictionary<string, string> { { "violations", string.Join("; ", validation.PolicyViolations) } },
                Warnings: validation.Warnings);
        }

        // For now, only prepare is implemented; execution is not implemented
        var operationId = Guid.NewGuid();
        _logger.LogInformation("Driver package action prepared: OperationId={OperationId}, ActionKind={ActionKind}, InfFile={InfFile}",
            operationId, request.ActionKind, request.DriverInfFile);

        return new DriverPackageResponse(
            SchemaVersion: 1,
            RequestId: request.RequestId,
            Accepted: true,
            ResultCode: ActionResultCodes.Accepted,
            OperationId: operationId.ToString("D"),
            RespondedAtUtc: DateTimeOffset.UtcNow,
            Details: new Dictionary<string, string>
            {
                { "operationId", operationId.ToString("D") },
                { "actionKind", request.ActionKind },
                { "infFile", request.DriverInfFile },
                { "targetHardwareId", request.TargetHardwareId }
            },
            Warnings: validation.Warnings);
    }

    /// <summary>
    /// Rejects execution while driver package mutation is unimplemented. Prepared intent remains pending.
    /// </summary>
    public async Task<DriverPackageResponse> ExecuteAsync(
        Guid operationId,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return await Task.FromResult(new DriverPackageResponse(
            SchemaVersion: 1,
            RequestId: Guid.Empty,
            Accepted: false,
            ResultCode: DriverActionResultCodes.RejectedNotImplemented,
            OperationId: operationId.ToString("D"),
            RespondedAtUtc: DateTimeOffset.UtcNow,
            Details: new Dictionary<string, string>
            {
                { "status", "execution-not-implemented" }
            },
            Warnings: new[] { "No driver package mutation was performed" }));
    }
}