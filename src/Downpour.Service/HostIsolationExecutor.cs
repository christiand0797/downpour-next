using System.Runtime.InteropServices;
using System.Text.Json;
using Downpour.Contracts;
using Downpour.Core;

namespace Downpour.Service;

public sealed record HostIsolationRecord(
    bool IsIsolated,
    DateTimeOffset IsolatedAtUtc,
    DateTimeOffset ExpiresAtUtc,
    int DurationMinutes,
    string? Reason,
    IReadOnlyList<string> RulesCreated);

/// <summary>
/// Executes policy-checked, audited emergency host isolation with scheduled automatic expiry (DN-008 Phase 5).
/// Creates inbound and outbound block-all rules across all profiles (loopback traffic is exempt from Windows Firewall).
/// Expiry does not depend on Downpour staying open: before any rule is added, a one-time Windows scheduled task is
/// registered that runs this binary with --release-isolation at the expiry time. If that cannot be scheduled, isolation
/// is refused. The in-process timer and startup recovery remain as additional release paths.
/// </summary>
public sealed class HostIsolationExecutor : IDisposable
{
    public const string RulePrefix = "DownpourNext_Isolation_";
    public const string RuleBlockOut = "DownpourNext_Isolation_Block_Out";
    public const string RuleBlockIn = "DownpourNext_Isolation_Block_In";
    // Retained only so rules created by earlier drafts are removed on release.
    public const string RuleAllowLoopbackIn = "DownpourNext_Isolation_Allow_Loopback_In";
    public const string RuleAllowLoopbackOut = "DownpourNext_Isolation_Allow_Loopback_Out";

    public const int MinimumDurationMinutes = 5;
    public const int MaximumDurationMinutes = 1440; // 24 hours
    public const int DefaultDurationMinutes = 30;

    private readonly IFirewallPolicyBackend _backend;
    private readonly ActionAuditLog _audit;
    private readonly string _storePath;
    private readonly Action? _lockWorkstationDelegate;
    private readonly IIsolationReleaseScheduler _releaseScheduler;
    private readonly object _gate = new();

    private CancellationTokenSource? _expiryCts;
    private HostIsolationRecord? _currentState;

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LockWorkStation();

    public HostIsolationExecutor(
        IFirewallPolicyBackend? backend = null,
        ActionAuditLog? audit = null,
        string? storePath = null,
        Action? lockWorkstationDelegate = null,
        IIsolationReleaseScheduler? releaseScheduler = null)
    {
        _releaseScheduler = releaseScheduler ?? new TaskSchedulerIsolationRelease();
        _backend = backend ?? new WindowsFirewallPolicyBackend();
        _audit = audit ?? ActionAuditLog.CreateForCurrentUser();
        _lockWorkstationDelegate = lockWorkstationDelegate;

        if (storePath != null)
        {
            _storePath = storePath;
        }
        else
        {
            var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DownpourNext", "state");
            SecureJournalDirectory.Ensure(root);
            _storePath = Path.Combine(root, "host-isolation.v1.json");
            SecureJournalDirectory.RestrictExistingFile(_storePath);
        }

        // Recover state on startup
        RecoverStartupState();
    }

    public bool IsIsolated
    {
        get
        {
            lock (_gate) return _currentState?.IsIsolated == true;
        }
    }

    public DateTimeOffset? ActiveUntilUtc
    {
        get
        {
            lock (_gate) return _currentState?.IsIsolated == true ? _currentState.ExpiresAtUtc : null;
        }
    }

    public HostIsolationRecord? CurrentState
    {
        get
        {
            lock (_gate) return _currentState;
        }
    }

    public (bool Allowed, string? DenyReason) ValidateDuration(int durationMinutes)
    {
        if (durationMinutes < MinimumDurationMinutes || durationMinutes > MaximumDurationMinutes)
        {
            return (false, $"Isolation duration must be between {MinimumDurationMinutes} minutes and {MaximumDurationMinutes} minutes ({MaximumDurationMinutes / 60} hours). Permanent isolation is prohibited.");
        }

        return (true, null);
    }

    public (bool Succeeded, string ResultCode, string Message, IReadOnlyList<string> RulesCreated, DateTimeOffset ExpiresAtUtc) Isolate(
        int durationMinutes,
        bool lockWorkstation,
        string? reason)
    {
        var (allowed, denyReason) = ValidateDuration(durationMinutes);
        if (!allowed)
        {
            return (false, "denied-invalid-duration", denyReason ?? "Invalid duration.", [], DateTimeOffset.MinValue);
        }

        var now = DateTimeOffset.UtcNow;
        var expiresAtUtc = now.AddMinutes(durationMinutes);
        var rulesCreated = new List<string> { RuleBlockOut, RuleBlockIn };

        lock (_gate)
        {
            if (_currentState?.IsIsolated == true)
                return (false, "already-isolated", "Release the existing isolation before starting another duration.", _currentState.RulesCreated, _currentState.ExpiresAtUtc);

            // Cancel any pending timer
            _expiryCts?.Cancel();
            _expiryCts?.Dispose();
            _expiryCts = new CancellationTokenSource();

            // Fail closed: the release must be guaranteed before the network is cut.
            if (_releaseScheduler.Schedule(expiresAtUtc) is { } scheduleError)
            {
                _audit.Record("isolate-host", "denied-release-unscheduled", "host", scheduleError);
                return (false, "denied-release-unscheduled", scheduleError, [], DateTimeOffset.MinValue);
            }

            var record = new HostIsolationRecord(true, now, expiresAtUtc, durationMinutes, reason, rulesCreated);
            // Persist recovery intent before the first system change. A failed write must not
            // leave firewall rules with no durable record of their expiry.
            try
            {
                SaveState(record);
                _audit.Record("isolate-host", "starting", "host", reason);
            }
            catch (Exception ex)
            {
                _releaseScheduler.Cancel();
                return (false, "recovery-state-error", $"Isolation was not applied: recovery state or audit could not be saved ({ex.GetType().Name}).", [], DateTimeOffset.MinValue);
            }
            _currentState = record;
            try
            {
                _backend.AddRule(RuleBlockOut, $"Downpour host isolation outbound block (expires {expiresAtUtc:O})", 0, 2, true, "*", 2147483647, "DownpourNext_Isolation");
                _backend.AddRule(RuleBlockIn, $"Downpour host isolation inbound block (expires {expiresAtUtc:O})", 0, 1, true, "*", 2147483647, "DownpourNext_Isolation");
            }
            catch (Exception ex)
            {
                var rollback = Release("Rollback after firewall setup failure");
                if (!rollback.Succeeded && IsIsolated) StartExpiryTimer(TimeSpan.FromSeconds(30));
                return (false, rollback.Succeeded ? "firewall-error" : "rollback-incomplete",
                    $"Isolation setup failed ({ex.GetType().Name}). {rollback.Message}",
                    IsIsolated ? rulesCreated : [], IsIsolated ? expiresAtUtc : DateTimeOffset.MinValue);
            }

            StartExpiryTimer(expiresAtUtc - now);

            // If lockWorkstation requested, trigger workstation lock
            if (lockWorkstation)
            {
                try
                {
                    if (_lockWorkstationDelegate != null)
                    {
                        _lockWorkstationDelegate();
                    }
                    else
                    {
                        LockWorkStation();
                    }
                }
                catch { }
            }
        }

        return (true, "isolated", $"Host has been isolated for {durationMinutes} minutes. Isolation will automatically expire at {expiresAtUtc:HH:mm:ss} UTC.", rulesCreated, expiresAtUtc);
    }

    public (bool Succeeded, string ResultCode, string Message) Release(string? reason)
    {
        lock (_gate)
        {
            bool wasIsolated = _currentState?.IsIsolated == true;
            var errors = TryRemoveRules();
            if (errors.Count > 0)
            {
                // Keep every release path alive. Never announce restored connectivity while
                // removal failed or absence could not be verified.
                _currentState ??= new HostIsolationRecord(true, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow,
                    0, "Recovery required", [RuleBlockOut, RuleBlockIn]);
                _currentState = _currentState with { IsIsolated = true };
                try { SaveState(_currentState); } catch (IOException) { } catch (UnauthorizedAccessException) { }
                _audit.Record("release-isolation", "cleanup-incomplete", "host", string.Join("; ", errors));
                return (false, "cleanup-incomplete", "Some isolation rules could not be removed or verified. Existing automatic recovery is retained; retry release with administrator access.");
            }

            _expiryCts?.Cancel();
            _expiryCts?.Dispose();
            _expiryCts = null;
            if (_currentState is not null) _currentState = _currentState with { IsIsolated = false };
            try
            {
                if (_currentState is not null) SaveState(_currentState);
                _audit.Record("release-isolation", "released", "host", reason);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Rules are gone, but retain the task to retry the durable bookkeeping.
                return (false, "released-state-error", "Isolation rules were removed; the recovery state or audit could not be saved. The scheduled recovery task is retained.");
            }
            _releaseScheduler.Cancel();
            return (true, wasIsolated ? "released" : "not-isolated", "Downpour isolation rules were verified absent. Other firewall policies still apply.");
        }
    }

    private void StartExpiryTimer(TimeSpan delay)
    {
        _expiryCts?.Cancel();
        _expiryCts?.Dispose();
        _expiryCts = new CancellationTokenSource();
        var token = _expiryCts.Token;
        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(delay < TimeSpan.Zero ? TimeSpan.Zero : delay, token);
                while (!token.IsCancellationRequested)
                {
                    var result = Release("Automatic expiry recovery");
                    if (result.Succeeded || !IsIsolated) break;
                    await Task.Delay(TimeSpan.FromSeconds(30), token);
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // An independent scheduled task remains registered if local audit/storage fails.
            }
        }, token);
    }

    /// <summary>
    /// Entry point for the scheduled task (<c>Downpour.Service.exe --release-isolation</c>): removes the isolation rules
    /// and marks the stored state released. Does nothing else.
    /// </summary>
    public static int ReleaseFromScheduledTask()
    {
        using var executor = new HostIsolationExecutor(releaseScheduler: new NoReleaseScheduler());
        var result = executor.Release("Scheduled automatic release");
        return result.Succeeded ? 0 : 1;
    }

    private sealed class NoReleaseScheduler : IIsolationReleaseScheduler
    {
        public string? Schedule(DateTimeOffset releaseAtUtc) => null;
        public void Cancel() { }
    }

    private IReadOnlyList<string> TryRemoveRules()
    {
        var errors = new List<string>();
        var names = new[] { RuleBlockOut, RuleBlockIn, RuleAllowLoopbackIn, RuleAllowLoopbackOut };
        foreach (var name in names)
        {
            try { _backend.RemoveRule(name); }
            catch (Exception ex) { errors.Add($"{name}: {ex.GetType().Name}"); }
        }
        try
        {
            if (_backend.EnumerateRules().Any(rule => names.Contains(rule.Name, StringComparer.OrdinalIgnoreCase)))
                errors.Add("Isolation rules remain present.");
        }
        catch (Exception ex) { errors.Add($"Cannot verify rule removal: {ex.GetType().Name}"); }
        return errors;
    }

    private void RecoverStartupState()
    {
        lock (_gate)
        {
            _currentState = LoadState();
            if (_currentState is not { IsIsolated: true }) return;
            var remaining = _currentState.ExpiresAtUtc - DateTimeOffset.UtcNow;
            if (remaining <= TimeSpan.Zero)
            {
                var result = Release("Expired isolation startup recovery");
                if (!result.Succeeded && IsIsolated) StartExpiryTimer(TimeSpan.FromSeconds(30));
            }
            else StartExpiryTimer(remaining);
        }
    }

    private HostIsolationRecord? LoadState()
    {
        try
        {
            if (File.Exists(_storePath))
            {
                if (new FileInfo(_storePath).Length > 64 * 1024) throw new IOException("Isolation state exceeds limit.");
                var bytes = File.ReadAllBytes(_storePath);
                return JsonSerializer.Deserialize<HostIsolationRecord>(bytes);
            }
        }
        catch { }

        return null;
    }

    private void SaveState(HostIsolationRecord record)
    {
        var temp = _storePath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            var bytes = JsonSerializer.SerializeToUtf8Bytes(record, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllBytes(temp, bytes);
            File.Move(temp, _storePath, overwrite: true);
        }
        catch
        {
            try { File.Delete(temp); } catch (IOException) { } catch (UnauthorizedAccessException) { }
            throw;
        }
    }

    public void Dispose()
    {
        _expiryCts?.Cancel();
        _expiryCts?.Dispose();
    }
}
