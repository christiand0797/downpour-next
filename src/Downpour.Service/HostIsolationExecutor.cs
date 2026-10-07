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
/// Executes policy-checked, audited emergency host isolation with an enforced auto-expiry guarantee (DN-008 Phase 5).
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

            try
            {
                // Inbound and outbound block-all rules on every profile (Action 0 = Block; loopback is exempt).
                _backend.AddRule(RuleBlockOut, $"Downpour host isolation outbound block (expires {expiresAtUtc:O})", 0, 2, true, "*", 2147483647, "DownpourNext_Isolation");
                _backend.AddRule(RuleBlockIn, $"Downpour host isolation inbound block (expires {expiresAtUtc:O})", 0, 1, true, "*", 2147483647, "DownpourNext_Isolation");
            }
            catch (Exception ex)
            {
                // Roll back any partially added isolation rules and the scheduled release.
                TryRemoveRules();
                _releaseScheduler.Cancel();
                return (false, "firewall-error", $"Failed to configure host isolation firewall rules: {ex.Message}", [], DateTimeOffset.MinValue);
            }

            var record = new HostIsolationRecord(
                IsIsolated: true,
                IsolatedAtUtc: now,
                ExpiresAtUtc: expiresAtUtc,
                DurationMinutes: durationMinutes,
                Reason: reason,
                RulesCreated: rulesCreated);

            SaveState(record);
            _currentState = record;

            // Schedule auto-expiry
            var delay = expiresAtUtc - now;
            var token = _expiryCts.Token;
            _ = Task.Run(async () =>
            {
                try
                {
                    await Task.Delay(delay, token);
                    if (!token.IsCancellationRequested)
                    {
                        AutoExpireIsolation();
                    }
                }
                catch (OperationCanceledException) { }
            }, token);

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
            if (_currentState is null || !_currentState.IsIsolated)
            {
                // Ensure rules are removed even if state already says not isolated
                TryRemoveRules();
                return (true, "not-isolated", "Host is not currently isolated.");
            }

            _expiryCts?.Cancel();
            _expiryCts?.Dispose();
            _expiryCts = null;

            TryRemoveRules();
            _releaseScheduler.Cancel();

            var updated = _currentState with { IsIsolated = false };
            SaveState(updated);
            _currentState = updated;
        }

        return (true, "released", "Host isolation has been released and normal network traffic is restored.");
    }

    private void AutoExpireIsolation()
    {
        lock (_gate)
        {
            if (_currentState is null || !_currentState.IsIsolated) return;

            TryRemoveRules();
            _releaseScheduler.Cancel();

            var updated = _currentState with { IsIsolated = false };
            SaveState(updated);
            _currentState = updated;

            _audit.Record("auto-expire-isolation", "released", "host", "Host isolation automatically expired");
        }
    }

    /// <summary>
    /// Entry point for the scheduled task (<c>Downpour.Service.exe --release-isolation</c>): removes the isolation rules
    /// and marks the stored state released. Does nothing else.
    /// </summary>
    public static int ReleaseFromScheduledTask()
    {
        using var executor = new HostIsolationExecutor(releaseScheduler: new NoReleaseScheduler());
        executor.Release("Scheduled automatic release");
        executor._audit.Record("auto-expire-isolation", "released", "host", "Host isolation released by its scheduled task");
        return 0;
    }

    private sealed class NoReleaseScheduler : IIsolationReleaseScheduler
    {
        public string? Schedule(DateTimeOffset releaseAtUtc) => null;
        public void Cancel() { }
    }

    private void TryRemoveRules()
    {
        try { _backend.RemoveRule(RuleBlockOut); } catch { }
        try { _backend.RemoveRule(RuleBlockIn); } catch { }
        try { _backend.RemoveRule(RuleAllowLoopbackIn); } catch { }
        try { _backend.RemoveRule(RuleAllowLoopbackOut); } catch { }
    }

    private void RecoverStartupState()
    {
        lock (_gate)
        {
            var loaded = LoadState();
            if (loaded is { IsIsolated: true })
            {
                var now = DateTimeOffset.UtcNow;
                if (now >= loaded.ExpiresAtUtc)
                {
                    // Expired while service was stopped
                    TryRemoveRules();
                    var expired = loaded with { IsIsolated = false };
                    SaveState(expired);
                    _currentState = expired;
                    _audit.Record("startup-recovery", "released", "host", "Expired host isolation released during startup recovery");
                }
                else
                {
                    // Still active: schedule remaining time
                    _currentState = loaded;
                    var remaining = loaded.ExpiresAtUtc - now;
                    _expiryCts = new CancellationTokenSource();
                    var token = _expiryCts.Token;
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            await Task.Delay(remaining, token);
                            if (!token.IsCancellationRequested)
                            {
                                AutoExpireIsolation();
                            }
                        }
                        catch (OperationCanceledException) { }
                    }, token);
                }
            }
            else
            {
                _currentState = loaded;
            }
        }
    }

    private HostIsolationRecord? LoadState()
    {
        try
        {
            if (File.Exists(_storePath))
            {
                var bytes = File.ReadAllBytes(_storePath);
                return JsonSerializer.Deserialize<HostIsolationRecord>(bytes);
            }
        }
        catch { }

        return null;
    }

    private void SaveState(HostIsolationRecord record)
    {
        var temp = _storePath + ".tmp";
        try
        {
            var bytes = JsonSerializer.SerializeToUtf8Bytes(record, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllBytes(temp, bytes);
            File.Move(temp, _storePath, overwrite: true);
        }
        catch
        {
            try { File.Delete(temp); } catch { }
        }
    }

    public void Dispose()
    {
        _expiryCts?.Cancel();
        _expiryCts?.Dispose();
    }
}
