using System.Security.Cryptography;

namespace Downpour.Service;

/// <summary>
/// One-time consent tokens minted when the desktop shows a preview. A token is bound to (operation, target) and carries the
/// SHA-256 the user saw; it expires after 60 seconds and is consumed on first use whether or not it matches.
/// </summary>
public sealed class ActionConsentStore(TimeProvider? time = null)
{
    public static readonly TimeSpan Lifetime = TimeSpan.FromSeconds(60);
    private const int MaximumOutstanding = 32;
    private readonly TimeProvider _time = time ?? TimeProvider.System;
    private readonly Dictionary<string, Entry> _tokens = new(StringComparer.Ordinal);
    private readonly object _gate = new();

    private sealed record Entry(string Operation, string Target, string Sha256, DateTimeOffset Expires);

    public (string Token, DateTimeOffset Expires) Mint(string operation, string target, string sha256)
    {
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        var expires = _time.GetUtcNow() + Lifetime;
        lock (_gate)
        {
            var now = _time.GetUtcNow();
            foreach (var expired in _tokens.Where(pair => pair.Value.Expires <= now).Select(pair => pair.Key).ToArray()) _tokens.Remove(expired);
            if (_tokens.Count >= MaximumOutstanding) _tokens.Remove(_tokens.MinBy(pair => pair.Value.Expires).Key);
            _tokens[token] = new Entry(operation, target, sha256.ToLowerInvariant(), expires);
        }
        return (token, expires);
    }

    public bool TryConsume(string? token, string operation, string target, out string sha256)
    {
        sha256 = "";
        if (token is not { Length: 64 }) return false;
        lock (_gate)
        {
            if (!_tokens.Remove(token, out var entry) || entry.Expires <= _time.GetUtcNow()) return false;
            if (!entry.Operation.Equals(operation, StringComparison.Ordinal) || !entry.Target.Equals(target, StringComparison.OrdinalIgnoreCase)) return false;
            sha256 = entry.Sha256;
            return true;
        }
    }
}
