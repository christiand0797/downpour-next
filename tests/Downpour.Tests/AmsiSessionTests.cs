using Downpour.Service;

namespace Downpour.Tests;

public sealed class AmsiSessionTests
{
    [Theory]
    [InlineData(0, AmsiIntegration.AmsiVerdict.Clean)]
    [InlineData(1, AmsiIntegration.AmsiVerdict.NotDetected)]
    [InlineData(16384, AmsiIntegration.AmsiVerdict.BlockedByAdmin)]
    [InlineData(32767, AmsiIntegration.AmsiVerdict.BlockedByAdmin)]
    [InlineData(32768, AmsiIntegration.AmsiVerdict.Detected)]
    [InlineData(40000, AmsiIntegration.AmsiVerdict.Detected)]
    [InlineData(65535, AmsiIntegration.AmsiVerdict.Detected)]
    [InlineData(-1, AmsiIntegration.AmsiVerdict.Unknown)]
    public void InterpretsTheFullDocumentedMalwareRange(int result, AmsiIntegration.AmsiVerdict expected) =>
        Assert.Equal(expected, AmsiIntegration.InterpretResult(result));

    [Fact]
    public void MissingProviderIsUnknownAndRetriesAreBounded()
    {
        var clock = new TestClock();
        var backend = new FakeBackend { InitializeResult = unchecked((int)0x80070103) };
        var session = new AmsiSession(backend, clock);
        for (var i = 0; i < 100; i++)
        {
            var result = session.ScanString("private script");
            Assert.False(result.Succeeded);
            Assert.Null(result.Result);
            Assert.Equal(AmsiIntegration.AmsiVerdict.Unknown, result.Verdict);
        }
        Assert.Equal(1, backend.InitializeCalls);
        Assert.Equal(0, backend.ScanCalls);
        clock.Advance(TimeSpan.FromSeconds(30));
        backend.InitializeResult = 0;
        Assert.True(session.ScanString("private script").Succeeded);
        Assert.Equal(2, backend.InitializeCalls);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ScanFailuresNeverUseTheNativeOutputAsACleanOrMalwareVerdict(bool buffer)
    {
        var backend = new FakeBackend { ScanResult = unchecked((int)0x80070005), Verdict = 32768 };
        var session = new AmsiSession(backend);
        var outcome = buffer ? session.ScanBuffer([1, 2, 3]) : session.ScanString("private script");
        Assert.False(outcome.Succeeded);
        Assert.Null(outcome.Result);
        Assert.Equal(AmsiIntegration.AmsiVerdict.Unknown, outcome.Verdict);
        Assert.Equal(backend.ScanResult, outcome.HResult);
    }

    [Fact]
    public void SuccessWithANullContextFailsClosed()
    {
        var backend = new FakeBackend { NullContext = true };
        var session = new AmsiSession(backend);
        Assert.False(session.ScanString("private script").Succeeded);
        Assert.Equal(0, backend.ScanCalls);
    }

    [Fact]
    public async Task ContextCannotBeUninitializedDuringAnActiveScan()
    {
        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var backend = new FakeBackend { DuringScan = () => { entered.Set(); Assert.True(release.Wait(TimeSpan.FromSeconds(5))); } };
        var session = new AmsiSession(backend);
        var scan = Task.Run(() => session.ScanString("private script"));
        Assert.True(entered.Wait(TimeSpan.FromSeconds(5)));
        var stop = Task.Run(session.Uninitialize);
        try
        {
            await Task.Delay(50);
            Assert.False(stop.IsCompleted);
            Assert.Equal(0, backend.UninitializeCalls);
        }
        finally { release.Set(); }
        Assert.True((await scan).Succeeded);
        await stop;
        Assert.Equal(1, backend.UninitializeCalls);
    }

    private sealed class FakeBackend : IAmsiBackend
    {
        public int InitializeResult, ScanResult, Verdict = 1, InitializeCalls, ScanCalls, UninitializeCalls;
        public bool NullContext;
        public Action? DuringScan;
        public int Initialize(string name, out IntPtr context)
        {
            InitializeCalls++;
            context = InitializeResult < 0 || NullContext ? IntPtr.Zero : new IntPtr(123);
            return InitializeResult;
        }
        public void Uninitialize(IntPtr context) => UninitializeCalls++;
        public int ScanString(IntPtr context, string text, string name, IntPtr session, out int result)
        {
            ScanCalls++;
            DuringScan?.Invoke();
            result = Verdict;
            return ScanResult;
        }
        public int ScanBuffer(IntPtr context, byte[] content, string name, IntPtr session, out int result) =>
            ScanString(context, "", name, session, out result);
    }
}

internal sealed class TestClock : TimeProvider
{
    private DateTimeOffset _now = DateTimeOffset.UtcNow;
    public override DateTimeOffset GetUtcNow() => _now;
    public void Advance(TimeSpan duration) => _now += duration;
}
