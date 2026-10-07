using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Downpour.Core;

namespace Downpour.Tests;

public sealed class SafeFileSandboxTests
{
    [Fact]
    public void ComputeShannonEntropyReturnsZeroForEmptyOrConstantData()
    {
        Assert.Equal(0.0, SafeFileSandbox.ComputeShannonEntropy(ReadOnlySpan<byte>.Empty));

        var constantData = new byte[256]; // all zeroes
        Assert.Equal(0.0, SafeFileSandbox.ComputeShannonEntropy(constantData));
    }

    [Fact]
    public void ComputeShannonEntropyReturnsMaxEightForUniformDistribution()
    {
        var data = new byte[256 * 4];
        for (int i = 0; i < data.Length; i++)
        {
            data[i] = (byte)(i % 256);
        }

        var entropy = SafeFileSandbox.ComputeShannonEntropy(data);
        Assert.Equal(8.0, entropy, precision: 4);
    }

    [Fact]
    public void AnalyzeStaticOnSimpleTextProducesValidHashesAndCleanVerdict()
    {
        var content = "This is a clean plain text sample artifact for testing."u8.ToArray();
        using var stream = new MemoryStream(content);

        var report = SafeFileSandbox.AnalyzeStatic(stream, "clean_sample.txt");

        Assert.Equal("clean_sample.txt", report.Metrics.FileName);
        Assert.Equal(content.Length, report.Metrics.FileSizeBytes);
        Assert.Equal(64, report.Metrics.Sha256.Length);
        Assert.Equal(40, report.Metrics.Sha1.Length);
        Assert.Equal(32, report.Metrics.Md5.Length);
        Assert.False(report.PeDetails.IsPortableExecutable);
        Assert.Equal("CLEAN", report.Verdict);
        Assert.True(report.RiskScore < 20);
        Assert.Contains("Host detonation is disabled", report.SecurityNotice);
    }

    [Fact]
    public void AnalyzeStaticDetectsPeStructureAndWxViolations()
    {
        var peBytes = CreatePeWithSection(".text", 0xA0000000u); // Writable + Executable
        using var stream = new MemoryStream(peBytes);

        var report = SafeFileSandbox.AnalyzeStatic(stream, "test_binary.exe");

        Assert.True(report.PeDetails.IsPortableExecutable);
        Assert.Equal("x64 (64-bit)", report.PeDetails.Architecture);
        Assert.Equal(1, report.PeDetails.SectionCount);
        Assert.Equal(1, report.PeDetails.WritableExecutableSectionCount);
        Assert.True(report.PeDetails.HasAuthenticodeCertificate);

        var wxIndicator = Assert.Single(report.TriggeredIndicators, t => t.Indicator == "W^X Violation");
        Assert.Equal("Memory Protection", wxIndicator.Category);
        Assert.True(report.RiskScore >= 25);
    }

    [Fact]
    public void AnalyzeStaticDetectsKnownPackerSections()
    {
        var peBytes = CreatePeWithSection(".upx0", 0x60000020u);
        using var stream = new MemoryStream(peBytes);

        var report = SafeFileSandbox.AnalyzeStatic(stream, "packed_sample.exe");

        Assert.True(report.PeDetails.IsPortableExecutable);
        Assert.Contains(".upx0", report.PeDetails.SuspiciousSectionNames);

        var packerIndicator = Assert.Single(report.TriggeredIndicators, t => t.Indicator == "Suspicious Section Names");
        Assert.Equal("Packer Identification", packerIndicator.Category);
    }

    [Fact]
    public void AnalyzeStaticDetectsSuspiciousApisAndEscalatesVerdict()
    {
        // Embed Process Injection and Defense Evasion API strings
        var sb = new StringBuilder();
        sb.Append("Some normal binary header data ");
        sb.Append("VirtualAllocEx WriteProcessMemory CreateRemoteThread ");
        sb.Append("AmsiScanBuffer GetAsyncKeyState downloadstring");

        var data = Encoding.ASCII.GetBytes(sb.ToString());
        using var stream = new MemoryStream(data);

        var report = SafeFileSandbox.AnalyzeStatic(stream, "injected_artifact.bin");

        Assert.Contains(report.TriggeredIndicators, t => t.Indicator == "VirtualAllocEx");
        Assert.Contains(report.TriggeredIndicators, t => t.Indicator == "WriteProcessMemory");
        Assert.Contains(report.TriggeredIndicators, t => t.Indicator == "CreateRemoteThread");
        Assert.Contains(report.TriggeredIndicators, t => t.Indicator == "AmsiScanBuffer");
        Assert.Contains(report.TriggeredIndicators, t => t.Indicator == "GetAsyncKeyState");
        Assert.Contains(report.TriggeredIndicators, t => t.Indicator == "downloadstring");

        Assert.Equal("MALICIOUS", report.Verdict);
        Assert.True(report.RiskScore >= 50);
    }

    [Fact]
    public void AnalyzeStaticDetectsUtf16ApiStrings()
    {
        // Embed UTF-16 string
        var utf16Data = Encoding.Unicode.GetBytes("ReflectiveLoader powershell -enc");
        using var stream = new MemoryStream(utf16Data);

        var report = SafeFileSandbox.AnalyzeStatic(stream, "script_loader.dat");

        Assert.Contains(report.TriggeredIndicators, t => t.Indicator == "ReflectiveLoader");
        Assert.Contains(report.TriggeredIndicators, t => t.Indicator == "powershell");
        Assert.Contains(report.TriggeredIndicators, t => t.Indicator == "-enc");
        Assert.True(report.RiskScore >= 50);
        Assert.Equal("MALICIOUS", report.Verdict);
    }

    [Fact]
    public void GenerateTextReportIncludesAllKeySections()
    {
        var content = "Sample benign stream for report generation."u8.ToArray();
        using var stream = new MemoryStream(content);
        var report = SafeFileSandbox.AnalyzeStatic(stream, "report_target.bin");

        var text = SafeFileSandbox.GenerateTextReport(report);

        Assert.Contains("=== DOWNPOUR FILE SANDBOX - STATIC THREAT REPORT ===", text);
        Assert.Contains("=== CRYPTOGRAPHIC CHECKSUMS ===", text);
        Assert.Contains("=== ENTROPY & PACKING ASSESSMENT ===", text);
        Assert.Contains("=== BEHAVIORAL & API INDICATORS", text);
        Assert.Contains("=== VERDICT:", text);
        Assert.Contains("=== SAFETY & EXECUTION POLICY NOTICE ===", text);
        Assert.Contains(report.Metrics.Sha256, text);
    }

    [Fact]
    public void AnalyzeStaticRejectsOversizeFiles()
    {
        using var stream = new LengthOnlyStream(SafeFileSandbox.MaximumFileSize + 1);

        Assert.Throws<InvalidDataException>(() => SafeFileSandbox.AnalyzeStatic(stream, "too_large.iso"));
    }

    private static byte[] CreatePeWithSection(string sectionName, uint characteristics)
    {
        const int peOffset = 0x80;
        const int optionalStart = peOffset + 24;
        const int optionalSize = 240;
        const int sectionOffset = optionalStart + optionalSize;
        var bytes = new byte[0x410];
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0, 2), 0x5A4D);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(0x3c, 4), peOffset);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(peOffset, 4), 0x00004550);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(peOffset + 4, 2), 0x8664); // x64
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(peOffset + 6, 2), 1); // 1 section
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(peOffset + 8, 4), 1_700_000_000);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(peOffset + 20, 2), optionalSize);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(optionalStart, 2), 0x20b); // PE32+
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(optionalStart + 112 + 32, 4), 0x400); // Cert offset
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(optionalStart + 112 + 36, 4), 16); // Cert size
        Encoding.ASCII.GetBytes(sectionName).CopyTo(bytes, sectionOffset);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(sectionOffset + 36, 4), characteristics);
        return bytes;
    }

    private sealed class LengthOnlyStream(long length) : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => length;
        public override long Position { get; set; }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new InvalidOperationException("Oversize stream should be rejected before reading.");
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
