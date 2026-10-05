using System.Buffers.Binary;
using Downpour.Core;

namespace Downpour.Tests;

public sealed class StaticFileInspectorTests
{
    [Fact]
    public void InspectReportsHashPeArchitectureCertificatePresenceAndWritableExecutableSections()
    {
        using var stream = new MemoryStream(CreatePe());

        var result = StaticFileInspector.Inspect(stream, "sample.exe");

        Assert.True(result.IsPortableExecutable);
        Assert.Equal("x64", result.Architecture);
        Assert.Equal(1, result.SectionCount);
        Assert.Equal(1, result.WritableExecutableSectionCount);
        Assert.True(result.HasAuthenticodeCertificateTable);
        Assert.Equal(64, result.Sha256.Length);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1_700_000_000), result.PeTimestampUtc);
    }

    [Fact]
    public void InspectHashesNonPeAsMetadataWithoutCallingItMalicious()
    {
        using var stream = new MemoryStream("readable local data"u8.ToArray());

        var result = StaticFileInspector.Inspect(stream, "notes.exe");

        Assert.False(result.IsPortableExecutable);
        Assert.Equal("Not a PE image", result.Architecture);
        Assert.False(result.HasAuthenticodeCertificateTable);
        Assert.Equal(64, result.Sha256.Length);
    }

    [Fact]
    public void InspectRejectsOversizedFilesBeforeReading()
    {
        using var stream = new LengthOnlyStream(StaticFileInspector.MaximumFileSize + 1);

        Assert.Throws<InvalidDataException>(() => StaticFileInspector.Inspect(stream, "large.exe"));
    }

    [Fact]
    public void InspectRejectsMalformedPeHeaderOffsets()
    {
        var bytes = CreatePe();
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(0x3c, 4), int.MaxValue);
        using var stream = new MemoryStream(bytes);

        Assert.Throws<InvalidDataException>(() => StaticFileInspector.Inspect(stream, "bad.exe"));
    }

    [Fact]
    public void InspectRejectsCertificateTableOutsideFile()
    {
        var bytes = CreatePe();
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0x98 + 112 + 32, 4), 0xfffffff0);
        using var stream = new MemoryStream(bytes);

        Assert.Throws<InvalidDataException>(() => StaticFileInspector.Inspect(stream, "bad-signature.exe"));
    }

    private static byte[] CreatePe()
    {
        const int peOffset = 0x80;
        const int optionalStart = peOffset + 24;
        const int optionalSize = 240;
        const int sectionOffset = optionalStart + optionalSize;
        var bytes = new byte[0x410];
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0, 2), 0x5A4D);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(0x3c, 4), peOffset);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(peOffset, 4), 0x00004550);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(peOffset + 4, 2), 0x8664);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(peOffset + 6, 2), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(peOffset + 8, 4), 1_700_000_000);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(peOffset + 20, 2), optionalSize);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(optionalStart, 2), 0x20b);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(optionalStart + 112 + 32, 4), 0x400);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(optionalStart + 112 + 36, 4), 16);
        System.Text.Encoding.ASCII.GetBytes(".text").CopyTo(bytes, sectionOffset);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(sectionOffset + 36, 4), 0xA0000000);
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
        public override int Read(byte[] buffer, int offset, int count) => throw new InvalidOperationException("Oversize streams must be rejected before reading.");
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
