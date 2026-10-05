using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Downpour.Core;

public sealed record StaticFileInspection(
    string FileName,
    long FileSize,
    string Sha256,
    bool IsPortableExecutable,
    string Architecture,
    int SectionCount,
    int WritableExecutableSectionCount,
    DateTimeOffset? PeTimestampUtc,
    bool HasAuthenticodeCertificateTable);

/// <summary>Reads a selected file's hash and bounded PE headers. This is static metadata, not malware detection.</summary>
public static class StaticFileInspector
{
    public const long MaximumFileSize = 256L * 1024 * 1024;
    private const int MaximumSections = 96;
    private const uint PeSignature = 0x00004550;

    public static StaticFileInspection Inspect(Stream stream, string fileName)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanRead || !stream.CanSeek) throw new ArgumentException("Inspection requires a readable, seekable stream.", nameof(stream));
        ArgumentException.ThrowIfNullOrWhiteSpace(fileName);
        var fileSize = stream.Length;
        if (fileSize < 0 || fileSize > MaximumFileSize) throw new InvalidDataException($"Selected files are limited to {MaximumFileSize / 1024 / 1024} MiB.");
        if (fileName.Length is < 1 or > 255 || fileName.Any(char.IsControl)) throw new InvalidDataException("The selected file name is invalid.");

        stream.Position = 0;
        var sha256 = Convert.ToHexString(SHA256.HashData(stream));
        stream.Position = 0;
        using var reader = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true);
        var dos = reader.ReadBytes(64);
        if (dos.Length < 64 || dos[0] != (byte)'M' || dos[1] != (byte)'Z')
            return Result(fileName, fileSize, sha256, false, "Not a PE image", 0, 0, null, false);

        var peOffset = BinaryPrimitives.ReadInt32LittleEndian(dos.AsSpan(0x3c, sizeof(int)));
        if (peOffset < 64 || peOffset > fileSize - 24) throw new InvalidDataException("The PE header offset is outside the file.");
        stream.Position = peOffset;
        if (reader.ReadUInt32() != PeSignature) throw new InvalidDataException("The PE signature is invalid.");

        var machine = reader.ReadUInt16();
        var sectionCount = reader.ReadUInt16();
        var timestamp = reader.ReadUInt32();
        _ = reader.ReadUInt32(); // symbol table pointer
        _ = reader.ReadUInt32(); // symbol count
        var optionalHeaderSize = reader.ReadUInt16();
        _ = reader.ReadUInt16(); // characteristics
        if (sectionCount > MaximumSections) throw new InvalidDataException("The PE section count exceeds the inspection limit.");

        var optionalStart = checked((long)peOffset + 24);
        var sectionTable = checked(optionalStart + optionalHeaderSize);
        if (sectionTable > fileSize || optionalHeaderSize < 2) throw new InvalidDataException("The PE optional header is outside the file.");
        stream.Position = optionalStart;
        var optionalMagic = reader.ReadUInt16();
        var (architecture, dataDirectoryOffset) = optionalMagic switch
        {
            0x10b => (Architecture(machine, is64Bit: false), 96),
            0x20b => (Architecture(machine, is64Bit: true), 112),
            _ => throw new InvalidDataException("The PE optional-header format is unsupported.")
        };

        var certificatePresent = false;
        var certificateEntryOffset = dataDirectoryOffset + (4 * 8);
        if (optionalHeaderSize >= certificateEntryOffset + 8)
        {
            stream.Position = optionalStart + certificateEntryOffset;
            var certificateOffset = reader.ReadUInt32();
            var certificateSize = reader.ReadUInt32();
            if ((certificateOffset == 0) != (certificateSize == 0)) throw new InvalidDataException("The PE certificate table is malformed.");
            if (certificateSize > 0)
            {
                if (certificateOffset > fileSize || certificateSize > fileSize - certificateOffset)
                    throw new InvalidDataException("The PE certificate table extends beyond the file.");
                certificatePresent = true;
            }
        }

        var sectionTableEnd = checked(sectionTable + (long)sectionCount * 40);
        if (sectionTableEnd > fileSize) throw new InvalidDataException("The PE section table is truncated.");
        var writableExecutable = 0;
        stream.Position = sectionTable;
        for (var index = 0; index < sectionCount; index++)
        {
            _ = reader.ReadBytes(8);
            stream.Position += 28;
            var characteristics = reader.ReadUInt32();
            if ((characteristics & 0xA0000000u) == 0xA0000000u) writableExecutable++;
        }

        DateTimeOffset? timestampUtc = timestamp == 0 ? null : DateTimeOffset.FromUnixTimeSeconds(timestamp);
        return Result(fileName, fileSize, sha256, true, architecture, sectionCount, writableExecutable, timestampUtc, certificatePresent);
    }

    private static StaticFileInspection Result(string name, long size, string hash, bool isPe, string architecture,
        int sections, int writableExecutable, DateTimeOffset? timestamp, bool certificateTable) =>
        new(name, size, hash, isPe, architecture, sections, writableExecutable, timestamp, certificateTable);

    private static string Architecture(ushort machine, bool is64Bit) => machine switch
    {
        0x014c => "x86",
        0x8664 => "x64",
        0xAA64 => "ARM64",
        0x01c4 => "ARM Thumb-2",
        0x0200 => "IA-64",
        _ => is64Bit ? $"Unknown 64-bit machine (0x{machine:X4})" : $"Unknown 32-bit machine (0x{machine:X4})"
    };
}
