using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Downpour.Contracts;

namespace Downpour.Core;

public static class SafeFileSandbox
{
    public const long MaximumFileSize = 100L * 1024 * 1024; // 100 MiB
    private const int MaximumSections = 96;
    private const uint PeSignature = 0x00004550;

    private static readonly (string Api, string Category, string Description, int Weight)[] KnownIndicators =
    [
        ("VirtualAllocEx", "Process Injection", "Allocates virtual memory in remote process address space (T1055)", 25),
        ("WriteProcessMemory", "Process Injection", "Writes shellcode or payload into remote process memory (T1055)", 25),
        ("CreateRemoteThread", "Process Injection", "Executes remote thread in targeted process (T1055.002)", 25),
        ("QueueUserAPC", "Process Injection", "Queues asynchronous procedure call to execute code (T1055.004)", 20),
        ("SetThreadContext", "Process Injection", "Modifies thread execution context / register state (T1055.003)", 20),
        ("NtMapViewOfSection", "Process Injection", "Process hollowing / section mapping primitive (T1055.012)", 20),
        ("ReflectiveLoader", "Process Injection", "Reflective DLL injection loader stub (T1620)", 30),

        ("GetAsyncKeyState", "Spyware / Keylogger", "Monitors physical key presses asynchronously (T1056.001)", 20),
        ("GetKeyState", "Spyware / Keylogger", "Queries physical virtual key state (T1056.001)", 15),
        ("SetWindowsHookEx", "Spyware / Keylogger", "Installs global keyboard or message hook (T1056.001)", 25),
        ("RegisterHotKey", "Spyware / Keylogger", "Registers global hotkeys to intercept keystrokes (T1056.001)", 15),

        ("AmsiScanBuffer", "Defense Evasion", "Antimalware Scan Interface bypass or hook target (T1562.001)", 25),
        ("EtwEventWrite", "Defense Evasion", "Event Tracing for Windows telemetry tampering candidate (T1562.006)", 15),
        ("IsDebuggerPresent", "Defense Evasion", "Anti-debugging check to detect analysis environment (T1497.001)", 15),
        ("CheckRemoteDebuggerPresent", "Defense Evasion", "Anti-analysis check for attached debugger (T1497.001)", 15),
        ("MiniDumpWriteDump", "Credential Access", "LSASS process memory dumping primitive (T1003.001)", 20),

        ("powershell", "Execution & Scripting", "Invokes PowerShell interpreter for scripted execution (T1059.001)", 15),
        ("-enc", "Execution & Scripting", "Base64 encoded command-line execution flag (T1027)", 20),
        ("cmd.exe", "Execution & Scripting", "Invokes Windows command processor (T1059.003)", 15),
        ("downloadstring", "Command & Control", "WebClient in-memory payload download cradle (T1105)", 25),
        ("certutil", "Command & Control", "Living-off-the-land utility for file transfer (T1105)", 20),
        ("bitsadmin", "Command & Control", "Background Intelligent Transfer Service download (T1197)", 20),
        ("mshta", "Execution & Scripting", "Microsoft HTML Application host bypass (T1218.005)", 20)
    ];

    private static readonly string[] KnownPackerSections =
    [
        ".upx0", ".upx1", ".upx2", ".aspack", ".vmp", ".themida", ".pack", "pecompact", ".nsp", ".mpress", ".enigma"
    ];

    public static double ComputeShannonEntropy(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0) return 0.0;

        Span<int> frequencies = stackalloc int[256];
        foreach (var b in data)
        {
            frequencies[b]++;
        }

        double total = data.Length;
        double entropy = 0.0;
        for (int i = 0; i < 256; i++)
        {
            if (frequencies[i] == 0) continue;
            double p = frequencies[i] / total;
            entropy -= p * Math.Log2(p);
        }

        return entropy;
    }

    public static SandboxReport AnalyzeStatic(Stream stream, string filePath)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanRead || !stream.CanSeek)
            throw new ArgumentException("Stream must be readable and seekable.", nameof(stream));

        var fileSize = stream.Length;
        if (fileSize < 0 || fileSize > MaximumFileSize)
            throw new InvalidDataException($"File size exceeds the {MaximumFileSize / (1024 * 1024)} MiB static analysis limit.");

        var fileName = Path.GetFileName(filePath);
        if (string.IsNullOrWhiteSpace(fileName)) fileName = "sample.bin";

        // 1. Read bytes for hashes and entropy
        stream.Position = 0;
        var sha256 = Convert.ToHexStringLower(SHA256.HashData(stream));
        stream.Position = 0;
        var sha1 = Convert.ToHexStringLower(SHA1.HashData(stream));
        stream.Position = 0;
        var md5 = Convert.ToHexStringLower(MD5.HashData(stream));

        stream.Position = 0;
        byte[] fileBytes;
        using (var ms = new MemoryStream((int)Math.Min(fileSize, 32L * 1024 * 1024)))
        {
            stream.CopyTo(ms);
            fileBytes = ms.ToArray();
        }

        double entropy = ComputeShannonEntropy(fileBytes);
        bool isHighEntropy = entropy >= 7.0;

        var metrics = new SandboxFileMetrics(
            FilePath: filePath,
            FileName: fileName,
            FileSizeBytes: fileSize,
            Sha256: sha256,
            Sha1: sha1,
            Md5: md5,
            ShannonEntropy: entropy,
            IsHighEntropy: isHighEntropy,
            AnalyzedAtUtc: DateTimeOffset.UtcNow);

        // 2. Parse PE Headers & Sections
        stream.Position = 0;
        var peDetails = ParsePeHeaders(stream, fileSize);

        // 3. Scan for Suspicious API / Keyword Indicators
        var triggered = new List<SandboxTriggeredIndicator>();
        var riskReasons = new List<string>();

        // Entropy indicator
        if (entropy >= 7.2)
        {
            var ind = new SandboxTriggeredIndicator("Packaging", "Extreme Entropy", $"Shannon entropy {entropy:F2} / 8.00 indicates strongly packed or encrypted code.", 30);
            triggered.Add(ind);
            riskReasons.Add(ind.Description);
        }
        else if (entropy >= 7.0)
        {
            var ind = new SandboxTriggeredIndicator("Packaging", "High Entropy", $"Shannon entropy {entropy:F2} / 8.00 indicates packed or compressed payload.", 20);
            triggered.Add(ind);
            riskReasons.Add(ind.Description);
        }
        else if (entropy >= 6.5)
        {
            var ind = new SandboxTriggeredIndicator("Packaging", "Elevated Entropy", $"Shannon entropy {entropy:F2} / 8.00 indicates compressed sections or encrypted strings.", 10);
            triggered.Add(ind);
            riskReasons.Add(ind.Description);
        }

        // PE Structure indicators
        if (peDetails.IsPortableExecutable)
        {
            if (peDetails.WritableExecutableSectionCount > 0)
            {
                var ind = new SandboxTriggeredIndicator(
                    "Memory Protection",
                    "W^X Violation",
                    $"Contains {peDetails.WritableExecutableSectionCount} writable and executable section(s) (W^X violation; packer/shellcode vector).",
                    25);
                triggered.Add(ind);
                riskReasons.Add(ind.Description);
            }

            if (peDetails.SuspiciousSectionNames.Count > 0)
            {
                var names = string.Join(", ", peDetails.SuspiciousSectionNames);
                var ind = new SandboxTriggeredIndicator(
                    "Packer Identification",
                    "Suspicious Section Names",
                    $"Known packer or protector section names detected: {names}.",
                    20);
                triggered.Add(ind);
                riskReasons.Add(ind.Description);
            }
        }

        // Byte string pattern scanner (ASCII & UTF-16)
        ScanByteStrings(fileBytes, triggered, riskReasons);

        // 4. Calculate Risk Score & Verdict
        int score = 0;
        foreach (var ind in triggered)
        {
            score += ind.Weight;
        }

        // Combinatorial synergy: if injection + evasion + high entropy -> escalate
        bool hasInjection = triggered.Any(t => t.Category == "Process Injection");
        bool hasEvasion = triggered.Any(t => t.Category == "Defense Evasion");
        if (hasInjection && isHighEntropy) score += 15;
        if (hasInjection && hasEvasion) score += 15;

        score = Math.Clamp(score, 0, 100);

        string verdict = score switch
        {
            >= 50 => "MALICIOUS",
            >= 20 => "SUSPICIOUS",
            _ => "CLEAN"
        };

        const string notice = "Host detonation is disabled under least-privilege security policy. Executing untrusted binaries directly on the host system without an isolated container or Windows Sandbox broker is prohibited. Static analysis only.";

        return new SandboxReport(
            Metrics: metrics,
            PeDetails: peDetails,
            TriggeredIndicators: triggered,
            RiskScore: score,
            Verdict: verdict,
            RiskReasons: riskReasons,
            SecurityNotice: notice);
    }

    private static SandboxPeDetails ParsePeHeaders(Stream stream, long fileSize)
    {
        using var reader = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true);
        var dos = reader.ReadBytes(64);
        if (dos.Length < 64 || dos[0] != (byte)'M' || dos[1] != (byte)'Z')
        {
            return new SandboxPeDetails(false, "Non-PE / Script or Binary", 0, 0, null, false, []);
        }

        var peOffset = BinaryPrimitives.ReadInt32LittleEndian(dos.AsSpan(0x3c, sizeof(int)));
        if (peOffset < 64 || peOffset > fileSize - 24)
        {
            return new SandboxPeDetails(false, "Corrupt PE Header Offset", 0, 0, null, false, []);
        }

        stream.Position = peOffset;
        if (reader.ReadUInt32() != PeSignature)
        {
            return new SandboxPeDetails(false, "Invalid PE Signature", 0, 0, null, false, []);
        }

        var machine = reader.ReadUInt16();
        var sectionCount = reader.ReadUInt16();
        var timestamp = reader.ReadUInt32();
        _ = reader.ReadUInt32(); // symbol table pointer
        _ = reader.ReadUInt32(); // symbol count
        var optionalHeaderSize = reader.ReadUInt16();
        _ = reader.ReadUInt16(); // characteristics

        if (sectionCount > MaximumSections) sectionCount = MaximumSections;

        var optionalStart = checked((long)peOffset + 24);
        var sectionTable = checked(optionalStart + optionalHeaderSize);
        if (sectionTable > fileSize || optionalHeaderSize < 2)
        {
            return new SandboxPeDetails(false, "Corrupt PE Header Bounds", 0, 0, null, false, []);
        }

        stream.Position = optionalStart;
        var optionalMagic = reader.ReadUInt16();
        string architecture;
        int dataDirectoryOffset;

        switch (optionalMagic)
        {
            case 0x10b:
                architecture = machine == 0x014c ? "x86 (32-bit)" : $"PE32 (0x{machine:X4})";
                dataDirectoryOffset = 96;
                break;
            case 0x20b:
                architecture = machine == 0x8664 ? "x64 (64-bit)" : machine == 0xaa64 ? "ARM64" : $"PE32+ (0x{machine:X4})";
                dataDirectoryOffset = 112;
                break;
            default:
                architecture = "Unsupported PE Optional Header";
                dataDirectoryOffset = 96;
                break;
        }

        bool certificatePresent = false;
        var certificateEntryOffset = dataDirectoryOffset + (4 * 8);
        if (optionalHeaderSize >= certificateEntryOffset + 8)
        {
            stream.Position = optionalStart + certificateEntryOffset;
            var certOffset = reader.ReadUInt32();
            var certSize = reader.ReadUInt32();
            if (certOffset > 0 && certSize > 0 && certOffset < fileSize)
            {
                certificatePresent = true;
            }
        }

        var suspiciousSections = new List<string>();
        int writableExecutableCount = 0;

        if (sectionTable + (sectionCount * 40) <= fileSize)
        {
            stream.Position = sectionTable;
            for (int i = 0; i < sectionCount; i++)
            {
                var nameBytes = reader.ReadBytes(8);
                var name = Encoding.ASCII.GetString(nameBytes).TrimEnd('\0').Trim();

                foreach (var packerSec in KnownPackerSections)
                {
                    if (name.Contains(packerSec, StringComparison.OrdinalIgnoreCase))
                    {
                        if (!suspiciousSections.Contains(name, StringComparer.OrdinalIgnoreCase))
                            suspiciousSections.Add(name);
                    }
                }

                stream.Position += 28;
                var characteristics = reader.ReadUInt32();
                if ((characteristics & 0xA0000000u) == 0xA0000000u)
                {
                    writableExecutableCount++;
                }
            }
        }

        DateTimeOffset? timestampUtc = timestamp == 0 ? null : DateTimeOffset.FromUnixTimeSeconds(timestamp);

        return new SandboxPeDetails(
            IsPortableExecutable: true,
            Architecture: architecture,
            SectionCount: sectionCount,
            WritableExecutableSectionCount: writableExecutableCount,
            TimestampUtc: timestampUtc,
            HasAuthenticodeCertificate: certificatePresent,
            SuspiciousSectionNames: suspiciousSections);
    }

    private static void ScanByteStrings(byte[] data, List<SandboxTriggeredIndicator> triggered, List<string> riskReasons)
    {
        var foundIndicators = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var ind in KnownIndicators)
        {
            if (foundIndicators.Contains(ind.Api)) continue;

            // Check ASCII match
            byte[] asciiBytes = Encoding.ASCII.GetBytes(ind.Api);
            if (ContainsSequence(data, asciiBytes))
            {
                foundIndicators.Add(ind.Api);
                var item = new SandboxTriggeredIndicator(ind.Category, ind.Api, ind.Description, ind.Weight);
                triggered.Add(item);
                riskReasons.Add($"{ind.Category}: Detected reference to '{ind.Api}' - {ind.Description}");
                continue;
            }

            // Check UTF-16LE match
            byte[] utf16Bytes = Encoding.Unicode.GetBytes(ind.Api);
            if (ContainsSequence(data, utf16Bytes))
            {
                foundIndicators.Add(ind.Api);
                var item = new SandboxTriggeredIndicator(ind.Category, ind.Api, ind.Description, ind.Weight);
                triggered.Add(item);
                riskReasons.Add($"{ind.Category}: Detected UTF-16 reference to '{ind.Api}' - {ind.Description}");
            }
        }
    }

    private static bool ContainsSequence(byte[] source, byte[] pattern)
    {
        if (pattern.Length == 0 || source.Length < pattern.Length) return false;
        int max = source.Length - pattern.Length;
        for (int i = 0; i <= max; i++)
        {
            if (source[i] != pattern[0]) continue;
            bool match = true;
            for (int j = 1; j < pattern.Length; j++)
            {
                if (source[i + j] != pattern[j])
                {
                    match = false;
                    break;
                }
            }
            if (match) return true;
        }
        return false;
    }

    public static string GenerateTextReport(SandboxReport report)
    {
        var m = report.Metrics;
        var p = report.PeDetails;
        var sb = new StringBuilder();

        sb.AppendLine("=== DOWNPOUR FILE SANDBOX - STATIC THREAT REPORT ===");
        sb.AppendLine($"File:        {m.FileName}");
        sb.AppendLine($"Path:        {m.FilePath}");
        sb.AppendLine($"Size:        {m.FileSizeBytes:N0} bytes ({m.FileSizeBytes / 1024.0:F1} KB)");
        sb.AppendLine($"Analyzed:    {m.AnalyzedAtUtc:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine();

        sb.AppendLine("=== CRYPTOGRAPHIC CHECKSUMS ===");
        sb.AppendLine($"SHA-256:     {m.Sha256}");
        sb.AppendLine($"SHA-1:       {m.Sha1}");
        sb.AppendLine($"MD5:         {m.Md5}");
        sb.AppendLine();

        sb.AppendLine("=== ENTROPY & PACKING ASSESSMENT ===");
        sb.AppendLine($"Shannon Entropy: {m.ShannonEntropy:F3} / 8.000");
        sb.AppendLine($"Packing Status:  {(m.IsHighEntropy ? "[!] HIGH ENTROPY - LIKELY PACKED / ENCRYPTED" : "Normal Code / Resource Density")}");
        sb.AppendLine();

        if (p.IsPortableExecutable)
        {
            sb.AppendLine("=== PORTABLE EXECUTABLE (PE) STRUCTURE ===");
            sb.AppendLine($"Architecture:    {p.Architecture}");
            sb.AppendLine($"Section Count:   {p.SectionCount}");
            sb.AppendLine($"W^X Violations:  {p.WritableExecutableSectionCount} (Writable + Executable)");
            sb.AppendLine($"Authenticode:    {(p.HasAuthenticodeCertificate ? "Present" : "Not Present / Unsigned")}");
            sb.AppendLine($"Linker Stamp:    {(p.TimestampUtc.HasValue ? p.TimestampUtc.Value.ToString("yyyy-MM-dd HH:mm:ss UTC") : "None")}");
            if (p.SuspiciousSectionNames.Count > 0)
            {
                sb.AppendLine($"Packer Sections: {string.Join(", ", p.SuspiciousSectionNames)}");
            }
            sb.AppendLine();
        }

        sb.AppendLine($"=== BEHAVIORAL & API INDICATORS ({report.TriggeredIndicators.Count}) ===");
        if (report.TriggeredIndicators.Count == 0)
        {
            sb.AppendLine("  No suspicious API references or evasion strings detected.");
        }
        else
        {
            foreach (var ind in report.TriggeredIndicators)
            {
                sb.AppendLine($"  [{ind.Category}] {ind.Indicator} (+{ind.Weight} pts)");
                sb.AppendLine($"    {ind.Description}");
            }
        }
        sb.AppendLine();

        sb.AppendLine($"=== VERDICT: {report.Verdict} (Risk Score: {report.RiskScore}/100) ===");
        if (report.RiskReasons.Count > 0)
        {
            sb.AppendLine("Key Assessment Findings:");
            foreach (var reason in report.RiskReasons)
            {
                sb.AppendLine($"  - {reason}");
            }
        }
        sb.AppendLine();

        sb.AppendLine("=== SAFETY & EXECUTION POLICY NOTICE ===");
        sb.AppendLine(report.SecurityNotice);

        return sb.ToString();
    }
}
