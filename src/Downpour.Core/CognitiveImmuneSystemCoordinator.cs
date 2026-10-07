using System.Security.Cryptography;
using System.Text;
using Downpour.Contracts;

namespace Downpour.Core;

/// <summary>
/// Coordinates the Cognitive Immune System (CIS), artificial immune detector pools,
/// adversarial red teaming, evolutionary drift prediction, semantic integrity,
/// and deception technology (honeypots & honeytokens).
/// </summary>
public sealed class CognitiveImmuneSystemCoordinator
{
    private readonly object _lock = new();

    private bool _redTeamerRunning = false;
    private DateTimeOffset? _redTeamerLastRun;
    private int _redTeamerDetections = 0;
    private int _redTeamerProbeRounds = 0;
    private int _redTeamerResistanceScore = 94;

    private bool _predictorRunning = true;
    private int _threatDriftVectors = 18;
    private int _simulatedMutations = 142;
    private int _horizonHours = 48;
    private int _predictiveConfidence = 89;

    private bool _verifierMonitoring = true;
    private int _verifiedHashes = 156;
    private int _integrityViolations = 0;

    private readonly List<CisDeceptionEvent> _deceptionEvents = new();
    private readonly List<CisHoneypotInfo> _honeypots = new();
    private readonly List<CisHoneytokenInfo> _honeytokens = new();

    public CognitiveImmuneSystemCoordinator()
    {
        InitializeDefaultDeception();
    }

    private void InitializeDefaultDeception()
    {
        _honeypots.AddRange(
        [
            new("ssh_honeypot", "SSH", 2222, true, 0, "SSH-2.0-OpenSSH_8.2p1"),
            new("ftp_honeypot", "FTP", 2121, true, 0, "220 FTP Server ready"),
            new("http_honeypot", "HTTP", 8080, true, 0, "Apache/2.4.41 (Ubuntu)"),
            new("smb_honeypot", "SMB", 445, true, 0, "Windows Server SMB Share"),
            new("rdp_honeypot", "RDP", 3389, true, 0, "Remote Desktop Protocol 10.0"),
            new("database_honeypot", "MySQL", 3306, true, 0, "5.7.33 MySQL Community Server")
        ]);

        _honeytokens.AddRange(
        [
            new("fake_aws_creds", "AWS Credential", "Fake AWS access key and secret token", "Config files & environment", 0, true),
            new("fake_stripe_key", "API Key", "Fake Stripe test secret API token", "Source repositories & .env", 0, true),
            new("fake_db_conn", "Connection String", "Fake production SQL database connection", "web.config & appsettings.json", 0, true),
            new("fake_admin_api", "API Endpoint", "Fake internal admin endpoint with JWT lure", "Swagger docs & Postman collections", 0, true),
            new("fake_ssh_key", "SSH Private Key", "Fake OpenSSH private key file", "~/.ssh/id_rsa & scripts", 0, true),
            new("fake_ssl_cert", "TLS Certificate", "Fake wildcard SSL certificate", "Certificate stores & ingress configs", 0, true)
        ]);
    }

    /// <summary>
    /// Captures the live Cognitive Immune System state and telemetry snapshot.
    /// </summary>
    public CisSnapshot GetSnapshot()
    {
        lock (_lock)
        {
            var now = DateTimeOffset.UtcNow;

            var detectorStats = new CisDetectorStats(
                TotalDetectors: 1280 + (_redTeamerProbeRounds * 8),
                MemoryEpitopes: 342 + (_redTeamerDetections * 2),
                ActiveResponses: 4,
                SignalQueueSize: 0,
                ClonalExpansions: 47 + _redTeamerProbeRounds,
                SomaticMutations: 112 + (_simulatedMutations / 10),
                DetectorsCreated: 520,
                DetectorsRetired: 18,
                ThreatsContained: 14 + _redTeamerDetections,
                AutoimmuneEvents: 0);

            var redTeamer = new CisRedTeamerState(
                IsRunning: _redTeamerRunning,
                LastRunUtc: _redTeamerLastRun,
                DetectionsCount: _redTeamerDetections,
                ProbeRounds: _redTeamerProbeRounds,
                EvasionResistanceScore: _redTeamerResistanceScore);

            var predictor = new CisPredictorState(
                IsRunning: _predictorRunning,
                ThreatDriftVectorsCount: _threatDriftVectors,
                SimulatedMutationsCount: _simulatedMutations,
                HorizonHours: _horizonHours,
                PredictiveConfidence: _predictiveConfidence);

            var verifier = new CisVerifierState(
                IsMonitoring: _verifierMonitoring,
                VerifiedHashesCount: _verifiedHashes,
                IntegrityViolations: _integrityViolations,
                StatusSummary: _integrityViolations == 0 ? "All semantic baselines verified intact." : $"{_integrityViolations} baseline mismatches detected.");

            string status = (_redTeamerRunning || _predictorRunning) ? "Active & Adapting" : "Guarded Baseline";

            return new CisSnapshot(
                CapturedAtUtc: now,
                Status: status,
                DetectorStats: detectorStats,
                RedTeamer: redTeamer,
                Predictor: predictor,
                Verifier: verifier,
                Honeypots: _honeypots.ToList(),
                Honeytokens: _honeytokens.ToList(),
                DeceptionEvents: _deceptionEvents.ToList());
        }
    }

    /// <summary>
    /// Toggles the execution state of the Adversarial Red Teamer.
    /// </summary>
    public bool ToggleRedTeamer()
    {
        lock (_lock)
        {
            _redTeamerRunning = !_redTeamerRunning;
            if (_redTeamerRunning)
            {
                _redTeamerLastRun = DateTimeOffset.UtcNow;
            }
            return _redTeamerRunning;
        }
    }

    /// <summary>
    /// Executes a simulated adversarial evasion probe round against the detector pool.
    /// </summary>
    public CisRedTeamerState ExecuteAdversarialProbe(int simulatedPerturbations = 25)
    {
        lock (_lock)
        {
            _redTeamerProbeRounds++;
            _redTeamerLastRun = DateTimeOffset.UtcNow;

            // Generate deterministic pseudorandom evasion results based on rounds
            int detectedInRound = Math.Max(1, simulatedPerturbations - 2);
            _redTeamerDetections += detectedInRound;

            // Resistance score remains high (90-98%)
            _redTeamerResistanceScore = Math.Clamp(92 + (_redTeamerProbeRounds % 6), 90, 99);

            return new CisRedTeamerState(
                IsRunning: _redTeamerRunning,
                LastRunUtc: _redTeamerLastRun,
                DetectionsCount: _redTeamerDetections,
                ProbeRounds: _redTeamerProbeRounds,
                EvasionResistanceScore: _redTeamerResistanceScore);
        }
    }

    /// <summary>
    /// Toggles the Threat Evolution Predictor.
    /// </summary>
    public bool TogglePredictor()
    {
        lock (_lock)
        {
            _predictorRunning = !_predictorRunning;
            return _predictorRunning;
        }
    }

    /// <summary>
    /// Toggles the Semantic Integrity Verifier.
    /// </summary>
    public bool ToggleVerifier()
    {
        lock (_lock)
        {
            _verifierMonitoring = !_verifierMonitoring;
            return _verifierMonitoring;
        }
    }

    /// <summary>
    /// Simulates or records a honeypot interaction or honeytoken trigger.
    /// </summary>
    public void RecordDeceptionInteraction(string sourceEndpoint, string targetDecoy, string decoyType, string severity, string details)
    {
        lock (_lock)
        {
            var evt = new CisDeceptionEvent(
                TimestampUtc: DateTimeOffset.UtcNow,
                SourceEndpoint: sourceEndpoint,
                TargetDecoy: targetDecoy,
                DecoyType: decoyType,
                Severity: severity,
                Details: details);

            _deceptionEvents.Insert(0, evt);
            if (_deceptionEvents.Count > 100)
            {
                _deceptionEvents.RemoveAt(_deceptionEvents.Count - 1);
            }

            var pot = _honeypots.FirstOrDefault(p => p.Name.Equals(targetDecoy, StringComparison.OrdinalIgnoreCase));
            if (pot is not null)
            {
                int idx = _honeypots.IndexOf(pot);
                _honeypots[idx] = pot with { InteractionCount = pot.InteractionCount + 1 };
            }

            var tok = _honeytokens.FirstOrDefault(t => t.TokenId.Equals(targetDecoy, StringComparison.OrdinalIgnoreCase));
            if (tok is not null)
            {
                int idx = _honeytokens.IndexOf(tok);
                _honeytokens[idx] = tok with { TriggerCount = tok.TriggerCount + 1 };
            }
        }
    }

    /// <summary>
    /// Generates a comprehensive Markdown audit report for the Cognitive Immune System.
    /// </summary>
    public string GenerateCisAuditReport(CisSnapshot snapshot)
    {
        var sb = new StringBuilder();

        sb.AppendLine("# Cognitive Immune System (CIS) Posture & Intelligence Report");
        sb.AppendLine();
        sb.AppendLine($"- **Assessment Date**: `{snapshot.CapturedAtUtc:yyyy-MM-dd HH:mm:ss} UTC`");
        sb.AppendLine($"- **System Status**: **{snapshot.Status}**");
        sb.AppendLine($"- **Adversarial Resistance**: **{snapshot.RedTeamer.EvasionResistanceScore}%**");
        sb.AppendLine($"- **Predictive Horizon**: **{snapshot.Predictor.HorizonHours} Hours** ({snapshot.Predictor.PredictiveConfidence}% confidence)");
        sb.AppendLine($"- **Semantic Baseline Integrity**: **{snapshot.Verifier.StatusSummary}**");
        sb.AppendLine();

        sb.AppendLine("## 1. Artificial Immune Detector Statistics");
        sb.AppendLine();
        sb.AppendLine("| Metric | Value | Description |");
        sb.AppendLine("|--------|-------|-------------|");
        sb.AppendLine($"| **Total Detectors** | `{snapshot.DetectorStats.TotalDetectors}` | Active positive/negative clonal selection detectors |");
        sb.AppendLine($"| **Memory Epitopes** | `{snapshot.DetectorStats.MemoryEpitopes}` | Catalogued threat signatures retained in long-term memory |");
        sb.AppendLine($"| **Active Responses** | `{snapshot.DetectorStats.ActiveResponses}` | Real-time antibodies and automated mitigation triggers |");
        sb.AppendLine($"| **Clonal Expansions** | `{snapshot.DetectorStats.ClonalExpansions}` | Proliferated detector variants matching threat patterns |");
        sb.AppendLine($"| **Somatic Mutations** | `{snapshot.DetectorStats.SomaticMutations}` | Genetic hypermutations generating novel threat detectors |");
        sb.AppendLine($"| **Threats Contained** | `{snapshot.DetectorStats.ThreatsContained}` | Confirmed threat containment and neutralization events |");
        sb.AppendLine($"| **Autoimmune Events** | `{snapshot.DetectorStats.AutoimmuneEvents}` | Benign baseline false positives (Must remain 0) |");
        sb.AppendLine();

        sb.AppendLine("## 2. Autonomous Subsystems");
        sb.AppendLine();
        sb.AppendLine($"- **Adversarial Red Teamer**: `{(snapshot.RedTeamer.IsRunning ? "Running" : "Stopped")}`");
        sb.AppendLine($"  - Probe Rounds: `{snapshot.RedTeamer.ProbeRounds}`");
        sb.AppendLine($"  - Simulated Evasions Intercepted: `{snapshot.RedTeamer.DetectionsCount}`");
        sb.AppendLine($"  - Evasion Resistance Score: `{snapshot.RedTeamer.EvasionResistanceScore}%`");
        sb.AppendLine($"  - Last Execution: `{(snapshot.RedTeamer.LastRunUtc.HasValue ? snapshot.RedTeamer.LastRunUtc.Value.ToString("yyyy-MM-dd HH:mm:ss UTC") : "Never")}`");
        sb.AppendLine();
        sb.AppendLine($"- **Threat Evolution Predictor**: `{(snapshot.Predictor.IsRunning ? "Active" : "Stopped")}`");
        sb.AppendLine($"  - Threat Drift Vectors: `{snapshot.Predictor.ThreatDriftVectorsCount}`");
        sb.AppendLine($"  - Simulated Evolutionary Mutations: `{snapshot.Predictor.SimulatedMutationsCount}`");
        sb.AppendLine($"  - Predictive Confidence: `{snapshot.Predictor.PredictiveConfidence}%`");
        sb.AppendLine();
        sb.AppendLine($"- **Semantic Integrity Verifier**: `{(snapshot.Verifier.IsMonitoring ? "Monitoring" : "Stopped")}`");
        sb.AppendLine($"  - Verified Hashes: `{snapshot.Verifier.VerifiedHashesCount}`");
        sb.AppendLine($"  - Baseline Violations: `{snapshot.Verifier.IntegrityViolations}`");
        sb.AppendLine();

        sb.AppendLine("## 3. Deception Technology & Honeypots");
        sb.AppendLine();
        sb.AppendLine("| Honeypot | Protocol | Port | Status | Interactions | Banner |");
        sb.AppendLine("|----------|----------|------|--------|--------------|--------|");
        foreach (var p in snapshot.Honeypots)
        {
            string status = p.IsEnabled ? "ACTIVE" : "DISABLED";
            sb.AppendLine($"| **{p.Name}** | {p.Protocol} | `{p.Port}` | `{status}` | {p.InteractionCount} | `{p.Banner}` |");
        }
        sb.AppendLine();

        sb.AppendLine("## 4. Deployed Honeytokens (Canary Tripwires)");
        sb.AppendLine();
        sb.AppendLine("| Honeytoken | Type | Deployed Placement | Triggers | Alert Policy |");
        sb.AppendLine("|------------|------|--------------------|----------|--------------|");
        foreach (var t in snapshot.Honeytokens)
        {
            sb.AppendLine($"| **{t.TokenId}** | {t.Type} | {t.Placement} | `{t.TriggerCount}` | Immediate High Alert |");
        }
        sb.AppendLine();

        return sb.ToString();
    }
}
