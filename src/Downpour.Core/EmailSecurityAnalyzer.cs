using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using Downpour.Contracts;

namespace Downpour.Core;

public static class EmailSecurityAnalyzer
{
    private const ushort DnsTypeText = 16;
    private static readonly string[] DkimSelectors = ["default", "google", "selector1", "selector2", "s1", "s2", "k1", "dkim"];

    [DllImport("dnsapi.dll", EntryPoint = "DnsQuery_W", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int DnsQuery(
        string pszName,
        ushort wType,
        uint options,
        IntPtr pExtra,
        out IntPtr ppQueryResults,
        IntPtr pReserved);

    [DllImport("dnsapi.dll", ExactSpelling = true)]
    private static extern void DnsRecordListFree(IntPtr pRecordList, int freeType);

    public static EmailSecurityCheckResult Analyze(string domain)
    {
        domain = (domain ?? "").Trim().TrimEnd('.').ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(domain) || !domain.Contains('.'))
        {
            return new EmailSecurityCheckResult(
                domain,
                "ERROR", "Invalid domain name", "",
                "ERROR", "Invalid domain name", "",
                "ERROR", "Invalid domain name", "");
        }

        // 1. SPF query on root domain
        var domainTxt = QueryTxtRecords(domain);
        var (spfStatus, spfVerdict, spfRecord) = EvaluateSpf(domainTxt);

        // 2. DMARC query on _dmarc.<domain>
        var dmarcTxt = QueryTxtRecords($"_dmarc.{domain}");
        var (dmarcStatus, dmarcVerdict, dmarcRecord) = EvaluateDmarc(dmarcTxt);

        // 3. DKIM query across common selectors
        var (dkimStatus, dkimVerdict, dkimSelector) = EvaluateDkim(domain);

        return new EmailSecurityCheckResult(
            Domain: domain,
            SpfStatus: spfStatus,
            SpfVerdict: spfVerdict,
            SpfRecord: spfRecord,
            DmarcStatus: dmarcStatus,
            DmarcVerdict: dmarcVerdict,
            DmarcRecord: dmarcRecord,
            DkimStatus: dkimStatus,
            DkimVerdict: dkimVerdict,
            DkimSelector: dkimSelector);
    }

    public static (string status, string verdict, string record) EvaluateSpf(IReadOnlyList<string> txtRecords)
    {
        var spfRecord = txtRecords.FirstOrDefault(r => r.ToLowerInvariant().Contains("v=spf1"));
        if (spfRecord == null)
        {
            return ("HIGH", "No SPF record found — domain can be spoofed freely", "");
        }

        var low = spfRecord.ToLowerInvariant();
        var match = Regex.Match(low, @"(?:^|\s)([\-~+]?)all(?:\s|$)");
        var sign = match.Success ? match.Groups[1].Value : "";

        if (sign == "-")
        {
            return ("OK", "SPF present with hard fail (-all) — strict policy", spfRecord);
        }

        if (sign == "~")
        {
            return ("WARN", "SPF softfail (~all) — spoofed mail may pass through spam filter", spfRecord);
        }

        if (sign == "+")
        {
            return ("HIGH", "SPF +all — any sender can spoof this domain without failure", spfRecord);
        }

        return ("WARN", "SPF present but missing an explicit 'all' mechanism", spfRecord);
    }

    public static (string status, string verdict, string record) EvaluateDmarc(IReadOnlyList<string> txtRecords)
    {
        var dmarcRecord = txtRecords.FirstOrDefault(r => r.ToLowerInvariant().Contains("v=dmarc1"));
        if (dmarcRecord == null)
        {
            return ("HIGH", "No DMARC record found — no reporting or spoof rejection policy", "");
        }

        var low = dmarcRecord.ToLowerInvariant();
        var pMatch = Regex.Match(low, @"(?:^|;)\s*p=([a-z]+)");
        var policy = pMatch.Success ? pMatch.Groups[1].Value : "";

        if (policy == "reject")
        {
            return ("OK", "DMARC p=reject — strongest policy, unauthorized mail is rejected", dmarcRecord);
        }

        if (policy == "quarantine")
        {
            return ("WARN", "DMARC p=quarantine — spoofed mail is delivered to spam/quarantine", dmarcRecord);
        }

        return ("HIGH", "DMARC p=none — monitoring mode only, no spoofing enforcement", dmarcRecord);
    }

    private static (string status, string verdict, string selector) EvaluateDkim(string domain)
    {
        foreach (var sel in DkimSelectors)
        {
            var target = $"{sel}._domainkey.{domain}";
            var records = QueryTxtRecords(target);
            var dkimRecord = records.FirstOrDefault(r =>
            {
                var low = r.ToLowerInvariant();
                return low.Contains("k=rsa") || low.Contains("v=dkim1") || low.Contains("p=");
            });

            if (dkimRecord != null)
            {
                return ("OK", $"DKIM key found for selector '{sel}'", $"{sel}._domainkey.{domain}");
            }
        }

        return ("INFO", "No common DKIM selector found (domain may use custom selector)", "");
    }

    public static List<string> QueryTxtRecords(string queryDomain)
    {
        var results = new List<string>();
        try
        {
            var status = DnsQuery(queryDomain, DnsTypeText, 0, IntPtr.Zero, out var pResults, IntPtr.Zero);
            if (status != 0 || pResults == IntPtr.Zero) return results;

            try
            {
                var cur = pResults;
                while (cur != IntPtr.Zero)
                {
                    var type = (ushort)Marshal.ReadInt16(cur, 16);
                    if (type == DnsTypeText)
                    {
                        var stringCount = Marshal.ReadInt32(cur, 32);
                        for (var i = 0; i < stringCount; i++)
                        {
                            var strPtr = Marshal.ReadIntPtr(cur, 40 + i * IntPtr.Size);
                            if (strPtr != IntPtr.Zero)
                            {
                                var text = Marshal.PtrToStringUni(strPtr);
                                if (!string.IsNullOrEmpty(text)) results.Add(text);
                            }
                        }
                    }

                    cur = Marshal.ReadIntPtr(cur, 0);
                }
            }
            finally
            {
                DnsRecordListFree(pResults, 0);
            }
        }
        catch
        {
            // Passive fallback; errors return empty list
        }

        return results;
    }
}
