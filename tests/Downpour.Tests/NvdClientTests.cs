using System.Text;
using Downpour.Core;

namespace Downpour.Tests;

public sealed class NvdClientTests
{
    private const string Payload = """
    {
      "format": "NVD_CVE",
      "version": "2.0",
      "timestamp": "2026-01-01T00:00:00.000",
      "vulnerabilities": [
        {
          "cve": {
            "id": "CVE-2026-0001",
            "published": "2026-01-01T00:00:00.000",
            "lastModified": "2026-01-02T00:00:00.000",
            "vulnStatus": "Analyzed",
            "descriptions": [ { "lang": "en", "value": "Range parsing fixture." } ],
            "configurations": [
              {
                "nodes": [
                  {
                    "cpeMatch": [
                      {
                        "vulnerable": true,
                        "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                        "versionStartIncluding": "1.0.0",
                        "versionEndExcluding": "2.0.0"
                      },
                      {
                        "vulnerable": true,
                        "criteria": "cpe:2.3:a:vendor:legacy:*:*:*:*:*:*:*:*",
                        "versionStartIncluding": "not\u0000a-version"
                      }
                    ]
                  }
                ]
              }
            ]
          }
        }
      ]
    }
    """;

    [Fact]
    public void ParsesNvdVersionRangeFieldsAndEvaluatesThem()
    {
        var snapshot = NvdClient.Parse(Encoding.UTF8.GetBytes(Payload));
        var entry = Assert.Single(snapshot!.Entries);
        Assert.Equal(2, entry.CpeMatches.Count);

        var ranged = entry.CpeMatches[0];
        Assert.Equal("*", ranged.Version);
        Assert.Equal("1.0.0", ranged.VersionStartIncluding);
        Assert.Equal("2.0.0", ranged.VersionEndExcluding);
        Assert.Null(ranged.VersionStartExcluding);
        Assert.Null(ranged.VersionEndIncluding);

        Assert.True(VulnerabilityMatchEngine.IsVersionAffected("1.5.0", ranged));
        Assert.False(VulnerabilityMatchEngine.IsVersionAffected("2.0.0", ranged));
        Assert.False(VulnerabilityMatchEngine.IsVersionAffected("0.9.0", ranged));
    }

    [Fact]
    public void MalformedOptionalBoundIsTreatedAsAbsentAndDoesNotDropTheCve()
    {
        var snapshot = NvdClient.Parse(Encoding.UTF8.GetBytes(Payload));
        var legacy = Assert.Single(snapshot!.Entries).CpeMatches[1];

        Assert.Equal("legacy", legacy.Product);
        Assert.Null(legacy.VersionStartIncluding);
        Assert.True(VulnerabilityMatchEngine.IsVersionAffected("9.9", legacy));
    }
}
