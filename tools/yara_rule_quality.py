r"""Measure bundled YARA rules against clean Windows system files (DN-026).

Any rule that matches a file shipped in C:\Windows\System32 (top-level *.exe and *.dll) is recorded as low
confidence in src/Downpour.Scanner/rule_quality.json. Low-confidence matches are shown in scan results but never
raised as triage alerts. Only aggregate per-rule hit counts are written; no file names or machine data.

Usage (after building tests in Debug):  python tools/yara_rule_quality.py
"""
import collections, datetime, glob, json, os, platform, subprocess, sys

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
exe = (glob.glob(os.path.join(root, r"src/Downpour.Scanner/bin/Debug/*/Downpour.Scanner.exe")) or [None])[0]
if not exe:
    sys.exit("Build src/Downpour.Scanner first.")
system32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
files = sorted(glob.glob(os.path.join(system32, "*.dll")) + glob.glob(os.path.join(system32, "*.exe")))
requests = "".join(json.dumps({"id": i, "path": path}) + "\n" for i, path in enumerate(files))
lines = subprocess.run([exe], input=requests.encode(), capture_output=True, check=True).stdout.decode().splitlines()
ready = json.loads(lines[0])
if ready.get("fatal"):
    sys.exit(ready["fatal"])
hits, scanned = collections.Counter(), 0
for line in lines[1:]:
    result = json.loads(line)
    if result["status"] in ("matched", "clean"):
        scanned += 1
    for key in {f'{m["namespace"]}:{m["rule"]}' for m in result["matches"]}:
        hits[key] += 1
report = {
    "schemaVersion": 1,
    "generatedOn": datetime.date.today().isoformat(),
    "corpus": f"Windows {platform.version()} System32 top-level .exe/.dll",
    "filesScanned": scanned,
    "engineVersion": ready["engineVersion"],
    "ruleCount": ready["ruleCount"],
    "policy": "A rule that matched any clean corpus file is low confidence: shown in scan results, never raised to triage.",
    "lowConfidence": {key: count for key, count in sorted(hits.items())},
}
out = os.path.join(root, "src", "Downpour.Scanner", "rule_quality.json")
with open(out, "w", encoding="utf-8", newline="\n") as handle:
    json.dump(report, handle, indent=2)
    handle.write("\n")
print(f"{scanned} files scanned; {len(hits)} of {ready['ruleCount']} rules are low confidence -> {out}")
