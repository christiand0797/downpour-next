<#
.SYNOPSIS
Signs release-manifest.json with an offline RSA key, producing release-manifest.json.sig.

.DESCRIPTION
The private key is never placed in the repository, the package output or CI. This script only reads a key file you
point it at and writes a detached base64 signature next to the manifest. Downpour.Core's ReleaseSignatureVerifier
checks it with a public key pinned into the build, so a compromised download host cannot substitute its own key.

.PARAMETER ManifestPath
Path to release-manifest.json.

.PARAMETER KeyPath
Path to the RSA private key in PEM form. Keep it offline (removable media, hardware-backed store).

.PARAMETER SelfTest
Generates an ephemeral 3072-bit key, signs and verifies a sample manifest, and exits without touching any file.

.EXAMPLE
pwsh -File tools/release/sign-release.ps1 -ManifestPath artifacts/DownpourNext-win-x64-0.1.25/release-manifest.json -KeyPath D:\keys\downpour-release.pem
#>
[CmdletBinding(DefaultParameterSetName = 'Sign')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Sign')]
    [string]$ManifestPath,

    [Parameter(Mandatory, ParameterSetName = 'Sign')]
    [string]$KeyPath,

    [Parameter(Mandatory, ParameterSetName = 'SelfTest')]
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security.Cryptography

function Read-Key([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Key file not found: $Path" }
    $pem = Get-Content -LiteralPath $Path -Raw
    $rsa = [System.Security.Cryptography.RSA]::Create()
    $rsa.ImportFromPem($pem)
    return $rsa
}

function New-Signature([byte[]]$Bytes, $Key) {
    return [Convert]::ToBase64String($Key.SignData($Bytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1))
}

function Test-Signature([byte[]]$Bytes, [string]$Signature, [string]$PublicKeyPem) {
    $rsa = [System.Security.Cryptography.RSA]::Create()
    $rsa.ImportFromPem($PublicKeyPem)
    return $rsa.VerifyData($Bytes, [Convert]::FromBase64String($Signature), [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
}

if ($SelfTest) {
    $key = [System.Security.Cryptography.RSA]::Create(3072)
    $sample = [Text.Encoding]::UTF8.GetBytes('{"schemaVersion":1,"files":[{"path":"Downpour.Desktop.exe","sha256":"00"}]}')
    $signature = New-Signature $sample $key
    $publicKey = $key.ExportSubjectPublicKeyInfoPem()
    if (-not (Test-Signature $sample $signature $publicKey)) { throw 'Self-test failed to verify its own signature.' }
    $tampered = [Text.Encoding]::UTF8.GetBytes('{"schemaVersion":1,"files":[]}')
    if (Test-Signature $tampered $signature $publicKey) { throw 'Self-test verified a tampered manifest.' }
    Write-Output 'Self-test passed: sign/verify round trip works and tampering is rejected.'
    exit 0
}

$resolvedManifest = (Resolve-Path -LiteralPath $ManifestPath).Path
$bytes = [IO.File]::ReadAllBytes($resolvedManifest)
if ($bytes.Length -eq 0) { throw "Manifest is empty: $resolvedManifest" }
if ($bytes.Length -gt 16MB) { throw "Manifest is larger than the 16 MiB signing bound." }

$rsa = Read-Key $KeyPath
try {
    if ($rsa.KeySize -lt 3072) { throw "The signing key must be RSA-3072 or stronger (found $($rsa.KeySize))." }
    $signature = New-Signature $bytes $rsa
    $signaturePath = "$resolvedManifest.sig"
    [IO.File]::WriteAllText($signaturePath, $signature + "`n", [Text.UTF8Encoding]::new($false))
    Write-Output "Signed $resolvedManifest -> $signaturePath (RSA-$($rsa.KeySize), SHA-256)."
}
finally {
    $rsa.Dispose()
}
