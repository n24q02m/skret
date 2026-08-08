# skret one-shot installer for Windows (PowerShell 5+).
# Usage:
#   iwr -useb https://skret.n24q02m.com/install.ps1 | iex
#   iwr -useb https://skret.n24q02m.com/install.ps1 | iex; & install -Version v1.0.0
# Flags:
#   -Version <tag>   install a specific release tag (default: latest)
#   -Prefix <path>   install target dir (default: $env:LOCALAPPDATA\Programs\skret)
#   -Quiet           suppress progress output

#Requires -Version 5.0
[CmdletBinding()]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'Quiet', Justification='Used in Log closure via script scope')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification='Installer progress output goes to host, not pipeline')]
param(
    [string]$Version = "",
    [string]$Prefix = "",
    [switch]$Quiet
)

$ErrorActionPreference = "Stop"
$Repo = "n24q02m/skret"

function Log($msg) { if (-not $Quiet) { Write-Host "==> $msg" } }
function Die($msg) { Write-Error "skret install: $msg"; exit 1 }

if (-not [System.Environment]::Is64BitOperatingSystem) {
    Die "32-bit Windows is not supported"
}

$arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }

if (-not $Version) {
    Log "Detecting latest release"
    try {
        $latest = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest"
        $Version = $latest.tag_name
    } catch {
        Die "could not detect latest version: $($_.Exception.Message)"
    }
}

$verTrim = $Version -replace '^v', ''

if (-not $Prefix) {
    $Prefix = Join-Path $env:LOCALAPPDATA "Programs\skret"
}
New-Item -ItemType Directory -Path $Prefix -Force | Out-Null

$asset       = "skret_${verTrim}_windows_${arch}.zip"
$url         = "https://github.com/$Repo/releases/download/$Version/$asset"
$checksumUrl = "https://github.com/$Repo/releases/download/$Version/checksums.txt"
# goreleaser signs with `--bundle`, so the release carries one signature artifact
# (checksums.txt.bundle). It does not publish separate .pem/.sig files.
$bundleUrl   = "https://github.com/$Repo/releases/download/$Version/checksums.txt.bundle"

$tmp = Join-Path $env:TEMP ("skret-install-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
try {
    Log "Downloading $asset"
    Invoke-WebRequest $url -OutFile (Join-Path $tmp "skret.zip") -UseBasicParsing
    Invoke-WebRequest $checksumUrl -OutFile (Join-Path $tmp "checksums.txt") -UseBasicParsing

    Log "Verifying SHA256 checksum"
    $actual = (Get-FileHash (Join-Path $tmp "skret.zip") -Algorithm SHA256).Hash.ToLower()
    # Match the filename field exactly. Select-String would read $asset as a
    # regex (the dots in "skret_1.16.0_..." match any character) and a substring
    # hit also lands on the SBOM row, "<asset>.sbom.json" -- so -First 1 picked
    # the right hash only for as long as goreleaser keeps writing the archive
    # row above the SBOM row. install.sh had the same bug and it was not latent
    # there: it matched both rows and failed every install with a bogus
    # "checksum mismatch".
    $expected = $null
    foreach ($row in Get-Content (Join-Path $tmp "checksums.txt")) {
        $fields = $row -split '\s+', 2
        if ($fields.Count -eq 2 -and $fields[1].Trim() -eq $asset) {
            $expected = $fields[0]
            break
        }
    }
    if (-not $expected) { Die "no checksum row for $asset in checksums.txt" }
    if ($expected -ne $actual) {
        Die "checksum mismatch (expected $expected, got $actual)"
    }

    if (Get-Command cosign -ErrorAction SilentlyContinue) {
        Log "Verifying cosign Sigstore signature"
        Invoke-WebRequest $bundleUrl -OutFile (Join-Path $tmp "checksums.txt.bundle") -UseBasicParsing
        & cosign verify-blob `
            --bundle (Join-Path $tmp "checksums.txt.bundle") `
            --certificate-identity-regexp "https://github.com/$Repo/.+" `
            --certificate-oidc-issuer "https://token.actions.githubusercontent.com" `
            (Join-Path $tmp "checksums.txt") 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Log "WARN: cosign verify failed - continuing (checksum already matched)"
        }
    } else {
        Log "cosign not installed - skipping signature check (checksum already verified)"
    }

    Log "Extracting"
    Expand-Archive (Join-Path $tmp "skret.zip") -DestinationPath $tmp -Force
    Copy-Item (Join-Path $tmp "skret.exe") -Destination (Join-Path $Prefix "skret.exe") -Force

    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($userPath -notlike "*$Prefix*") {
        [Environment]::SetEnvironmentVariable("Path", "$userPath;$Prefix", "User")
        Log "Added $Prefix to user PATH (restart shell to apply)"
    }

    $installed = & (Join-Path $Prefix "skret.exe") --version
    Log "Installed: $installed"
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
