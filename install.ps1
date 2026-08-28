# skret one-shot installer for Windows (PowerShell 5+).
# Usage:
#   iwr -useb https://skret.n24q02m.com/install.ps1 | iex
#   iwr -useb https://skret.n24q02m.com/install.ps1 | iex; & install -Version v1.0.0
# Flags:
#   -Version <tag>   install a specific release tag (default: latest)
#   -Prefix <path>   install target dir (default: $env:LOCALAPPDATA\Programs\skret)
#   -Quiet           suppress progress output
# Env:
#   $env:SKRET_INSECURE_SKIP_VERIFY = "1"   install only with an explicit signature-verification bypass

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

function Protect-OwnerOnlyDirectory([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        Die "staging directory was not created: $Path"
    }
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    # Remove inherited entries, then grant only the current Windows identity
    # explicit full control (including files and child directories).
    $acl.SetAccessRuleProtection($true, $false)
    $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList @(
        $identity,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        $inheritance,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Assert-NoReparsePointInAncestorPath([string]$Path) {
$fullPath = [System.IO.Path]::GetFullPath($Path)
$root = [System.IO.Path]::GetPathRoot($fullPath)
$separators = [char[]]@(
    [System.IO.Path]::DirectorySeparatorChar,
    [System.IO.Path]::AltDirectorySeparatorChar
)
$rootCompare = $root.TrimEnd($separators)
if ([string]::IsNullOrEmpty($rootCompare)) { $rootCompare = $root }
$current = $fullPath.TrimEnd($separators)
if ([string]::IsNullOrEmpty($current)) { $current = $root }

while ($true) {
    if (Test-Path -LiteralPath $current) {
        $item = Get-Item -LiteralPath $current -Force
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            Die "destination path contains a symlink or reparse-point ancestor: $current"
        }
    }
    if ($current -eq $rootCompare) { break }
    $parent = [System.IO.Directory]::GetParent($current)
    if ($null -eq $parent) { break }
    $parentPath = $parent.FullName
    if ($parentPath -eq $current) { break }
    $current = $parentPath.TrimEnd($separators)
    if ([string]::IsNullOrEmpty($current)) { $current = $root }
}
}

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

$asset       = "skret_${verTrim}_windows_${arch}.zip"
$url         = "https://github.com/$Repo/releases/download/$Version/$asset"
$checksumUrl = "https://github.com/$Repo/releases/download/$Version/checksums.txt"
# goreleaser signs with `--bundle`, so the release carries one signature artifact
# (checksums.txt.bundle). It does not publish separate .pem/.sig files.
$bundleUrl   = "https://github.com/$Repo/releases/download/$Version/checksums.txt.bundle"

# SAFE-ARCHIVE-V1 Policy Constants
$MaxEntries    = 16
$MaxTotalBytes = 104857600  # 100 MiB
$MaxEntryBytes = 104857600  # 100 MiB
$MaxRatio      = 20
$AllowedFiles  = @(
    "skret.exe",
    "LICENSE", "LICENSE.txt", "LICENSE.md",
    "README", "README.md", "README.txt",
    "CHANGELOG", "CHANGELOG.md", "CHANGELOG.txt"
)

function Test-SafeArchiveV1([string]$zipPath) {
    if (-not (Test-Path -LiteralPath $zipPath)) {
        Die "SAFE-ARCHIVE-V1: archive file missing at $zipPath"
    }
    $zipItem = Get-Item -LiteralPath $zipPath -Force
    if ($zipItem.Length -le 0) {
        Die "SAFE-ARCHIVE-V1: archive file is empty"
    }

    [System.Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null
    $zip = $null
    try {
        try {
            $zip = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
        } catch {
            Die "SAFE-ARCHIVE-V1: unable to open zip archive: $($_.Exception.Message)"
        }

        if ($zip.Entries.Count -eq 0) {
            Die "SAFE-ARCHIVE-V1: archive has no entries"
        }
        if ($zip.Entries.Count -gt $MaxEntries) {
            Die "SAFE-ARCHIVE-V1: entry count exceeds maximum $MaxEntries (found $($zip.Entries.Count))"
        }

        $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        [int64]$totalUncompressed = 0
        $hasBinary = 0

        foreach ($entry in $zip.Entries) {
            $name = $entry.FullName
            # A release is a strict root-only file set. This also rejects drive
            # paths, UNC paths, backslashes, and NTFS alternate data streams.
            if ($name -match '[/\\:]' -or $name -match '^\.\.' -or $name -eq '.') {
                Die "SAFE-ARCHIVE-V1: illegal path, stream, or traversal in entry: $name"
            }
            if ($name -notmatch '^[A-Za-z0-9._-]+$') {
                Die "SAFE-ARCHIVE-V1: unsafe characters in entry name: $name"
            }
            if ($AllowedFiles -notcontains $name) {
                Die "SAFE-ARCHIVE-V1: unexpected file in release archive: $name"
            }
            if (-not $seen.Add($name)) {
                Die "SAFE-ARCHIVE-V1: duplicate or case-colliding entry name: $name"
            }

            # Validate Unix external attributes when present to reject symlinks,
            # hardlinks, directories, devices, and other non-regular entries.
            $unixMode = ($entry.ExternalAttributes -shr 16) -band 0xFFFF
            if ($unixMode -ne 0) {
                $fileType = $unixMode -band 0xF000
                if ($fileType -ne 0x8000) {
                    Die "SAFE-ARCHIVE-V1: non-regular file entry: $name (mode: 0x$($unixMode.ToString('X')) )"
                }
            }

            [int64]$entryLength = $entry.Length
            if ($entryLength -gt $MaxEntryBytes) {
                Die "SAFE-ARCHIVE-V1: entry size exceeds maximum: $name ($entryLength > $MaxEntryBytes)"
            }
            $totalUncompressed += $entryLength
            if ($name -eq "skret.exe") {
                $hasBinary++
            }
        }

        if ($hasBinary -ne 1) {
            Die "SAFE-ARCHIVE-V1: archive must contain exactly one skret.exe binary (found $hasBinary)"
        }
        if ($totalUncompressed -gt $MaxTotalBytes) {
            Die "SAFE-ARCHIVE-V1: total uncompressed size exceeds maximum ($totalUncompressed > $MaxTotalBytes)"
        }
        if ($zipItem.Length -le 0 -or ($totalUncompressed / [double]$zipItem.Length) -gt $MaxRatio) {
            if ($zipItem.Length -le 0) {
                Die "SAFE-ARCHIVE-V1: archive size is unavailable for compression-ratio validation"
            }
            Die "SAFE-ARCHIVE-V1: compression ratio bomb detected ($totalUncompressed / $($zipItem.Length) > $MaxRatio)"
        }
    } finally {
        if ($null -ne $zip) {
            $zip.Dispose()
        }
    }
}

$tmp = Join-Path $env:TEMP ("skret-install-" + [guid]::NewGuid())
$stageDir = $null
$dest = Join-Path $Prefix "skret.exe"
$guid = [guid]::NewGuid().ToString("N")
$destTmp = Join-Path $Prefix (".skret.tmp." + $guid + ".exe")
$destBak = Join-Path $Prefix (".skret.bak." + $guid + ".exe")
$hadPrior = $false
$priorStashed = $false
$newInstalled = $false
$installOk = $false

try {
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
    Protect-OwnerOnlyDirectory $tmp

    Log "Downloading $asset"
    Invoke-WebRequest $url -OutFile (Join-Path $tmp "skret.zip") -UseBasicParsing
    Invoke-WebRequest $checksumUrl -OutFile (Join-Path $tmp "checksums.txt") -UseBasicParsing

    Log "Verifying SHA256 checksum"
    $actual = (Get-FileHash (Join-Path $tmp "skret.zip") -Algorithm SHA256).Hash.ToLowerInvariant()
    $expected = $null
    $matchingRows = 0
    $lineNumber = 0
    foreach ($rawRow in Get-Content -LiteralPath (Join-Path $tmp "checksums.txt")) {
        $lineNumber++
        $row = ([string]$rawRow).Trim()
        if ($row.Length -eq 0) { continue }
        $fields = $row -split '\s+'
        if ($fields.Count -ne 2 -or $fields[0] -notmatch '^[0-9A-Fa-f]{64}$' -or $fields[1] -match '\s') {
            Die "malformed checksum row at line $lineNumber"
        }
        if ($fields[1] -eq $asset) {
            $matchingRows++
            $expected = $fields[0]
        }
    }
    if ($matchingRows -eq 0) { Die "no checksum row for $asset in checksums.txt" }
    if ($matchingRows -ne 1) { Die "duplicate checksum rows for $asset in checksums.txt" }
    $expected = $expected.ToLowerInvariant()
    if ($expected -ne $actual) {
        Die "checksum mismatch (expected $expected, got $actual)"
    }

    if ($env:SKRET_INSECURE_SKIP_VERIFY -eq "1") {
        Log "WARN: skipping cosign signature verification because SKRET_INSECURE_SKIP_VERIFY=1"
    } else {
        if (-not (Get-Command cosign -ErrorAction SilentlyContinue)) {
            Die "missing required signature verification tool: cosign (set `$env:SKRET_INSECURE_SKIP_VERIFY = '1' only to bypass verification)"
        }
        Log "Verifying cosign Sigstore signature"
        $bundlePath = Join-Path $tmp "checksums.txt.bundle"
        Invoke-WebRequest $bundleUrl -OutFile $bundlePath -UseBasicParsing
        if (-not (Test-Path -LiteralPath $bundlePath) -or (Get-Item -LiteralPath $bundlePath -Force).Length -le 0) {
            Die "missing or empty signature bundle for $Version"
        }
        # Keep cosign's stderr visible; only its normal output is suppressed.
        & cosign verify-blob `
            --bundle $bundlePath `
            --certificate-identity-regexp "https://github.com/$Repo/.+" `
            --certificate-oidc-issuer "https://token.actions.githubusercontent.com" `
            (Join-Path $tmp "checksums.txt") > $null
        if ($LASTEXITCODE -ne 0) {
            Die "signature verification failed for $Version. The download does not carry a valid Sigstore signature from $Repo. Set `$env:SKRET_INSECURE_SKIP_VERIFY = '1' to install anyway."
        }
    }

    Log "Validating release archive (SAFE-ARCHIVE-V1)"
    $zipPath = Join-Path $tmp "skret.zip"
    Test-SafeArchiveV1 $zipPath

    $stageDir = Join-Path $tmp "stage"
    New-Item -ItemType Directory -Path $stageDir -Force | Out-Null
    Protect-OwnerOnlyDirectory $stageDir

    Log "Extracting to staging"
    Expand-Archive -LiteralPath $zipPath -DestinationPath $stageDir -Force

    # Validate the exact extracted root tree, including hidden entries.
    foreach ($fileItem in Get-ChildItem -LiteralPath $stageDir -Force) {
        if ($fileItem.PSIsContainer) {
            Die "SAFE-ARCHIVE-V1: staging directory contains a nested directory: $($fileItem.Name)"
        }
        if (($fileItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            Die "SAFE-ARCHIVE-V1: staging directory contains a symlink/reparse point: $($fileItem.Name)"
        }
        if ($AllowedFiles -notcontains $fileItem.Name) {
            Die "SAFE-ARCHIVE-V1: staging directory contains unexpected extracted file: $($fileItem.Name)"
        }
    }

    $extractedBin = Join-Path $stageDir "skret.exe"
    if (-not (Test-Path -LiteralPath $extractedBin -PathType Leaf)) {
        Die "SAFE-ARCHIVE-V1: extracted binary missing at $extractedBin"
    }
    $extractedItem = Get-Item -LiteralPath $extractedBin -Force
    if (($extractedItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        Die "SAFE-ARCHIVE-V1: extracted binary is a link or reparse point"
    }

    # Reject reparse points on every existing destination-prefix ancestor before
    # creating the prefix or touching the target. Re-check after mkdir as well.
    Assert-NoReparsePointInAncestorPath $Prefix
    if (-not (Test-Path -LiteralPath $Prefix -PathType Container)) {
        New-Item -ItemType Directory -Path $Prefix -Force | Out-Null
    }
    Assert-NoReparsePointInAncestorPath $Prefix
    $prefixItem = Get-Item -LiteralPath $Prefix -Force
    if (-not $prefixItem.PSIsContainer) {
        Die "destination prefix is not a directory: $Prefix"
    }
    Assert-NoReparsePointInAncestorPath $dest

    if (Test-Path -LiteralPath $dest) {
        $destItem = Get-Item -LiteralPath $dest -Force
        if ($destItem.PSIsContainer -or (($destItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
            Die "destination target is not a regular file: $dest"
        }
        $hadPrior = $true
    } else {
        $hadPrior = $false
    }

    Log "Installing $dest (atomic swap)"
    Copy-Item -LiteralPath $extractedBin -Destination $destTmp -Force -ErrorAction Stop
    if ($hadPrior) {
        try {
            Move-Item -LiteralPath $dest -Destination $destBak -Force -ErrorAction Stop
        } catch {
            if ((Test-Path -LiteralPath $destBak) -and (-not (Test-Path -LiteralPath $dest))) {
                $priorStashed = $true
            }
            Die "failed to move prior binary aside: $($_.Exception.Message)"
        }
        $priorStashed = $true
    }

    try {
        Move-Item -LiteralPath $destTmp -Destination $dest -Force -ErrorAction Stop
    } catch {
        if ((Test-Path -LiteralPath $dest) -and (-not $hadPrior)) {
            $newInstalled = $true
        }
        Die "failed to activate staged binary: $($_.Exception.Message)"
    }
    $newInstalled = $true

    # Run smoke test on the new binary before committing the transaction.
    Log "Verifying installed binary"
    try {
        $installed = & $dest --version 2>&1
        if ($LASTEXITCODE -ne 0 -and $null -ne $LASTEXITCODE) {
            throw "process exited with code $LASTEXITCODE"
        }
    } catch {
        Die "installed binary verification failed (--version exited non-zero); rolling back to prior state"
    }

    # If backup cleanup fails, installOk remains false and finally restores it.
    if ($hadPrior -and (Test-Path -LiteralPath $destBak)) {
        Remove-Item -LiteralPath $destBak -Force -ErrorAction Stop
    }
    $installOk = $true

    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($userPath -notlike "*$Prefix*") {
        [Environment]::SetEnvironmentVariable("Path", "$userPath;$Prefix", "User")
        Log "Added $Prefix to user PATH (restart shell to apply)"
    }

    Log "Installed: $installed"
} finally {
    if (-not $installOk) {
        try {
            if (Test-Path -LiteralPath $destTmp) {
                Remove-Item -LiteralPath $destTmp -Force -ErrorAction Stop
            }
            if ($priorStashed) {
                if (Test-Path -LiteralPath $dest) {
                    Remove-Item -LiteralPath $dest -Force -ErrorAction Stop
                }
                if (Test-Path -LiteralPath $destBak) {
                    Move-Item -LiteralPath $destBak -Destination $dest -Force -ErrorAction Stop
                }
            } elseif ((-not $hadPrior) -and $newInstalled -and (Test-Path -LiteralPath $dest)) {
                Remove-Item -LiteralPath $dest -Force -ErrorAction Stop
            }
        } catch {
            Write-Error "skret install: rollback cleanup failed: $($_.Exception.Message)"
        }
    } elseif (Test-Path -LiteralPath $destTmp) {
        Remove-Item -LiteralPath $destTmp -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $tmp) {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}
