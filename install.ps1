<#
.SYNOPSIS
Installs ScanForge on Windows.
.DESCRIPTION
Installs a verified prebuilt binary. -Full also installs pinned Go tools and
wafw00f through pipx when available; unsupported Windows tools are reported.
#>
param(
    [switch]$Full,
    [string]$Version = "latest",
    [string]$InstallDir = ""
)

$ErrorActionPreference = "Stop"
$Repo = "MikeRoss27/scanforge"
$RawBase = "https://raw.githubusercontent.com/$Repo/main"
$ApiBase = "https://api.github.com/repos/$Repo"

function Write-Info { Write-Host $args -ForegroundColor Cyan }
function Write-Ok { Write-Host "[OK] $args" -ForegroundColor Green }
function Write-Warn { Write-Warning $args }

function Get-ScanForgeArchitecture {
    param([System.Runtime.InteropServices.Architecture]$Architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture)
    if ($Architecture -ne [System.Runtime.InteropServices.Architecture]::X64) {
        throw "Unsupported Windows architecture: $Architecture. ScanForge publishes only windows/amd64 releases."
    }
    return "amd64"
}

function Get-ScanForgeVersion {
    param([string]$Requested)
    if ($Requested -eq "latest") {
        Write-Info "Fetching the latest available version..."
        $release = Invoke-RestMethod "$ApiBase/releases/latest"
        $Requested = $release.tag_name
    }
    $resolved = $Requested.TrimStart("v")
    if (-not $resolved -or $resolved -notmatch '^[0-9A-Za-z._+-]+$') {
        throw "Invalid version: $Requested"
    }
    return $resolved
}

function Get-ChecksumEntry {
    param([string]$Content, [string]$Artifact)
    foreach ($line in ($Content -split "`r?`n")) {
        if ($line -match '^([0-9A-Fa-f]{64})\s+\*?(.+)$' -and $Matches[2] -eq $Artifact) {
            return $Matches[1].ToLowerInvariant()
        }
    }
    return $null
}

function Assert-FileChecksum {
    param([string]$Path, [string]$Expected, [string]$Label)
    if ($Expected -notmatch '^[0-9a-f]{64}$') {
        throw "Invalid SHA-256 value for $Label"
    }
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $Expected) {
        throw "SHA-256 mismatch for ${Label}: expected $Expected, got $actual"
    }
    Write-Ok "SHA-256 verified ($Label)"
}

function Install-ScanForge {
    $architecture = Get-ScanForgeArchitecture
    $resolvedVersion = Get-ScanForgeVersion $Version
    Write-Info "Target version: $resolvedVersion"

    if (-not $script:InstallDir) {
        $script:InstallDir = Join-Path $env:LOCALAPPDATA "Programs\scanforge"
    }
    New-Item -ItemType Directory -Force -Path $script:InstallDir | Out-Null

    $releaseName = "scanforge_${resolvedVersion}_windows_${architecture}"
    $asset = "$releaseName.zip"
    $releaseBase = "https://github.com/$Repo/releases/download/v${resolvedVersion}"
    $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("scanforge-install-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $tempDir | Out-Null
    try {
        $archive = Join-Path $tempDir $asset
        Write-Info "Downloading $asset ..."
        Invoke-WebRequest "$releaseBase/$asset" -OutFile $archive

        try {
            $checksums = (Invoke-WebRequest "$releaseBase/checksums.txt").Content
            $expectedArchive = Get-ChecksumEntry $checksums $asset
            if (-not $expectedArchive) {
                throw "checksums.txt exists but has no entry for $asset"
            }
            Assert-FileChecksum $archive $expectedArchive "release archive $asset"
        } catch {
            $response = $_.Exception.Response
            if ($response -and [int]$response.StatusCode -eq 404) {
                Write-Warn "Release v$resolvedVersion has no checksums.txt; integrity verification is unavailable for this legacy release"
            } else {
                throw
            }
        }

        $extractDir = Join-Path $tempDir "extracted"
        Expand-Archive -LiteralPath $archive -DestinationPath $extractDir
        $binaryName = "$releaseName.exe"
        $binary = Join-Path $extractDir $binaryName
        if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
            throw "Expected binary not found in archive: $binaryName"
        }

        $embeddedFile = Join-Path $extractDir "$releaseName.sha256"
        if (Test-Path -LiteralPath $embeddedFile -PathType Leaf) {
            $embeddedExpected = Get-ChecksumEntry (Get-Content -LiteralPath $embeddedFile -Raw) $binaryName
            if (-not $embeddedExpected) {
                throw "Embedded checksum does not name $binaryName"
            }
            Assert-FileChecksum $binary $embeddedExpected "extracted binary $binaryName"
        } else {
            Write-Warn "Archive contains no binary checksum; archive checksum was the only integrity check"
        }

        Copy-Item -LiteralPath $binary -Destination (Join-Path $script:InstallDir "scanforge.exe") -Force
    } finally {
        Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $pathParts = @($currentPath -split ';' | Where-Object { $_ })
    if ($script:InstallDir -notin $pathParts) {
        $newPath = (@($pathParts) + $script:InstallDir) -join ';'
        [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
        Write-Ok "Directory added to the user PATH (reopen your terminal)"
    }
    Write-Ok "ScanForge $resolvedVersion installed in $script:InstallDir\scanforge.exe"
}

function Get-ToolVersions {
    $toolsFile = Join-Path $PSScriptRoot ".tools-version"
    $downloadedFile = $null
    if (-not (Test-Path -LiteralPath $toolsFile)) {
        Write-Info "Fetching pinned tool versions (.tools-version)..."
        $downloadedFile = Join-Path ([System.IO.Path]::GetTempPath()) ("scanforge-tools-" + [guid]::NewGuid().ToString("N"))
        Invoke-WebRequest "$RawBase/.tools-version" -OutFile $downloadedFile
        $toolsFile = $downloadedFile
    }
    try {
        $versions = @{}
        foreach ($line in Get-Content -LiteralPath $toolsFile) {
            if (-not $line -or $line.StartsWith('#')) { continue }
            if ($line -notmatch '^([A-Z_]+)=([0-9A-Za-z.+-]+)$') {
                throw "Invalid entry in .tools-version: $line"
            }
            $versions[$Matches[1]] = $Matches[2]
        }
        $required = @('SUBFINDER_VERSION', 'DNSX_VERSION', 'HTTPX_VERSION', 'NAABU_VERSION', 'KATANA_VERSION', 'NUCLEI_VERSION', 'TLSX_VERSION', 'GAU_VERSION', 'FFUF_VERSION', 'SHUFFLEDNS_VERSION', 'SECLISTS_VERSION', 'SECLISTS_DNS_SHA256', 'MASSDNS_VERSION', 'MASSDNS_SOURCE_SHA256', 'WAFW00F_VERSION')
        foreach ($key in $required) {
            if (-not $versions.ContainsKey($key)) { throw "Missing $key in .tools-version" }
        }
        return $versions
    } finally {
        if ($downloadedFile) { Remove-Item -LiteralPath $downloadedFile -Force -ErrorAction SilentlyContinue }
    }
}

function Install-GoTools {
    param([hashtable]$ToolsVersion)
    if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
        throw "Go is required for -Full. Install it from https://go.dev/dl/"
    }
    Write-Ok "Go is installed: $(go version)"
    $goTools = @(
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@$($ToolsVersion.SUBFINDER_VERSION)",
        "github.com/projectdiscovery/dnsx/cmd/dnsx@$($ToolsVersion.DNSX_VERSION)",
        "github.com/projectdiscovery/httpx/cmd/httpx@$($ToolsVersion.HTTPX_VERSION)",
        "github.com/projectdiscovery/naabu/v2/cmd/naabu@$($ToolsVersion.NAABU_VERSION)",
        "github.com/projectdiscovery/katana/cmd/katana@$($ToolsVersion.KATANA_VERSION)",
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@$($ToolsVersion.NUCLEI_VERSION)",
        "github.com/projectdiscovery/tlsx/cmd/tlsx@$($ToolsVersion.TLSX_VERSION)",
        "github.com/lc/gau/v2/cmd/gau@$($ToolsVersion.GAU_VERSION)",
        "github.com/ffuf/ffuf/v2@$($ToolsVersion.FFUF_VERSION)",
        "github.com/projectdiscovery/shuffledns/cmd/shuffledns@$($ToolsVersion.SHUFFLEDNS_VERSION)"
    )
    foreach ($tool in $goTools) {
        Write-Info "Installing $tool"
        & go install $tool
        if ($LASTEXITCODE -ne 0) { throw "go install failed: $tool" }
    }
}

function Install-PythonTools {
    param([hashtable]$ToolsVersion)
    if (Get-Command pipx -ErrorAction SilentlyContinue) {
        Write-Info "Installing wafw00f in an isolated pipx environment..."
        & pipx install --force "wafw00f==$($ToolsVersion.WAFW00F_VERSION.TrimStart('v'))"
        if ($LASTEXITCODE -ne 0) { throw "pipx failed to install wafw00f" }
    } elseif (Get-Command wafw00f -ErrorAction SilentlyContinue) {
        Write-Warn "wafw00f exists but pipx is unavailable, so its pinned version could not be enforced"
    } else {
        Write-Warn "pipx is unavailable. Install pipx, then run: pipx install wafw00f"
    }
}

function Install-DnsWordlist {
    param([hashtable]$ToolsVersion)
    $wordlistDir = Join-Path $env:LOCALAPPDATA "scanforge\wordlists"
    $target = Join-Path $wordlistDir "subdomains-top1million-5000.txt"
    $tempFile = Join-Path ([System.IO.Path]::GetTempPath()) ("scanforge-wordlist-" + [guid]::NewGuid().ToString("N"))
    try {
        $url = "https://raw.githubusercontent.com/danielmiessler/SecLists/$($ToolsVersion.SECLISTS_VERSION)/Discovery/DNS/subdomains-top1million-5000.txt"
        Invoke-WebRequest $url -OutFile $tempFile
        Assert-FileChecksum $tempFile $ToolsVersion.SECLISTS_DNS_SHA256 "SecLists DNS wordlist $($ToolsVersion.SECLISTS_VERSION)"
        New-Item -ItemType Directory -Force -Path $wordlistDir | Out-Null
        Copy-Item -LiteralPath $tempFile -Destination $target -Force
        Write-Ok "DNS wordlist installed in $target"
    } finally {
        Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
    }
}

function Install-Full {
    $versions = Get-ToolVersions
    Install-GoTools $versions
    Install-PythonTools $versions
    Install-DnsWordlist $versions
    Write-Warn "Nmap requires the official Windows installer: https://nmap.org/download.html"
    Write-Warn "massdns, WhatWeb and DNS wordlists remain manual on native Windows; WSL or Docker is recommended for profiles that require them"
    Install-ScanForge
}

function Invoke-Main {
    if ($Full) { Install-Full } else { Install-ScanForge }
    Write-Info "Installation complete. Reopen the terminal, then run:"
    Write-Host "> scanforge init" -ForegroundColor Yellow
    Write-Host "> scanforge doctor" -ForegroundColor Yellow
}

if ($env:SCANFORGE_INSTALLER_TESTING -ne '1') { Invoke-Main }
