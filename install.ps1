<#
.SYNOPSIS
ScanForge - install script (Windows).

.DESCRIPTION
By default, installs the prebuilt ScanForge binary from GitHub Releases
(only PowerShell is required, no Go needed):

    Invoke-Expression (Invoke-RestMethod https://raw.githubusercontent.com/MikeRoss27/scanforge/main/install.ps1)

With the -Full parameter, also installs all external tools
(nmap, wafw00f, subfinder, nuclei, ...) via Go and pip.

.PARAMETER Full
Also installs the external tools (requires Go).

.PARAMETER Version
Version to install (default: latest). Example: -Version v0.1.0

.PARAMETER InstallDir
Install directory (default: $env:LOCALAPPDATA\Programs\scanforge).
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
function Write-Warn { Write-Host "[WARNING] $args" -ForegroundColor Yellow }
function Write-Err { Write-Host "[ERROR] $args" -ForegroundColor Red; exit 1 }

function Get-ScanForgeVersion {
    param([string]$Requested)
    if ($Requested -eq "latest") {
        Write-Info "Fetching the latest available version..."
        $release = Invoke-RestMethod "$ApiBase/releases/latest"
        return $release.tag_name.TrimStart("v")
    }
    return $Requested.TrimStart("v")
}

function Install-ScanForge {
    $version = Get-ScanForgeVersion $Version
    Write-Info "Target version: $version"

    if (-not $InstallDir) {
        $InstallDir = "$env:LOCALAPPDATA\Programs\scanforge"
    }
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

    $asset = "scanforge_${version}_windows_amd64.zip"
    $url = "https://github.com/$Repo/releases/download/v${version}/$asset"
    $archive = "$env:TEMP\$asset"
    $tmp = Join-Path $env:TEMP ("scanforge-install-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null

    Write-Info "Downloading $asset ..."
    Invoke-WebRequest $url -OutFile $archive

    Expand-Archive -Path $archive -DestinationPath $tmp -Force

    $bin = Get-ChildItem $tmp -Recurse -File -Filter "scanforge*.exe" | Select-Object -First 1
    if (-not $bin) {
        Write-Err "Binary not found in the archive"
    }

    # Verify the SHA-256 checksum
    $expected = ""
    $actual = ""
    try {
        $checksums = Invoke-RestMethod "https://github.com/$Repo/releases/download/v${version}/checksums.txt"
        $expected = ($checksums -split "`n" | Where-Object { $_ -match "(\s)$([regex]::Escape($asset))$" } | ForEach-Object { ($_ -split "\s+")[0] })
        $actual = (Get-FileHash $archive -Algorithm SHA256).Hash.ToLower()
    } catch {
        $expected = ""
    }
    if ($expected -and $actual -and $expected -eq $actual) {
        Write-Ok "SHA-256 checksum verified"
    } else {
        Write-Warn "Unable to verify the SHA-256 checksum"
    }

    Copy-Item $bin.FullName "$InstallDir\scanforge.exe" -Force
    Remove-Item $tmp -Recurse -Force

    $current = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($current -notlike "*$InstallDir*") {
        [Environment]::SetEnvironmentVariable("Path", "$current;$InstallDir", "User")
        Write-Ok "Directory added to the user PATH (reopen your terminal)"
    }

    Write-Ok "ScanForge $version installed in $InstallDir\scanforge.exe"
}

function Install-Full {
    $toolsVersion = @{}
    $toolsFile = "$PSScriptRoot\.tools-version"
    if (-not (Test-Path $toolsFile)) {
        Write-Info "Fetching pinned tool versions (.tools-version)..."
        $toolsFile = "$env:TEMP\scanforge-tools-version"
        Invoke-WebRequest "$RawBase/.tools-version" -OutFile $toolsFile
    }
    Get-Content $toolsFile | ForEach-Object {
        if ($_ -match "^([A-Z_]+)=(.+)$") {
            $toolsVersion[$Matches[1]] = $Matches[2]
        }
    }

    try {
        $goVersion = go version
        Write-Ok "Go is installed: $goVersion"
    } catch {
        Write-Err "Go is not installed or missing from PATH. Install it from https://go.dev/dl/"
    }

    $goTools = @(
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@$($toolsVersion['SUBFINDER_VERSION'])",
        "github.com/projectdiscovery/dnsx/cmd/dnsx@$($toolsVersion['DNSX_VERSION'])",
        "github.com/projectdiscovery/httpx/cmd/httpx@$($toolsVersion['HTTPX_VERSION'])",
        "github.com/projectdiscovery/naabu/v2/cmd/naabu@$($toolsVersion['NAABU_VERSION'])",
        "github.com/projectdiscovery/katana/cmd/katana@$($toolsVersion['KATANA_VERSION'])",
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@$($toolsVersion['NUCLEI_VERSION'])",
        "github.com/projectdiscovery/tlsx/cmd/tlsx@$($toolsVersion['TLSX_VERSION'])",
        "github.com/lc/gau/v2/cmd/gau@$($toolsVersion['GAU_VERSION'])",
        "github.com/ffuf/ffuf/v2@$($toolsVersion['FFUF_VERSION'])"
    )

    Write-Info "Installing Go tools (pinned versions)... This may take a few minutes."
    foreach ($tool in $goTools) {
        Write-Host "-> Installing $tool ..."
        go install $tool
        if ($LASTEXITCODE -ne 0) {
            Write-Warn "Unable to install $tool"
        } else {
            Write-Ok "Installed"
        }
    }

    Write-Info "Installing non-Go tools..."
    try {
        pip install wafw00f
    } catch {
        Write-Warn "wafw00f not installed (pip unavailable). Install it manually: pip install wafw00f"
    }
    Write-Warn "Nmap: download the installer from https://nmap.org/download.html"
    Write-Warn "WhatWeb: mainly usable under Linux/WSL (or via Docker)"

    Install-ScanForge
}

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host " ScanForge Installation (Windows) " -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

if ($Full) {
    Install-Full
} else {
    Install-ScanForge
}

Write-Host ""
Write-Info "Installation complete! You can now run:"
Write-Host "> scanforge init" -ForegroundColor Yellow
Write-Host "> scanforge doctor" -ForegroundColor Yellow
