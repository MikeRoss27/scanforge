$ErrorActionPreference = "Stop"
$env:SCANFORGE_INSTALLER_TESTING = "1"
. (Join-Path $PSScriptRoot "..\install.ps1")

$tests = 0
function Assert-Equal($Actual, $Expected) {
    $script:tests++
    if ($Actual -ne $Expected) { throw "Expected '$Expected', got '$Actual'" }
    Write-Host "ok $script:tests"
}

Assert-Equal (Get-ScanForgeArchitecture ([System.Runtime.InteropServices.Architecture]::X64)) "amd64"
try {
    Get-ScanForgeArchitecture ([System.Runtime.InteropServices.Architecture]::Arm64) | Out-Null
    throw "Expected Arm64 to be rejected"
} catch {
    if ($_.Exception.Message -eq "Expected Arm64 to be rejected") { throw }
}
$tests++; Write-Host "ok $tests"

$digest = "a" * 64
$content = "$digest  scanforge_1.0.0_windows_amd64.zip`n"
Assert-Equal (Get-ChecksumEntry $content "scanforge_1.0.0_windows_amd64.zip") $digest
Assert-Equal (Get-ChecksumEntry $content "missing.zip") $null

$tempFile = Join-Path ([System.IO.Path]::GetTempPath()) ("scanforge-checksum-test-" + [guid]::NewGuid().ToString("N"))
try {
    [System.IO.File]::WriteAllText($tempFile, "payload")
    $actual = (Get-FileHash -LiteralPath $tempFile -Algorithm SHA256).Hash.ToLowerInvariant()
    Assert-FileChecksum $tempFile $actual "test" | Out-Null
    $tests++; Write-Host "ok $tests"
    try {
        Assert-FileChecksum $tempFile ("0" * 64) "test" | Out-Null
        throw "Expected checksum mismatch"
    } catch {
        if ($_.Exception.Message -eq "Expected checksum mismatch") { throw }
    }
    $tests++; Write-Host "ok $tests"
} finally {
    Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
}

Write-Host "1..$tests"
