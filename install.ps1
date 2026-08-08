<#
.SYNOPSIS
Script d'installation automatisée pour ScanForge et ses dépendances (Windows).

.DESCRIPTION
Ce script va :
1. Vérifier que Go est installé.
2. Installer tous les outils Go requis via "go install".
3. Compiler et installer ScanForge.
4. Indiquer les étapes pour les outils non-Go (nmap, wafw00f, whatweb).
#>

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host " Installation de ScanForge (Windows) " -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

# Vérification de Go
try {
    $goVersion = go version
    Write-Host "[OK] Go est installé : $goVersion" -ForegroundColor Green
} catch {
    Write-Host "[ERREUR] Go n'est pas installé ou n'est pas dans le PATH." -ForegroundColor Red
    Write-Host "Veuillez installer Go (https://go.dev/dl/) avant de continuer." -ForegroundColor Yellow
    exit 1
}

# Versions épinglées des outils (source unique : .tools-version)
$toolsVersion = @{}
Get-Content "$PSScriptRoot\.tools-version" | ForEach-Object {
    if ($_ -match "^([A-Z_]+)=(.+)$") {
        $toolsVersion[$Matches[1]] = $Matches[2]
    }
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

Write-Host "`nInstallation des outils Go... Cela peut prendre quelques minutes." -ForegroundColor Cyan
foreach ($tool in $goTools) {
    Write-Host "-> Installation de $tool ..."
    go install $tool
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERREUR] Impossible d'installer $tool" -ForegroundColor Red
    } else {
        Write-Host "[OK] Installé" -ForegroundColor Green
    }
}

Write-Host "`nCompilation et installation de ScanForge..." -ForegroundColor Cyan
go install ./cmd/scanforge
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERREUR] Impossible de compiler ScanForge." -ForegroundColor Red
    exit 1
} else {
    Write-Host "[OK] ScanForge est installé !" -ForegroundColor Green
}

Write-Host "`n=========================================" -ForegroundColor Cyan
Write-Host "               ETAPE FINALE              " -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Certains outils ne peuvent pas être installés via Go :"
Write-Host "1. Nmap : Téléchargez l'installateur sur https://nmap.org/download.html"
Write-Host "2. Wafw00f : Si Python est installé, tapez : pip install wafw00f"
Write-Host "3. WhatWeb : Utilisable principalement sous Linux/WSL (ou via Docker)."
Write-Host ""
Write-Host "Installation terminée ! Vous pouvez maintenant lancer la commande :" -ForegroundColor Green
Write-Host "> scanforge init" -ForegroundColor Yellow
Write-Host "> scanforge doctor" -ForegroundColor Yellow
