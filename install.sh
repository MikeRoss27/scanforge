#!/bin/bash
# Script d'installation automatisée pour ScanForge et ses dépendances (Linux/macOS)

set -e

echo -e "\e[36m=========================================\e[0m"
echo -e "\e[36m Installation de ScanForge (Linux/macOS) \e[0m"
echo -e "\e[36m=========================================\e[0m\n"

# Vérification de Go
if ! command -v go &> /dev/null; then
    echo -e "\e[31m[ERREUR] Go n'est pas installé ou n'est pas dans le PATH.\e[0m"
    echo -e "\e[33mVeuillez installer Go (https://go.dev/dl/) avant de continuer.\e[0m"
    exit 1
fi

GO_VERSION=$(go version)
echo -e "\e[32m[OK] Go est installé : $GO_VERSION\e[0m"

# Installation des paquets natifs (si on est sous Debian/Ubuntu)
if command -v apt &> /dev/null; then
    echo -e "\n\e[36mInstallation des paquets systèmes (nmap, python3, whatweb, wafw00f)...\e[0m"
    sudo apt update
    sudo apt install -y nmap python3 python3-pip whatweb wafw00f
fi

TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/ffuf/ffuf/v2@latest"
)

echo -e "\n\e[36mInstallation des outils Go... Cela peut prendre quelques minutes.\e[0m"
for TOOL in "${TOOLS[@]}"; do
    echo "-> Installation de $TOOL ..."
    go install "$TOOL"
    echo -e "\e[32m[OK] Installé\e[0m"
done

echo -e "\n\e[36mCompilation et installation de ScanForge...\e[0m"
go install ./cmd/scanforge
echo -e "\e[32m[OK] ScanForge est installé !\e[0m"

echo -e "\n\e[36m=========================================\e[0m"
echo -e "\e[36m               ETAPE FINALE              \e[0m"
echo -e "\e[36m=========================================\e[0m"
echo -e "Si vous n'êtes pas sous Debian/Ubuntu, pensez à installer manuellement :"
echo "1. nmap"
echo "2. whatweb"
echo "3. wafw00f (via pip install wafw00f)"
echo ""
echo -e "\e[32mInstallation terminée ! Vous pouvez maintenant lancer la commande :\e[0m"
echo -e "\e[33m> scanforge init\e[0m"
echo -e "\e[33m> scanforge doctor\e[0m"
