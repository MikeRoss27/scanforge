#!/bin/bash
# Script d'installation automatisée pour ScanForge et ses dépendances (Linux/macOS)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "\e[36m=========================================\e[0m"
echo -e "\e[36m Installation de ScanForge (Linux/macOS) \e[0m"
echo -e "\e[36m=========================================\e[0m\n"

# Versions épinglées des outils (source unique : .tools-version)
if [ ! -f "$SCRIPT_DIR/.tools-version" ]; then
    echo -e "\e[31m[ERREUR] Fichier .tools-version introuvable. Clonez le dépôt complet.\e[0m"
    exit 1
fi
# shellcheck source=/dev/null
source "$SCRIPT_DIR/.tools-version"

# Vérification de Go
if ! command -v go &> /dev/null; then
    echo -e "\e[31m[ERREUR] Go n'est pas installé ou n'est pas dans le PATH.\e[0m"
    echo -e "\e[33mVeuillez installer Go (https://go.dev/dl/) avant de continuer.\e[0m"
    exit 1
fi

GO_VERSION=$(go version)
echo -e "\e[32m[OK] Go est installé : $GO_VERSION\e[0m"

# Installation des paquets natifs
if command -v apt &> /dev/null; then
    echo -e "\n\e[36mInstallation des paquets systèmes (nmap, python3, whatweb, wafw00f)...\e[0m"
    sudo apt update
    sudo apt install -y nmap python3 python3-pip whatweb wafw00f
elif command -v brew &> /dev/null; then
    echo -e "\n\e[36mInstallation des paquets systèmes via Homebrew (nmap, whatweb, python3)...\e[0m"
    brew install nmap whatweb python3
    pip3 install --user wafw00f || true
else
    echo -e "\e[33m[AIDE] Paquets non installés automatiquement (ni apt ni brew trouvés).\e[0m"
    echo -e "\e[33mInstallez manuellement : nmap, python3, whatweb, et wafw00f (pip install wafw00f).\e[0m"
fi

TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION}"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@${DNSX_VERSION}"
    "github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION}"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@${NAABU_VERSION}"
    "github.com/projectdiscovery/katana/cmd/katana@${KATANA_VERSION}"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION}"
    "github.com/projectdiscovery/tlsx/cmd/tlsx@${TLSX_VERSION}"
    "github.com/lc/gau/v2/cmd/gau@${GAU_VERSION}"
    "github.com/ffuf/ffuf/v2@${FFUF_VERSION}"
)

echo -e "\n\e[36mInstallation des outils Go (versions épinglées)... Cela peut prendre quelques minutes.\e[0m"
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
echo -e "Si vous n'êtes pas sous Debian/Ubuntu ni macOS avec brew, pensez à installer manuellement :"
echo "1. nmap"
echo "2. whatweb"
echo "3. wafw00f (via pip install wafw00f)"
echo ""
echo -e "\e[32mInstallation terminée ! Vous pouvez maintenant lancer la commande :\e[0m"
echo -e "\e[33m> scanforge init\e[0m"
echo -e "\e[33m> scanforge doctor\e[0m"
