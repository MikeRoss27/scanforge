FROM golang:1.22-bookworm

# Mise à jour et installation des dépendances système
RUN apt-get update && apt-get install -y \
    nmap \
    python3 \
    python3-pip \
    python3-venv \
    whatweb \
    wafw00f \
    && rm -rf /var/lib/apt/lists/*

# Fix pour Wafw00f dans les environnements récents (PEP 668)
# Ou utiliser apt install wafw00f si disponible sur bookworm (c'est le cas)

# Installer les outils de ProjectDiscovery et ffuf
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/ffuf/ffuf/v2@latest

# Création du répertoire de travail pour la compilation
WORKDIR /src
COPY . .
RUN go build -o /usr/local/bin/scanforge ./cmd/scanforge

# Nettoyage
RUN rm -rf /src

# Définition du répertoire de travail final (celui qui sera monté par l'utilisateur)
WORKDIR /workspace

# Point d'entrée
ENTRYPOINT ["scanforge"]
