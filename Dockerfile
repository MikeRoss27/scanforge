# Stage 1 : compilation de ScanForge et des outils Go
FROM golang:1.26-bookworm AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Versions épinglées des outils (source unique : .tools-version)
COPY .tools-version /tmp/tools-version

# Binaires des outils de ProjectDiscovery et ffuf, installés dans un répertoire dédié
RUN . /tmp/tools-version && \
    GOBIN=/out go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION} && \
    GOBIN=/out go install github.com/projectdiscovery/dnsx/cmd/dnsx@${DNSX_VERSION} && \
    GOBIN=/out go install github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION} && \
    GOBIN=/out go install github.com/projectdiscovery/naabu/v2/cmd/naabu@${NAABU_VERSION} && \
    GOBIN=/out go install github.com/projectdiscovery/katana/cmd/katana@${KATANA_VERSION} && \
    GOBIN=/out go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION} && \
    GOBIN=/out go install github.com/projectdiscovery/tlsx/cmd/tlsx@${TLSX_VERSION} && \
    GOBIN=/out go install github.com/lc/gau/v2/cmd/gau@${GAU_VERSION} && \
    GOBIN=/out go install github.com/ffuf/ffuf/v2@${FFUF_VERSION} && \
    GOBIN=/out go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@${SHUFFLEDNS_VERSION}

# Wordlist DNS minimale requise par shuffledns, épinglée et vérifiée.
RUN . /tmp/tools-version && \
    mkdir -p /wordlists && \
    curl -fsSL "https://raw.githubusercontent.com/danielmiessler/SecLists/${SECLISTS_VERSION}/Discovery/DNS/subdomains-top1million-5000.txt" \
      -o /wordlists/subdomains-top1million-5000.txt && \
    echo "${SECLISTS_DNS_SHA256}  /wordlists/subdomains-top1million-5000.txt" | sha256sum -c -

RUN . /tmp/tools-version && \
    curl -fsSL "https://github.com/blechschmidt/massdns/archive/refs/tags/${MASSDNS_VERSION}.tar.gz" -o /tmp/massdns.tar.gz && \
    echo "${MASSDNS_SOURCE_SHA256}  /tmp/massdns.tar.gz" | sha256sum -c - && \
    tar -xzf /tmp/massdns.tar.gz -C /tmp && \
    make -C "/tmp/massdns-${MASSDNS_VERSION#v}" && \
    cp "/tmp/massdns-${MASSDNS_VERSION#v}/bin/massdns" /out/massdns

# Compilation de ScanForge (binaire statique, sans cache)
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN TOOLS_VERSIONS="$(awk -F= 'BEGIN { sep="" } !/^#/ && NF == 2 { printf "%s%s=%s", sep, $1, $2; sep="," }' /tmp/tools-version)" && \
    CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X github.com/MikeRoss27/scanforge/internal/dependencies.PinnedVersions=${TOOLS_VERSIONS}" \
    -o /out/scanforge ./cmd/scanforge

# Stage 2 : image d'exécution minimale
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    chromium \
    nmap \
    pipx \
    python3 \
    python3-venv \
    whatweb \
    && rm -rf /var/lib/apt/lists/*

COPY .tools-version /tmp/tools-version
RUN . /tmp/tools-version && PIPX_BIN_DIR=/usr/local/bin pipx install "wafw00f==${WAFW00F_VERSION#v}"

COPY --from=build /out/ /usr/local/bin/
COPY --from=build /wordlists/ /usr/share/scanforge/wordlists/

# Répertoire de travail final (celui qui sera monté par l'utilisateur)
WORKDIR /workspace

ENTRYPOINT ["scanforge"]
