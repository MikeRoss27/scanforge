# Stage 1 : compilation de ScanForge et des outils Go
FROM golang:1.26-bookworm AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
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
    GOBIN=/out go install github.com/ffuf/ffuf/v2@${FFUF_VERSION}

# Compilation de ScanForge (binaire statique, sans cache)
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/scanforge ./cmd/scanforge

# Stage 2 : image d'exécution minimale
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    nmap \
    python3 \
    python3-pip \
    python3-venv \
    whatweb \
    wafw00f \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/ /usr/local/bin/

# Répertoire de travail final (celui qui sera monté par l'utilisateur)
WORKDIR /workspace

ENTRYPOINT ["scanforge"]
