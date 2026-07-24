# Architecture

## Pipeline piloté par les artefacts

Chaque module déclare les artefacts qu'il exige et produit. ScanForge construit
un DAG, rejette les producteurs dupliqués, dépendances introuvables et cycles,
puis exécute les modules prêts par vagues.

Chaînes principales :

```text
subfinder → subdomains → dnsx → resolved_hosts
resolved_hosts → httpx → alive_urls
resolved_hosts → naabu → open_ports → nmap
alive_urls → tlsx / whatweb / wafw00f / katana / ffuf / nuclei
target → gau → historical_urls
```

`scanforge plan TARGET --preset deep` affiche les vagues validées sans lancer
d'outil ni créer de run.

## Frontière de sécurité

Le scope effectif est construit dans la couche application et transmis au
`RunContext`. Avant publication, les artefacts textuels contenant des hôtes,
IP, ports ou URL sont filtrés centralement. Une valeur refusée n'atteint donc
pas un module aval et est enregistrée dans le journal de rejets.

Le mode `exact` conserve toujours la cible racine dans la sortie Subfinder afin
que DNSX et HTTPX puissent poursuivre sans élargir implicitement le périmètre.
Nmap reçoit les couples hôte/port validés produits par Naabu et lance des scans
restreints à ces ports.

## Organisation des sorties

Un run est stocké sous `runs/<cible>/<horodatage>/` :

```text
00_meta/       manifeste, commandes, stderr, scope et rejets
01_subdomains/ résultats Subfinder et DNS
02_http/       sondes HTTP et enrichissements TLS
03_ports/      résultats Naabu et XML Nmap
04_web/        technologies et détection WAF
05_content/    crawl, URL historiques et fuzzing
06_vulns/      résultats Nuclei
report.json    rapport normalisé
report.md      synthèse lisible
```

Le manifeste distingue les états `completed`, `partial` et `failed`, référence
les artefacts produits et conserve la source du scope pour audit.
