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

## Couche triage (H3.1)

`scanforge triage <run>` dérive une interprétation du rapport sans jamais le
modifier :

```text
report.json ──► finding.FromReport ──► findings canoniques (IDs déterministes)
                                          │
                                          ▼
                              finding.BuildRelations (L0/L1)
                                          │
                                          ▼
                              moteur triage : group → bundle → analyze → validate
                                          │
                                          ▼
                          <run>/triage/ (manifest, relations, insights, report.md)
```

La frontière est stricte : **ScanForge possède les faits, l'IA possède les
interprétations, la validation se tient entre les deux.**

- `internal/finding` projette le rapport en findings plats avec IDs
  déterministes (`F-` + hash de source|template|asset|matched_at|evidence) et
  calcule les relations déterministes (doublon 1.00, CVE partagée 0.99, même
  endpoint 0.95, même actif 0.80). Les relations sémantiques (L2) peuvent s'y
  ajouter mais jamais les surcharger.
- `internal/triage` exécute le pipeline : regroupement (union-find sur le
  graphe de relations), insights déterministes (résumé + groupes de doublons),
  analyse LLM optionnelle, validation et réconciliation (tri par priorité, IDs
  stables).
- Le LLM ne reçoit qu'une projection réduite (`TriageBundle`) : preuves
  tronquées, jamais de sortie brute d'outil, plafonnée à 150 findings. Sa
  sortie est validée contre les faits — un ID de finding, une CVE ou une
  preuve inconnus rejettent l'insight entier — donc le modèle ne peut pas
  injecter de nouvelles vérités.
- `internal/inference` abstrait le transport derrière une interface `Client` ;
  l'implémentation livrée parle l'API OpenAI-compatible chat completions
  (llama.cpp, vLLM, Ollama, ...).
- La provenance est enregistrée dans `triage/manifest.json` (modèle, version
  du prompt, empreinte d'entrée, température) et le cache réutilise les
  résultats quand l'empreinte d'entrée, le modèle et la version du prompt sont
  inchangés (`--force` le contourne).
