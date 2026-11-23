# Architecture

## Pipeline piloté par les artefacts

Chaque module déclare les artefacts qu'il exige et produit. ScanForge construit
un DAG, rejette les producteurs dupliqués, dépendances introuvables et cycles,
puis démarre chaque module dès que ses artefacts requis sont disponibles. Un
module indépendant lent ne bloque donc plus une autre branche prête.

Chaînes principales :

```text
                         ┌→ dnsx (entrée passive) ─────────────┐
subfinder → subdomains ──┤                                     ├→ resolved_hosts
                         └→ dnsbrute → dnsx (résultats tardifs)┘
resolved_hosts → httpx → alive_urls
resolved_hosts → naabu → open_ports → nmap
alive_urls → tlsx / whatweb / wafw00f / katana / ffuf / nuclei
target → gau → historical_urls
crawled_urls/historical_urls/discovered_paths → jssecrets → js_secrets → dbdetect → db_fingerprint → dbenum
```

`ffuf`, `nuclei` et `katana` dépendent « souplement » (`modules.SoftRequires`)
de l'artefact `waf_raw` produit par `wafw00f` : ils attendent sa fin quand il
fait partie du profil choisi, sans jamais échouer s'il n'y est pas. Quand
`wafw00f` détecte un WAF, `RunContext.WAFInfo` le transmet aux trois
scanners, qui réduisent automatiquement leur agressivité — concurrence/
rate-limit abaissés, délai aléatoire par requête, rotation de User-Agent
(`modules.RandomUserAgent`) — sauf si l'opérateur a déjà fixé un rate-limit
explicite ou un en-tête `User-Agent`, qui prime toujours. `jssecrets`
dépend aussi souplement de `historical_urls` et `discovered_paths` pour
analyser des URL JS trouvées par gau/ffuf que le crawl aurait manquées
(`collectJSURLs`).

DNSX résout les découvertes passives pendant le bruteforce DNS. Quand le
producteur optionnel termine, DNSX résout uniquement ses hôtes supplémentaires,
fusionne les deux flux JSONL et publie l’artefact final filtré par le scope. Si
le producteur optionnel échoue, l’attente est libérée et la branche passive
continue.

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
les artefacts produits et conserve la source du scope pour audit. `partial`
signifie que le module a tourné mais en mode dégradé : `httpcheck` et
`jssecrets` le rapportent quand toutes les URL tentées étaient inaccessibles,
et `jsverify` quand aucun navigateur n'était disponible, qu'il n'a pas pu se
lancer, ou que chaque replay PoC est revenu `unreachable` — un WAF ou un
problème réseau qui bloque tout se voit donc, au lieu d'un faux `completed`
sans aucune trouvaille.

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
