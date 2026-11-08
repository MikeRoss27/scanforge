# Feuille de route produit — ScanForge

Ce document capture la revue produit (positionnement, analyse concurrentielle,
couverture phase par phase) et les axes d'amélioration organisés en horizons.
Il sert de référence pour prioriser le développement.

## 1. Positionnement

ScanForge est un CLI Go qui orchestre des outils de recon/security dans un
pipeline à artefacts, avec **enforcement strict du scope** — le différentiateur
central : aucun outil de l'écosystème ProjectDiscovery n'impose de périmètre
autorisé. Le DAG + artefacts + dry-run en font un outil sûr, déterministe et
auditable pour le pentest autorisé.

| Outil | Type | Points forts vs ScanForge | Atouts ScanForge |
|---|---|---|---|
| Suite ProjectDiscovery (pdtm) | Suite d'outils + SaaS cloud | Intégration continue, templates communautaires, screenshots | Scope enforcement, pipeline artefacts, dry-run, report consolidé |
| reconftw | Script bash massif | Nombre de modules, communauté | Fiabilité, scope, déterminisme |
| Osmedeus | Orchestrateur Go | Extensibilité modules/plugins, API web, workspaces | Simplicité, sécurité (scope), TUI |
| reNgine | ASM web open-source | UI, scheduling, notifications, organisations | CLI + dry-run + scope pour pentest manuel |
| Trickest / PD Cloud / Intruder | ASM commercial | Continuous scanning, priorisation, ticketing | — |

**Verdict** : les concurrents sérieux sont **reNgine** (continuité/ASM) et
**reconftw** (couverture de modules). Les deux plus gros manques de ScanForge
sont exactement là : la couverture (bruteforce DNS, feeds passifs) et la
continuité (diff entre runs, scheduling, notifications).

## 2. Couverture phase par phase

| Phase | ScanForge | Best-in-class | Écart |
|---|---|---|---|
| Enum sous-domaines | subfinder + gau + shuffledns | + permutation (gotator/altdns), feeds passifs (Chaos, CDX) | 🟡 — brute OK, permutation et feeds passifs à venir |
| Résolution | dnsx | — | ✅ |
| Ports | naabu + nmap | + masscan (très gros ranges) | 🟡 |
| HTTP probing | httpx + screenshots | — | ✅ |
| Crawl | katana | — | ✅ |
| Fuzz | ffuf | — | ✅ |
| Vulnérabilités | nuclei + techcve | + priorisation EPSS / CISA KEV / CVSS | 🟡 techcve est idéalement placé |
| Secrets | jssecrets natif | + gitleaks/trufflehog (repos git) | 🟡 |
| Rapports | report.json/.md | HTML, SARIF, DefectDojo, notifications | 🔴 — attendu par les clients/CI |
| Continuité | run one-shot | scheduling, diff entre runs, alertes | 🔴 — valeur des ASM commerciaux |

## 3. Horizons

### H1 — Vite, valeur immédiate

| # | Idée | Statut |
|---|---|---|
| H1.1 | `scanforge diff <run1> <run2>` : delta sous-domaines / ports / vulnérabilités entre deux runs (option `--json` pour la CI) | ✅ implémenté |
| H1.2 | `scanforge export --format sarif\|defectdojo <run>` : sorties standard pour l'écosystème (GitHub/GitLab CI, DefectDojo) | ✅ implémenté |
| H1.3 | Multi-cibles : `--targets <fichier>` sur `run`/`plan` (10 domaines + ranges), déduplication globale, scope par cible | ✅ implémenté |
| H1.4 | Priorisation EPSS + CISA KEV dans techcve (dataset embarqué, scores réels), affichage dans le report | ✅ implémenté |

### H2 — Milieu de gamme

| # | Idée |
|---|---|
| H2.1 | Module DNS brute : shuffledns + massdns (nouveaux outils `.tools-version`), résultats fusionnés dans dnsx, filtrés par scope | ✅ implémenté |
| H2.2 | Screenshots : module basé sur `httpx -screenshot` — retour visuel client | ✅ implémenté |
| H2.3 | Resume des runs interrompus : reprise à la wave courante via le manifest |
| H2.4 | Notifications webhook (Slack/Discord/générique) en fin de run | ✅ implémenté |
| H2.5 | `scanforge watch` : scheduling simple + diff auto |
| H2.6 | CVSS dans le modèle (score/base) pour alimenter SARIF/DefectDojo et le tri | ✅ implémenté |

### H3 — Vision

| # | Idée | Statut |
|---|---|---|
| H3.1 | Triage IA des findings : résumé LLM + déduplication | ✅ implémenté |
| H3.2 | Report HTML type nuclei (compte rendu client) | |
| H3.3 | Données live : fetch EPSS/KEV/NVD à jour plutôt que dataset embarqué | |

## 4. Hors périmètre (anti-scope creep)

- sqlmap / dalfox / smuggler : nuclei + httpcheck couvrent l'essentiel, ça
  fragiliserait la cohérence du DAG.
- amass passif : coûteux en RAM, subfinder + chaos suffisent.
- UI web complète : reNgine existe déjà — la différenciation de ScanForge
  reste le CLI sûr et déterministe.

## 5. Sources de données

- EPSS : https://api.first.org/data/v1/epss (récupéré le 2026-08-09 pour le dataset techcve)
- CISA KEV : https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
