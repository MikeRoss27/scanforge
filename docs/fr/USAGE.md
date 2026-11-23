# Guide d'utilisation

## Installation

### Une ligne (binaire pré-compilé, sans Go)

```bash
curl -fsSL https://raw.githubusercontent.com/MikeRoss27/scanforge/main/install.sh | bash
```

```powershell
Invoke-Expression (Invoke-RestMethod https://raw.githubusercontent.com/MikeRoss27/scanforge/main/install.ps1)
```

### Avec les outils externes (requiert Go)

```bash
curl -fsSL https://raw.githubusercontent.com/MikeRoss27/scanforge/main/install.sh | bash -s -- --full
```

Depuis un clone du dépôt, les scripts locaux font la même chose :

```bash
./install.sh --full
```

```powershell
.\install.ps1 -Full
```

Sur Arch, `--full` utilise `pacman -S --needed` pour les seuls paquets officiels, sans mise à niveau globale, puis Go, pipx et des artefacts upstream vérifiés. WhatWeb reste manuel/AUR et aucun helper AUR n'est requis. L'installateur n'effectue aucun `pip install` global (compatibilité PEP 668). La vérification finale et `scanforge doctor --profile NOM` indiquent précisément ce qui manque encore.

Vous pouvez aussi construire le binaire localement :

```bash
make build      # ou : go build -o scanforge ./cmd/scanforge
```

## Commandes de développement

Depuis un clone du dépôt, le `Makefile` encapsule la toolchain Go. Cibles les
plus utiles :

| Commande | Rôle |
| --- | --- |
| `make dev` / `make run` | Lance le CLI via `go run` sans build ; arguments via `ARGS="plan example.com --preset deep"` |
| `make test` / `make race` | Suite de tests (rapide / avec le détecteur de race) |
| `make check` | Porte avant push : vérification du format, `go vet`, golangci-lint et tests |
| `make cover` | Tests avec rapport de couverture et résumé par fonction |
| `make fmt` / `make fmt-check` | Formater le code / lister les fichiers non formatés sans les réécrire |
| `make vet` / `make lint` | Analyse statique ; `make tools` installe la version de golangci-lint épinglée par le CI |
| `make tidy` | Nettoyer `go.mod` / `go.sum` |
| `make clean` | Supprimer le binaire et `coverage.out` |

## Configuration

`scanforge init` crée `scanforge.yaml`, un `scope.txt` facultatif et le dossier
`runs/`. La configuration est recherchée dans cet ordre :

1. `--config chemin.yaml`
2. variable `SCANFORGE_CONFIG`
3. `./scanforge.yaml`

Les chemins des exécutables se configurent sous `tools`. Les profils intégrés
peuvent être remplacés ; les presets `web`, `vuln`, `deep` et `full` enchaînent
la consolidation de la surface d'attaque (`attacksurface`), la corrélation
technologie→CVE (`techcve`), les vérifications d'en-têtes HTTP (`httpcheck`)
et la génération de wordlists de payloads (`payloadgen`) :

```yaml
workspace: runs
default_profile: safe

tools:
  subfinder: /opt/bin/subfinder

profiles:
  internal-web:
    - subfinder
    - dnsx
    - httpx
    - nuclei
```

Les limites de temps par module se configurent sous `module_timeouts` avec des
durées Go. Un module qui dépasse sa limite est tué et signalé comme échoué, et
ses dépendants sont marqués `skipped` ; les modules sans limite gardent leur
défaut :

```yaml
module_timeouts:
  nuclei: 45m
  katana: 20m
```

La section `ai` configure le backend LLM utilisé par `scanforge triage`. Tout
serveur exposant l'API OpenAI-compatible chat completions fonctionne
(llama.cpp, vLLM, Ollama, LM Studio, ...). Si la section est absente, le
triage fonctionne en mode purement déterministe (déduplication et
regroupement sans modèle) :

```yaml
ai:
  base_url: http://127.0.0.1:8080/v1
  model: qwen3.5-9b
  api_key: ""        # facultatif pour les serveurs locaux
  timeout: 5m
  temperature: 0.1   # des valeurs basses stabilisent le triage
```

## Templates nuclei intégrés

`--nuclei-include-custom` ajoute au run nuclei les templates livrés dans le
dossier `templates/` de ce dépôt (`spring-actuator-exposed`,
`swagger-openapi-exposed`, `cors-wildcard-credentials`,
`go-debug-endpoints-exposed`, `wordpress-debug-log-exposed`, `wordpress-config-backup-exposed`, `wordpress-install-exposed`, `wordpress-readme-exposed`). Ils sont
localisés via `SCANFORGE_TEMPLATES_DIR`, puis le répertoire de travail
(`./templates`) et enfin le répertoire de l'exécutable.

Par défaut nuclei tourne avec `-as` (scan automatique) : les templates sont
choisis selon la techno détectée sur chaque hôte au lieu de lancer tout le
catalogue sur chaque hôte, avec la limite de débit par défaut de nuclei
(150 req/s). Passez `--nuclei-tags`, `--nuclei-templates`, ou
`--nuclei-full-scan` pour lancer tous les templates sur tous les hôtes
(plus lent ; augmentez `--nuclei-timeout` en conséquence).
`--nuclei-rate-limit` surcharge la limite de débit dans tous les cas.

`ffuf` lance un processus séparé par hôte vivant (borné par une limite de
concurrence interne, même compromis que `nmap`) au lieu de fuzzer tous les
hôtes depuis une seule invocation : l'auto-calibration (`-ac`/`-ach`)
n'apprend fiablement la signature wildcard/soft-404 propre à un hôte que
lorsqu'elle tourne seule sur cet hôte.

## WordPress (wp)

`scanforge run example.com --preset wp` lance la chaîne d'engagement WordPress :
`subfinder → dnsbrute → dnsx → httpx → whatweb → wpdetect → wpplugins → wpthemes → wpusers → wpexposure → wpxmlrpc → wpcve → techcve → httpcheck → attacksurface → nuclei → screenshot`.

- La détection est **passive par défaut** : les versions des plugins/thèmes sont lues dans les assets crawlés (`?ver=`), le `readme.html` exposé, l'index REST et le flux RSS. Rien de fuyable sans votre accord.
- `--wp-detection-mode mixed` ajoute la lecture de `readme.txt` pour les slugs détectés passivement (versions + confirmation). `--wp-detection-mode aggressive --wp-wordlist slugs.txt` sonde les slugs plugins/thèmes d'une liste top embarquée (ou votre propre fichier, un slug par ligne) pour une parité maximale avec wpscan. En mode agressif le scan devient bruyant ; à doser selon l'engagement.
- `--wp` ajoute la chaîne WordPress à n'importe quel autre profil (`scanforge run example.com --profile web --wp`).
- `wpcve` corrèle les versions core/plugins/thèmes avec le dataset embarqué (hors ligne ; vérifié contre la NVD, voir `internal/modules/wpcve/cves_wp.yaml`). Aucune clé API nécessaire.
- `wpbrute` (sonde de credentials contre les utilisateurs énumérés) est **désactivé partout par défaut** et ne s'exécute qu'avec les trois : `--wp-bruteforce` + `--confirm-scope` (scopes implicites) + `--wp-passwords <wordlist>`. Il se limite à `--wp-bruteforce-max` tentatives par utilisateur (défaut 100), s'arrête au premier succès ou à tout signal de lockout, et refuse de tourner si `wpusers` n'a énuméré aucun identifiant. Aucune liste de mots de passe n'est embarquée.
- `scanforge doctor --profile wp` remonte l'état des wordlists/dataset embarqués et des outils externes.
- Sans `--wp`, `scanforge run` lance tout de même une sonde WordPress passive rapide contre la cible confirmée (mêmes signaux que `wpdetect`, plafonnée à 8s) juste après la confirmation de scope. Si ça ressemble à WordPress et que la session est un terminal interactif, elle propose d'ajouter la chaîne à ce run ; en contexte non interactif (CI, scripts, `--dry-run`), elle se contente de logguer la détection sans modifier le run.

## Flux recommandé

Contrôlez d'abord les dépendances et le plan :

```bash
scanforge doctor --profile safe
scanforge plan example.com --preset safe
```

Lancez ensuite le run. Sans fichier applicable, le scope implicite est affiché
et confirmé avant toute création de dossier :

```bash
scanforge run example.com --preset safe
```

Pour inspecter les commandes sans les exécuter :

```bash
scanforge run example.com --preset ports --dry-run
```

Le dry-run exige la même confirmation lorsqu'il utilise un scope implicite.
Dans un terminal non interactif :

```bash
scanforge plan example.com --scope-mode domain
scanforge run example.com --scope-mode domain --confirm-scope
```

## Commandes utiles

| Commande | Fonction |
| --- | --- |
| `scanforge init` | Crée la configuration initiale. |
| `scanforge doctor --profile NAME` | Vérifie les outils du profil. |
| `scanforge plan TARGET` | Affiche le scope et les vagues du DAG. |
| `scanforge run TARGET` | Exécute un profil autorisé. |
| `scanforge scan TARGET` | Alias de `run`. |
| `scanforge triage RUN` | Regroupe et (avec un backend `ai:`) analyse les findings d'un run. |
| `scanforge auth` | Gère les clés requises par certains outils. |
| `scanforge benchmark run LAB\|--all` | Outil mainteneur : exécute le pipeline réel contre des labs vulnérables embarqués et score la détection par rapport aux attentes. |
| `scanforge version` | Affiche la version du binaire. |

Consultez `scanforge <commande> --help` pour la liste exacte des options.

## Triage des findings

`scanforge triage <run>` projette le rapport consolidé en findings canoniques,
calcule les relations déterministes (doublons, CVE partagée, endpoint commun,
même actif) et écrit le résultat sous `<run>/triage/` :

```text
triage/manifest.json    provenance : modèle, version du prompt, empreinte d'entrée
triage/relations.json   relations déterministes entre findings
triage/insights.json    insights (groupes de doublons + insights LLM validés)
triage/report.md        résumé lisible
```

Avec un backend `ai:` configuré, le modèle reçoit une projection volontairement
réduite des findings (preuves tronquées, jamais de sortie brute d'outil) et ses
insights sont validés avant stockage : tout insight référençant un ID de
finding, une CVE ou une preuve inconnus est rejeté. Le modèle peut interpréter
les findings, jamais en créer. Relancer avec une entrée inchangée touche le
cache (0 inférence) ; `--force` le contourne :

```bash
scanforge triage runs/example.com/2026-08-19T10:00:00Z
scanforge triage runs/example.com/2026-08-19T10:00:00Z --force
scanforge triage runs/example.com/2026-08-19T10:00:00Z --model qwen3.5-9b
```

## Engagements multi-cibles

`run` et `plan` acceptent un fichier de cibles au lieu d'une cible positionnelle
unique. Chaque cible obtient sa propre validation de scope, son répertoire de
run et son rapport sous `runs/<target>/` ; une cible en échec n'interrompt pas
le reste de l'engagement.

```bash
scanforge plan --targets cibles.txt --preset web
scanforge run --targets cibles.txt --preset web --confirm-scope
```

Le fichier contient une cible par ligne (commentaires `#` et lignes vides
ignorés). `--targets` est exclusif avec une cible positionnelle.

## Comparer des runs et exporter

`scanforge diff` reconsolide deux répertoires de run et liste ce qui a changé —
actifs, ports et vulnérabilités apparus ou disparus (une boucle ASM
périodique légère, sans infrastructure) :

```bash
scanforge diff runs/example.com/2026-08-09_10-00-00 runs/example.com/2026-08-10_10-00-00
scanforge diff runs/example.com/2026-08-09_10-00-00 runs/example.com/2026-08-10_10-00-00 --json
```

`scanforge export` sérialise le rapport consolidé pour des outils tiers :

```bash
scanforge export runs/example.com/2026-08-10_10-00-00 --format sarif          # code scanning GitHub/GitLab
scanforge export runs/example.com/2026-08-10_10-00-00 --format defectdojo     # import-scan "Generic Findings Import"
```
