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

Vous pouvez aussi construire le binaire localement :

```bash
go build -o scanforge ./cmd/scanforge
```

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

## Templates nuclei intégrés

`--nuclei-include-custom` ajoute au run nuclei les templates livrés dans le
dossier `templates/` de ce dépôt (`spring-actuator-exposed`,
`swagger-openapi-exposed`, `cors-wildcard-credentials`,
`go-debug-endpoints-exposed`, `wordpress-debug-log-exposed`). Ils sont
localisés via `SCANFORGE_TEMPLATES_DIR`, puis le répertoire de travail
(`./templates`) et enfin le répertoire de l'exécutable.

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
| `scanforge auth` | Gère les clés requises par certains outils. |
| `scanforge version` | Affiche la version du binaire. |

Consultez `scanforge <commande> --help` pour la liste exacte des options.
