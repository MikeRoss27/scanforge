<p align="center">
  <img src="public/SCANFORGE.gif" width="100%" alt="ScanForge">
</p>

# ScanForge

**ScanForge** est un outil en ligne de commande (CLI) écrit en Go, conçu pour orchestrer de manière sécurisée et structurée vos flux de travail de test d'intrusion et de reconnaissance (recon).

Grâce à son architecture pilotée par les artefacts, ScanForge enchaîne intelligemment les outils de sécurité reconnus du marché tout en appliquant des règles de validation de scope extrêmement strictes pour éviter tout scan non autorisé.

## 📚 Documentation

- [Guide d'utilisation](docs/USAGE.md) : installation, configuration, commandes et exemples.
- [Gestion du scope](docs/SCOPE.md) : modes implicites, fichiers, exclusions et CI.
- [Architecture](docs/ARCHITECTURE.md) : DAG, artefacts, filtrage central et sorties.
- [Guide de contribution](AGENTS.md) : structure du dépôt, style et validations.

## 🚀 Fonctionnalités Clés

- **Pipeline orienté Artefacts** : Les modules communiquent via des artefacts de manière ordonnée (ex: la sortie de `subfinder` alimente automatiquement `dnsx` et `httpx`).
- **Validation de Scope Stricte** : Scope explicite par fichier ou scope implicite confirmé (`exact` par défaut, `domain` sur demande), puis filtrage de chaque artefact.
- **Mode Dry-Run** : Visualisez les commandes qui vont être lancées et les fichiers générés avant de faire la moindre requête réseau.
- **Outil de Diagnostic (Doctor)** : Vérifiez instantanément si vos dépendances locales sont installées et configurées pour le profil sélectionné.
- **Rapports consolidés** : Génère automatiquement un modèle de risque unifié en formats `report.json` et `report.md`.

---

## 🛠️ Outils Supportés

ScanForge centralise et orchestre 12 outils de sécurité :

1. **subfinder** (Découverte de sous-domaines)
2. **dnsx** (Résolution DNS active)
3. **httpx** (Sondage HTTP et détection de technologies)
4. **naabu** (Scanner de ports ultra-rapide)
5. **nmap** (Scan de ports et détection de services précis)
6. **whatweb** (Reconnaissance des technologies web)
7. **wafw00f** (Détection de Web Application Firewall)
8. **katana** (Crawl de ressources web)
9. **ffuf** (Fuzzing de répertoires et fichiers)
10. **nuclei** (Scanner de vulnérabilités basé sur des modèles)
11. **gau** (Collecte passive d'URL historiques)
12. **tlsx** (Enrichissement des certificats et protocoles TLS)

---

## 📦 Installation Simple (Sans prise de tête)

ScanForge dépend d'outils externes. Nous avons automatisé leur installation pour vous faciliter la vie.

### Option 1 : Scripts automatisés (Recommandé)

**Sur Windows (PowerShell) :**
Lisez et exécutez le script d'installation pour configurer l'environnement :

```powershell
.\install.ps1
```

**Sur Linux / macOS (Bash) :**

```bash
chmod +x install.sh
./install.sh
```

### Option 2 : Docker (Zéro installation locale)

Si vous ne souhaitez pas installer Go ou les autres outils sur votre système hôte, utilisez Docker. Tout est pré-configuré dans l'image !

```bash
# Avec docker-compose
docker-compose run scanforge run target.com --profile web

# Manuellement avec Docker
docker build -t scanforge .
docker run -v $(pwd):/workspace scanforge run target.com --profile web
```

---

## 🚦 Guide de Démarrage Rapide

### 1. Initialiser le projet

Générez les fichiers de configuration par défaut dans votre répertoire actuel :

```bash
scanforge init
```

Cela crée :

- `scanforge.yaml` : Permet de configurer les chemins des outils et de modifier/définir des profils.
- `scope.txt` : Modèle facultatif pour conserver un périmètre réutilisable. Vous pouvez le supprimer ; ScanForge proposera alors un scope implicite minimal à confirmer.

### 2. Valider l'environnement

Vérifiez que tous les outils requis pour votre profil de scan sont bien installés et accessibles :

```bash
scanforge doctor --profile web
```

### 3. Lancer un Scan

Sans fichier de scope applicable, ScanForge déduit un scope minimal depuis la
cible, l'affiche et demande une confirmation explicite avant de créer le run :

```bash
scanforge run example.com --profile web
```

Pour inclure le domaine et ses sous-domaines, ajouter des règles ou en exclure :

```bash
scanforge run example.com --scope-mode domain \
  --scope-add api.other.test --exclude admin.example.com
```

`--scope fichier.txt` reste prioritaire et n'est jamais remplacé implicitement
s'il refuse la cible. Pour éviter toute ambiguïté, il ne se combine pas avec
`--scope-mode`, `--scope-add` ou `--exclude`. Un fichier explicite ou configuré
ne demande aucune confirmation supplémentaire. Pour un scope implicite en CI
ou sans TTY, inspectez d'abord `scanforge plan`, puis confirmez l'intention avec
`--confirm-scope`.

Pour tester sans envoyer de requêtes :

```bash
scanforge run example.com --profile web --dry-run --confirm-scope
```

Avec un scope implicite, le dry-run exige lui aussi une confirmation : il
n'effectue pas de requêtes réseau, mais formalise le périmètre autorisé.

Prévisualisez le pipeline validé avant de créer un run :

```bash
scanforge plan example.com --preset deep
```

La commande `scanforge scan` est un alias plus direct de `scanforge run` :

```bash
scanforge scan example.com --preset safe
```

---

## 📊 Profils et presets intégrés

| Nom | Modules | Usage |
| --- | --- | --- |
| `safe` | subfinder, dnsx, httpx, tlsx | Vérification légère d'exposition. |
| `recon` | safe + gau | Inventaire enrichi par les URL historiques. |
| `passive` | subfinder, dnsx, httpx | Pipeline historique minimal. |
| `ports` | subfinder, dnsx, naabu, nmap | Ports ouverts puis validation de services. |
| `web` | subfinder, dnsx, httpx, whatweb, wafw00f, katana, nuclei | Analyse applicative. |
| `vuln` | subfinder, dnsx, httpx, tlsx, nuclei | Détection ciblée de vulnérabilités. |
| `deep` | Tous les modules | Pipeline complet et bruyant. |
| `full` | Tous les modules | Profil complet compatible historique. |

Utilisez indifféremment `--preset safe` ou `--profile safe`. Avant un profil
actif, contrôlez toujours son DAG avec `scanforge plan`.

---

## 📂 Structure du Rapport Final

À la fin de chaque scan, un dossier horodaté est créé sous `./runs/`. En plus des fichiers de logs bruts de chaque outil, ScanForge génère :

- `report.json` : Modèle structuré des actifs, ports, technologies et vulnérabilités.
- `report.md` : Rapport synthétique lisible.
- `00_meta/manifest.json` : Statut du run, modules, artefacts et métadonnées de scope.
- `00_meta/commands.log` : Commandes externes préparées ou exécutées.
- `00_meta/effective-scope.txt` : Copie canonique du scope réellement appliqué, avec sa source et son mode consignés dans le manifeste.
- `00_meta/scope-rejections.jsonl` : Valeurs hors scope rejetées, lorsqu'il y en a.

> ScanForge doit uniquement être utilisé sur des actifs pour lesquels vous
> disposez d'une autorisation explicite.
