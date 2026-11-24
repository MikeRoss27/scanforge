# Découverte récursive (`--recursive`)

Modèle hybride : le DAG d'artefacts continue d'ordonnancer les grandes étapes
(subfinder, dnsx, httpx, katana, jssecrets...). En plus, les artefacts de ces
modules sont émis comme **événements typés** (`internal/events`) et de petits
abonnés réagissent aux **nouvelles** découvertes. Désactivé par défaut.

```bash
scanforge run example.com --preset web --recursive
scanforge run example.com --preset web --recursive --recursive-depth 3 --recursive-budget 100
```

Config (`scanforge.yaml`), les flags l'emportent s'ils sont non nuls :

```yaml
recursive:
  enabled: false
  depth: 2     # profondeur maximale de découverte
  budget: 200  # nombre maximal de commandes de suivi par run
```

`--recursive` active aussi le bus d'événements (`--events` reste utilisable seul
et conserve son comportement de démonstration : `subdomains` -> `DNS_NAME`).
`scanforge plan` n'est pas modifié : la découverte récursive n'ajoute aucun
module au DAG, elle s'exécute après lui. Sans effet en `--dry-run`.

## Événements émis

| Artefact | Événements |
|---|---|
| `subdomains`, `brute_subdomains`, `resolved_hosts` | `DNS_NAME` |
| `open_ports` | `OPEN_PORT` |
| `alive_urls` | `LIVE_URL` (+ `DNS_NAME` de l'hôte) |
| `crawled_urls`, `historical_urls` | `JS_URL` (fichiers `.js`/`.mjs`), `DNS_NAME` (hôte de l'URL) |
| `js_secrets` | `JS_URL`, `API_ROUTE` (kind `endpoint`), `DNS_NAME` (kinds `internal-host`, `cloud-storage`) |

Une `API_ROUTE` relative est résolue contre l'origine du fichier JS qui la
contient ; cette origine est son `scope_ref`, donc une route n'est jamais « plus
dans le scope » que l'hôte qui la sert.

## Abonnés (actions de suivi)

- `DNS_NAME` nouveau et dans le scope, découvert tardivement (JS, crawl...) : passe
  bornée `dnsx` puis `httpx` sur ce seul nom. Les noms déjà connus du DAG (cible,
  `subdomains`, `resolved_hosts`, `alive_urls`) ne déclenchent rien.
- `LIVE_URL` trouvée par une passe de suivi : passe `katana` de profondeur 1 sur
  cette URL. Les URL vivantes du DAG sont déjà crawlées par le DAG.
- `OPEN_PORT`, `JS_URL`, `API_ROUTE` : persistés dans `events.jsonl`, pas d'action.

Les abonnés ne font que mettre des tâches en file ; les tâches s'exécutent une à
une après la fin du DAG, ce qui garde l'ordre déterministe.

## Garde-fous

1. **Scope d'abord.** Chaque événement passe par `Scope.IsAllowed` avant tout
   abonné. Une découverte OSINT/JS n'est **jamais** autorisée automatiquement :
   hors scope, elle est abandonnée et journalisée dans
   `00_meta/scope-rejections.jsonl` (artefact `event:<TYPE>`). Les sorties des
   passes de suivi sont en plus filtrées par `RunContext.AddArtifact` (point de
   passage unique) et seul le fichier filtré est relu.
2. **Exécuteur injecté.** Les commandes passent par le `runner.Executor` du run
   (donc le scheduler : concurrence, req/s, `--max-requests`) et sont écrites dans
   `commands.log`. Jamais d'`os/exec` direct.
3. **Anti-boucle.** Un événement (type + valeur normalisée) n'est livré qu'une fois
   par run ; A -> B -> A s'arrête.
4. **Profondeur.** Les événements des artefacts du DAG sont à la profondeur 0 ; ceux
   issus d'une passe de suivi héritent de `parent + 1`. Au-delà de
   `--recursive-depth` ils sont abandonnés.
5. **Budget.** `--recursive-budget` borne le nombre total de commandes de suivi
   (dnsx, httpx et katana comptent chacune 1). Épuisé, les suivis restants sont
   ignorés avec un avertissement.

## Fichiers produits

- `00_meta/events.jsonl` : événements acceptés (id, type, valeur, source, parent,
  profondeur, verdict, `scope_ref`).
- `07_recursive/NNN-<valeur>-*` : entrées/sorties de chaque commande de suivi.
  Les artefacts de suivi (`recursive.resolved_hosts`, `recursive.alive_urls`,
  `recursive.crawled_urls`) portent des noms distincts : ils ne remplacent jamais
  les artefacts du DAG et ne sont pas encore intégrés à `report.json`.
