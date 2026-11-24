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

## Reprise (`resume`) et `--incremental`

- `scanforge resume` conserve `--recursive`, `--recursive-depth` et `--recursive-budget`
  (stockés dans les paramètres du manifeste). Les passes de suivi terminées sont
  listées dans `07_recursive/done.jsonl` : à la reprise elles sont rejouées depuis
  leurs sorties (aucune commande, annoncées `recursive: reuse ...`), ce qui
  reconstruit la chaîne d'événements ; seules les passes interrompues ou nouvelles
  sont exécutées, avec une numérotation qui ne réécrit pas les sorties existantes.
  `events.jsonl` et `scope-rejections.jsonl` ne reçoivent pas de lignes en double.
- `--incremental` fonctionne avec `--recursive`. Les passes de suivi ne sont pas
  restreintes par le focus incrémental : elles sont refaites à chaque run (nouveau
  répertoire) dans la limite du budget.

## Ports

Le `httpx` de suivi sonde 80/443 plus les ports web des `alive_urls` du DAG
(ex. 8080, 8443) : une application hébergée sur un port non standard est ainsi vue
sur le nouveau nom. Sans `alive_urls`, httpx garde ses ports par défaut.

## Console

Chaque passe est annoncée (`[INF] recursive [3/50] crawl http://...`, `[n/budget]`
= prochaine commande / budget), puis un résumé : jobs, commandes, événements
au-delà de la profondeur, dépassements de budget, échecs. Masqué avec `--quiet`.

## Validation de bout en bout (labo loopback)

Validé avec un vrai `scanforge run localhost --preset deep --scope scope.txt
--confirm-scope --recursive --recursive-depth 2 --recursive-budget 50` (scope
`localhost`, `*.localhost`, `127.0.0.1`) contre un petit serveur HTTP Python sur
`127.0.0.1:8080` qui sert, selon l'en-tête `Host`, la même racine pour tous les
noms et une chaîne `api.lab.localhost` -> `l1.lab.localhost` -> `l2.lab.localhost`
-> `l3.lab.localhost` (liens `http://evil.example.org/...` à chaque niveau, JS avec
URL absolues `evil.example.org`, `internal.corp.evil...`). `api.lab.localhost` n'est
atteint par le crawl du DAG (katana, profondeur 2) qu'en tant que lien, jamais
chargé ; il est donc « découvert tardivement ».

Constats :

- `api.lab.localhost` (DNS_NAME depuis `crawled_urls`) -> dnsx + httpx
  (`07_recursive/001-*`), live URL `:8080` -> katana depth 1 (`003-*`), qui révèle
  `l1`/`l2` (profondeur 2) -> dnsx + httpx ; leurs `LIVE_URL` (profondeur 3) sont
  abandonnées : `l3` n'est jamais sondé (4 événements « past depth » dans le
  résumé). Avec `--recursive-depth 1 --recursive-budget 3` la boucle s'arrête après
  3 commandes avec l'avertissement de budget.
- Hors scope : `evil.example.org` apparaît dans la sortie katana de suivi et est
  retiré par `AddArtifact` (`scope-rejections.jsonl`, artefact
  `recursive.crawled_urls`) ; `internal.corp` (JS, `event:DNS_NAME`) est rejeté par
  le bus. Aucune commande de `commands.log` ne cible un hôte hors scope et aucun
  fichier de `07_recursive/` ne le contient.
- `scanforge resume` : 0 commande de suivi relancée, `events.jsonl` inchangé (62
  lignes avant et après) ; `--incremental --recursive` : le run se termine
  normalement.
- Le sous-domaine passif (subfinder) renvoie du bruit réel pour `localhost` ;
  le labo répond donc la racine pour tout nom inconnu.
- Limite connue : le mode `domain` implicite refuse un nom à un seul label
  (`localhost`) ; le labo utilise donc `--scope` avec un fichier.
