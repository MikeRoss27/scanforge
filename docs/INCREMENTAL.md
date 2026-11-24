# Scans incrémentaux

ScanForge garde, pour chaque cible, un historique des assets observés dans un
simple fichier : `runs/<cible>/assets.jsonl`. Pas de base de données : le
fichier est lisible, copiable et versionnable, comme le reste d'un run.

## Historique (`assets.jsonl`)

Fichier **append-only** (une ligne JSON par enregistrement), mis à jour
atomiquement (fichier temporaire + `rename`) à la fin de chaque run
**terminé** (`status: completed`, hors `--dry-run`). Il est construit à partir
du rapport consolidé du run (`internal/report`), pas en reparsant les sorties
des outils.

| Champ | Sens |
|-------|------|
| `type` | `subdomain`, `host` (IP), `url` (service HTTP), `path` (katana/ffuf), `port`, `tech`, `finding`, `run` |
| `value` | identité de l'asset (`host:port/proto`, `host\|techno`, etc.) |
| `first_seen` / `last_seen` | première / dernière observation (RFC 3339) |
| `last_run_id` | dernier run qui a touché l'asset |
| `status` | `new`, `unchanged`, `changed`, `gone` |
| `host` | chaîne vérifiée contre le scope avant toute réutilisation |
| `fingerprint` | empreinte des attributs dont le changement donne `changed` (statut HTTP, titre, serveur, version de service, IP, sévérité) |

L'état courant d'un asset est sa **dernière ligne**. Chaque run ajoute une
ligne `run` (hash du scope, versions des outils) puis une ligne par asset
observé, et une ligne `gone` pour chaque asset connu qui n'a plus été vu.

- `new` : jamais vu, ou réapparu après `gone` (le `first_seen` d'origine est conservé).
- `changed` : l'empreinte a changé depuis le dernier run.
- `gone` : absent alors que le run pouvait l'observer. Un type n'est déclaré
  `gone` que si un module capable de le produire s'est terminé (ex. pas de
  `gone` sur les ports sans naabu/nmap). Dans un run `--incremental` filtré,
  `path` et `finding` ne sont jamais déclarés `gone` : nuclei/katana/ffuf n'ont
  volontairement pas tout revu.
- Un run `partial`, `failed`, `aborted` ou `--dry-run` n'écrit **rien** : il
  ferait apparaître des assets `gone` à tort.
- Enregistrer deux fois le même run (ex. `resume` d'un run terminé) est sans effet.

## `scanforge run TARGET --incremental`

Avant les modules, l'historique est chargé, puis **chaque entrée est
re-filtrée contre le scope effectif courant** (une entrée hors scope ou sans
clé de scope n'est jamais utilisée). Ensuite nuclei, ffuf, katana et
jssecrets ne traitent que les URLs **nouvelles ou modifiées** :

- ffuf et katana : filtrage de `alive_urls` ;
- nuclei : filtrage de `attack_surface_urls` ;
- jssecrets : filtrage de `crawled_urls` (les corpus `historical_urls` et
  `discovered_paths` restent lus en entier).

Une URL est conservée si elle est inconnue, `gone` au dernier run, ou si son
empreinte httpx (statut, titre, serveur, redirection, type, favicon ; pas la
taille ni le temps de réponse) a changé. En cas de doute, elle est conservée.
Le focus ne peut **que retirer** des lignes d'un artefact déjà filtré par le
scope (`RunContext.FocusedInput` refiltre aussi par le scope) : il n'élargit
jamais la cible. Sans `--incremental`, le comportement est inchangé.

Si le focus ne laisse rien à scanner, le module est marqué `skipped`
(« incremental: no new or changed URLs ») et publie un artefact vide pour que
les modules en aval fonctionnent.

Conséquence à connaître : le `report.json` d'un run incrémental ne contient
que les findings/chemins des URLs revues ; l'historique, lui, conserve les
précédents.

### Invalidation du cache

Conservatrice : si le **hash du scope effectif** (`scope_sha256`) ou la
**version d'un outil** (présent dans les deux runs) diffère du dernier run
enregistré, tout est traité comme nouveau : aucun filtrage, et tous les
assets observés sont écrits `new`.

### Reprise

`scanforge resume` d'un run incrémental reste incrémental (option persistée
dans le manifest). Le digest du focus est ajouté au hash d'entrée des modules
concernés (`internal/orchestrator/checkpoint.go`) : un résultat calculé avec un
autre focus n'est jamais réutilisé.

## `scanforge assets <cible>`

```
scanforge assets example.com            # état courant de tous les assets
scanforge assets example.com --new      # statut new
scanforge assets example.com --gone     # assets disparus
scanforge assets example.com --json
```

## Limites

- Un seul run à la fois par cible est supposé pour l'écriture de l'historique.
- Le fichier croît à chaque run (snapshot complet) ; il peut être archivé ou
  supprimé à la main : le run suivant repart alors d'un historique vide.
