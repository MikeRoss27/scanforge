# Reprise de scan, checkpoints et suivi des runs

Chaque run enregistre l'état de ses modules dans `00_meta/manifest.json`
(fichier uniquement, aucune base de données). Le manifeste est écrit de façon
atomique (fichier temporaire + `rename`) à chaque changement d'état : un run
interrompu (Ctrl+C, crash, coupure) reste donc reprenable.

## Commandes

```bash
scanforge runs list [--target example.com] [--json]   # runs du workspace, du plus récent au plus ancien
scanforge status <run-id> [--json]                    # état de chaque module + indication « resumable »
scanforge resume <run-id>                             # relance uniquement ce qui reste à faire
```

`<run-id>` est l'identifiant horodaté (`2026-08-18_10-00-00`), `cible/id`
(si le même id existe pour plusieurs cibles) ou le chemin du dossier du run.

## États d'un module

`pending`, `running`, `completed`, `failed`, `skipped`, `cancelled`.
Un run tué brutalement laisse des modules `running` ou `pending` : ils sont
simplement relancés à la reprise.

## Règles de reprise

Un module est **réutilisé** (non relancé) seulement si tout est vrai :

1. son état est `completed` (ou `skipped` par le module lui-même, « non applicable ») ;
2. son `input_hash` est identique ;
3. ses artefacts et fichiers de sortie existent toujours.

Sinon (`pending`, `running`, `failed`, `cancelled`, entrée modifiée, sortie
supprimée) il est relancé. Les modules réutilisés republient leurs artefacts
via `RunContext.AddArtifact` : le filtrage de scope est donc réappliqué.

`input_hash` = sha256 de : version du hash, module, cible, profil, dry-run,
scope effectif, paramètres du module (proxy, en-têtes, options de l'outil
concerné : nuclei, ffuf, nmap, WordPress ; timeout configuré), version de l'outil
externe (si obtenue via `-version`/`--version`, hors dry-run) et empreinte du
contenu des artefacts requis. Si un module amont est relancé mais produit la
même sortie, les modules aval restent en cache.

## Sécurité du scope

`resume` recharge `00_meta/effective-scope.txt` et vérifie son sha256 par
rapport à `scope_sha256` du manifeste ; toute modification (élargissement
compris) fait refuser la reprise. Aucune option de scope n'existe sur `resume`.
Les hôtes ajoutés en cours de run (`scope-additions.jsonl`) ne sont pas
réappliqués. Les runs créés avant cette fonctionnalité (sans `scope_sha256`)
ne sont pas reprenables : lancer un nouveau run.

## Proxy et en-têtes

`--proxy` et `--header` peuvent contenir des secrets : ils ne sont **pas**
écrits dans le manifeste. Pour reprendre un run authentifié, repassez les mêmes
valeurs ; sinon leur empreinte diffère et les modules concernés sont relancés.
Les autres options (nuclei, ffuf, nmap, WordPress) et la liste des modules sont
sauvegardées dans `params` et restaurées automatiquement.
