# Gestion du scope

Le scope est toujours obligatoire comme garde-fou, mais le fichier
`scope.txt` ne l'est pas. ScanForge résout un périmètre effectif avant de créer
un run, puis filtre les artefacts transmis entre modules.

## Scope implicite

Sans fichier applicable, le mode `exact` autorise uniquement la cible :

```bash
scanforge plan example.com --scope-mode exact
```

Le mode `domain` autorise la racine et ses sous-domaines :

```bash
scanforge plan example.com --scope-mode domain
```

Ajoutez ou excluez des entrées avec des options répétables :

```bash
scanforge run example.com --scope-mode domain \
  --scope-add api.other.test \
  --scope-add 10.20.0.0/24 \
  --exclude admin.example.com \
  --exclude '*.legacy.example.com'
```

Les exclusions sont prioritaires. Les CIDR sont acceptés uniquement comme
ajouts explicites ; le mode `domain` refuse les IP, CIDR et noms mono-label.

## Fichier de scope

Un fichier accepte les hôtes, wildcards, CIDR et exclusions préfixées par `!` :

```text
example.com
*.example.com
10.20.0.0/24
!admin.example.com
!*.legacy.example.com
```

Utilisez-le explicitement avec `--scope scope-client.txt`, ou configurez
`default_scope`. Un fichier fourni par `--scope` est strict : si la cible n'est
pas autorisée, le run échoue sans fallback. Il ne peut pas être combiné avec
`--scope-mode`, `--scope-add` ou `--exclude`.

Si le fichier configuré par défaut est absent ou ne couvre pas la cible,
ScanForge propose un scope implicite et demande confirmation. Un fichier valide
qui couvre la cible ne nécessite pas de confirmation supplémentaire.

## Traçabilité et CI

Chaque run conserve :

- `00_meta/effective-scope.txt` : règles réellement appliquées ;
- `scope_source` et `scope_mode` dans le manifeste ;
- `00_meta/scope-rejections.jsonl` : valeurs rejetées.

En CI, prévisualisez avec `plan`, puis passez `--confirm-scope` uniquement pour
un scope implicite. Cette option confirme le périmètre affiché ; elle ne
désactive jamais le filtrage.
