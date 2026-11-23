# API HTTP locale (`scanforge api`)

API JSON sur le magasin de runs fichier, partageant le lecteur d'index et les règles de
permissions du serveur MCP (voir `docs/MCP.md`).

```
scanforge api [--listen 127.0.0.1:8787] [--token-file ./token] [--allow-active --scope scope.txt]
```

## Sécurité

- Écoute sur `127.0.0.1` uniquement ; une autre adresse est refusée sauf `--unsafe-bind`.
  L'en-tête `Host` doit être local (protection contre le DNS rebinding).
- Un jeton bearer est généré à chaque démarrage (affiché sur stderr, ou écrit en 0600 avec
  `--token-file`). Les `GET` de lecture n'en ont pas besoin ; tout le reste oui :
  `Authorization: Bearer <jeton>`.
- Scans actifs désactivés par défaut ; mêmes règles que MCP (`--allow-active` + `--scope`
  obligatoire, cible dans le scope, journal d'audit JSONL).
- Findings renvoyés non masqués ; identifiants de l'opérateur toujours masqués.

## Endpoints

| Méthode | Chemin | Jeton |
|---|---|---|
| GET | `/v1/health` | non |
| GET | `/v1/runs?target=&limit=` | non |
| GET | `/v1/runs/{cible}/{horodatage}` | non |
| GET | `/v1/runs/{cible}/{horodatage}/assets?filter=&limit=&offset=` | non |
| GET | `/v1/runs/{cible}/{horodatage}/findings?severity=&asset=&source=&kind=&limit=&offset=` | non |
| GET | `/v1/runs/{cible}/{horodatage}/evidence?finding_id=` ou `?file=06_vulns/x.jsonl&offset=&max_bytes=` | non |
| POST | `/v1/plan` `{"target","profile","wp"}` | oui |
| POST | `/v1/scans` `{"target","profile","dry_run"}` (202) | oui |
| GET | `/v1/scans` | oui |
| DELETE | `/v1/scans/{id}` | oui |

Codes : 400 identifiant/chemin invalide, 401 jeton, 403 actif désactivé ou cible hors scope,
404 introuvable, 429 trop de scans.

```
curl -s localhost:8787/v1/runs
curl -s -H "Authorization: Bearer $TOKEN" -d '{"target":"example.com"}' localhost:8787/v1/plan
```
