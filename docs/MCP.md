# Serveur MCP (`scanforge mcp`)

Expose le magasin de runs fichier (`runs/<cible>/<horodatage>/`) à un agent IA via le
protocole MCP (JSON-RPC 2.0, une ligne par message, sur stdin/stdout). Aucune base de données :
tout est lu depuis `manifest.json`, `report.json` et les artefacts `01_` à `06_`.

```json
{ "mcpServers": { "scanforge": { "command": "scanforge", "args": ["mcp"] } } }
```

## Outils

| Outil | Mode | Rôle |
|---|---|---|
| `scanforge.list_runs` | lecture | Liste les runs (filtre `target`, `limit`) |
| `scanforge.get_run` | lecture | Statut, modules, provenance du scope, compteurs |
| `scanforge.get_assets` | lecture | Assets (ports, HTTP, TLS, technos) |
| `scanforge.get_findings` | lecture | Findings, plus sévères d'abord (filtres `severity`, `asset`, `source`, `kind`, `status`, `confidence` ; chaque finding porte `provenance`, `status`, `confidence`, `evidence_items`, voir `docs/EVIDENCE.md`) |
| `scanforge.get_evidence` | lecture | Preuve d'un `finding_id`, ou tranche d'un fichier d'artefact (`file`, `offset`, `max_bytes`) |
| `scanforge.plan_scan` | lecture | Vagues du pipeline validé ; ne crée aucun run |
| `scanforge.start_authorized_scan` | **actif** | Lance `scanforge run` (désactivé par défaut) |
| `scanforge.stop_scan` | **actif** | Interrompt proprement un scan lancé par ce serveur |

`run_id` a la forme `<dossier-cible>/<horodatage>` (voir `list_runs`). Tout identifiant contenant
`..`, un `/` en trop, un chemin absolu ou sortant du workspace (liens symboliques inclus) est rejeté.

## Modèle de permissions

Les outils actifs sont refusés tant que le serveur n'est pas lancé ainsi :

```
scanforge mcp --allow-active --scope scope.txt [--audit-log audit.jsonl]
```

- `--allow-active` **et** `--scope <fichier>` sont obligatoires ensemble. Le scope est strict
  (sémantique `--scope` de `scanforge run`) : pas de scope implicite, pas de confirmation interactive.
  Le fichier est relu à chaque démarrage de scan.
- L'agent ne peut pas fournir son propre scope : seule la cible est un paramètre, et elle doit
  être autorisée par le fichier (les exclusions `!` gagnent). Le processus enfant revérifie le scope.
- Les arguments inconnus sont rejetés : il n'existe aucun paramètre pour des en-têtes, cookies,
  proxy ou clés.
- Au plus 2 scans simultanés. `stop_scan` n'agit que sur les scans lancés par ce serveur
  (SIGINT, puis kill après 15 s).
- Chaque appel actif (autorisé **ou refusé**) est ajouté à un journal JSONL (0600), par défaut
  `<workspace>/.scanforge-audit.jsonl` : heure, acteur, action, décision, raison, cible, profil,
  `scan_id`, PID, fichier de scope. Aucun secret n'y est écrit.
- La sortie des scans lancés est dans `<workspace>/.scanforge-active/scan-<id>.log`.

## Règle sur les secrets

- Les **valeurs trouvées sur la cible** (clés AWS, tokens dans du JS...) sont renvoyées **telles
  quelles** : ce sont les preuves du bounty. Aucun masquage des findings.
- Les **identifiants de l'opérateur** (clés API de `~/.scanforge/auth.yaml`, clé IA de la config,
  en-têtes/cookies/proxy passés à un scan, relus depuis `00_meta/commands.log`) sont remplacés par
  `[REDACTED-OPERATOR-SECRET]` dans toute sortie. `00_meta/` n'est jamais servi.
