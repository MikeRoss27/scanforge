# Modèle de preuves des findings

Chaque finding de `report.json` porte, en plus de ses champs historiques, une
couche **provenance / confiance / statut / preuves**. Elle dit d'où vient le
finding, jusqu'où il a été vérifié et ce qui a réellement été vérifié.

Principe directeur : **ne jamais inventer une vérification.** Seul le module qui
a effectivement vérifié quelque chose peut relever un statut. Triage, export,
MCP et API lisent ces champs, ils ne les modifient jamais.

## Champs (additifs, `omitempty`)

Les champs sont ajoutés à chaque entrée de `assets.<hôte>.vulnerabilities[]` ;
un `report.json` plus ancien se relit et se réécrit à l'identique.

| Champ | Contenu |
|---|---|
| `source` | inchangé : nom du module producteur (chaîne). |
| `provenance` | `{module, tool, tool_version}`. `tool_version` vient de `00_meta/manifest.json` (`tool_versions`, détection best effort au lancement) pour les outils externes, de la version de ScanForge pour les modules natifs (`tool: "scanforge"`). Vide quand la version est inconnue. |
| `confidence` | `low` \| `medium` \| `high`. |
| `status` | `potential` \| `version-match` \| `validated` \| `inconclusive`. |
| `evidence_items[]` | `{kind, summary, artifact, excerpt, verified_by}`. |

Écarts de nommage assumés pour ne rien casser : `source` et `evidence` existent
déjà (chaîne) ; la forme structurée s'appelle donc `provenance` et
`evidence_items`.

**Confiance catégorielle** (`low/medium/high`) plutôt qu'un flottant 0..1 : pas
de fausse précision, lisible dans les exports. (Les *insights* de triage gardent
leur confiance flottante, indépendante de celle des findings.)

`evidence_items[].artifact` est un chemin relatif au run (ex.
`06_vulns/nuclei.jsonl`). `excerpt` est copié tel quel. `verified_by` décrit en
clair ce qui a été **réellement** vérifié (et, pour un `potential`, ce qui ne l'a
pas été).

## Secrets

Les valeurs fuitées **sur la cible** (clés, tokens) restent **en clair** dans
`evidence`, `evidence_items[].excerpt`, `get_findings` et `get_evidence` : ce sont
les preuves du bounty. Seuls les identifiants de l'**opérateur** (en-têtes,
clés d'API) sont masqués dans les logs et les sorties servies
(`internal/runindex`).

## Règles de statut

| Producteur | Cas | `status` | `confidence` |
|---|---|---|---|
| `nuclei` | template apparié | `potential` | `medium` |
| `techcve` / `wpcve` | jeu de données embarqué, version dans l'intervalle affecté | `version-match` | `medium` |
| `techcve` | vulnintel `exact-cpe-range` | `version-match` | `high` |
| `techcve` | vulnintel `version-range` | `version-match` | `medium` |
| `techcve` | vulnintel `name-only` / `confirmed=false` (piste) | `potential` | `low` |
| `jssecrets` | secret / valeur littérale (cloud-storage, host interne, email, source-map...) | `potential` | `medium` |
| `jssecrets` | motif de code (`dom-sink`, `node-sink`, `proto-pollution`, `postmessage`, `env-leak`) | `potential` | `low` |
| `jssecrets` + `jsverify` `executed` | payload exécuté dans un navigateur headless | `validated` | `high` |
| `jssecrets` + `jsverify` `sink-reached` | puits atteint, exécution non observée | `inconclusive` | `medium` |
| `jssecrets` sans verdict exploitable | pas rejoué, ou `not-observed` / `unreachable` | `potential` | inchangée |
| `jsverify` (finding `verified_secret`) | `executed` / `sink-reached` | `validated` / `inconclusive` | `high` / `medium` |
| `httpcheck` | en-tête / cookie lu directement dans la réponse | `validated` | `high` |
| `wpexposure` | ressource en HTTP 200 contenant le marqueur attendu | `validated` | celle du module |
| `wpusers` | login renvoyé par l'endpoint de la cible | `validated` | celle du module |
| `wpxmlrpc` | endpoint répond à une requête de liste de méthodes | `validated` | `high` |
| `wpbrute` | authentification acceptée par la cible | `validated` | `high` |

Remarques :

- `version-match` signifie *la version détectée est dans l'intervalle affecté* ;
  la vulnérabilité elle-même n'est pas exercée.
- `validated` pour `httpcheck` / `wp*` désigne l'observation directe du fait
  annoncé (un en-tête absent, un endpoint exposé), pas une exploitation.
- Un `jssecrets` n'est `validated` que si `jsverify` l'a rejoué avec le verdict
  `executed` (même URL de script et même motif). Un verdict plus faible ne
  rétrograde jamais un `validated`.
- `dbdetect` / `dbenum` ne produisent pas d'entrée `vulnerabilities[]` dans
  `report.json` aujourd'hui : ils n'ont donc pas de statut.
- Tout producteur non listé, ou tout finding issu d'un ancien rapport, n'a pas
  de `status` : les consommateurs doivent le traiter comme « non renseigné », pas
  comme `potential`.

## Où c'est affiché

- **`report.md`** : sous chaque tableau de vulnérabilités, une ligne
  « Evidence » par finding annoté (statut, confiance, source + version,
  artefact et `verified`).
- **SARIF** : `kind` = `fail` si `validated`, sinon `review` (omis sans statut) ;
  `rank` = confiance (20 / 50 / 90) ; `properties` : `scanforge/status`,
  `scanforge/confidence`, `scanforge/provenance`, `scanforge/evidence`.
- **DefectDojo** : `verified` vrai uniquement si `validated`, `under_review`
  sinon ; tags `status:*` et `confidence:*` ; `severity_justification` ;
  `steps_to_reproduce` = les entrées de preuve avec leur `verified_by`.
- **MCP / API** : `get_findings` (`/findings`) renvoie les nouveaux champs et
  accepte les filtres `status` et `confidence` ; `get_evidence` d'un finding
  renvoie `evidence_items`.
- **Triage** : `status` et `confidence` sont transmis au LLM ; le résumé
  déterministe donne la répartition des statuts ; un insight dont aucun finding
  couvert n'est `validated` reçoit une entrée d'incertitude ; la confiance d'un
  insight LLM est plafonnée par la confiance la plus faible des findings couverts
  (low 0,4 / medium 0,7). Triage ne crée ni ne relève jamais un statut.

L'ID d'un finding (`F-...`) ne dépend pas de cette couche : il est identique avec
ou sans elle.

## Découverte récursive dans le rapport

Les passes de suivi de `--recursive` (`07_recursive/`, voir `docs/RECURSIVE.md`)
sont intégrées à `report.json` par `report.GenerateReport` (donc visibles par
`scanforge diff`, `export`, `triage` et l'historique d'assets). Les parseurs
existants (`ParseHosts`, `ParseKatana`, `ParseDnsx`, `ParseHttpx`) sont réutilisés
sur un rapport temporaire puis fusionnés. Filtrage de scope :

1. les listes texte (`*-resolved.txt`, `*-alive.txt`, `*-katana.txt`) ont déjà
   été filtrées sur place par `RunContext.AddArtifact` ;
2. les JSONL bruts (`*-dnsx.jsonl`, `*-httpx.jsonl`) ne sont fusionnés que pour
   les hôtes/URL présents dans la liste filtrée de la même passe ;
3. en défense en profondeur, chaque hôte fusionné est revérifié contre
   `00_meta/effective-scope.txt` quand le fichier est lisible.

Les assets qui n'existent que grâce à la récursion portent
`"discovered_by": "recursive"`.
