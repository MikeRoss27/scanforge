# Workflows YAML

Un workflow est une alternative declarative aux profils : il selectionne des
modules ScanForge enregistres et regle leur politique d'execution. Il est
**compile en la meme liste de modules qu'un profil** : le DAG, l'orchestrateur
et le filtrage de scope (`RunContext.AddArtifact`) restent inchanges. Un
workflow ne peut jamais executer de commande arbitraire.

```bash
scanforge workflow validate workflows/web-recon.yaml   # validation seule
scanforge plan example.com --workflow workflows/web-recon.yaml   # affiche les vagues
scanforge run example.com --workflow workflows/web-recon.yaml
```

`--workflow` est exclusif avec `--profile`, `--preset` et `--wp`. Les flags CLI
explicites (ex. `--nuclei-severity`) restent prioritaires sur les `params`.

## Format

```yaml
name: web-recon          # lettres, chiffres, . _ -
version: 1               # seule version supportee
steps:
  - id: probe            # unique
    module: httpx        # nom de module enregistre
    needs: [resolve]     # ids des etapes precedentes
    timeout: 15m         # 1s a 24h (defaut : celui du module)
    retries: 1           # 0 a 5, pause croissante entre essais
    on_error: fail       # fail (defaut) | continue | skip
    when:                # optionnel, une seule cle
      artifact_nonempty: alive_urls   # ou artifact_present: <artefact>
    params: {}           # voir ci-dessous
```

- `on_error: continue` : l'etape est marquee `failed`, le run continue.
  `skip` : l'etape est marquee `skipped`. Dans les deux cas, les modules qui
  dependent de ses artefacts sont ignores par l'orchestrateur. Une
  interruption utilisateur n'est jamais adoucie.
- `when` n'accepte que `artifact_present` ou `artifact_nonempty` sur un
  artefact produit par une etape listee dans `needs` (pas d'expression, pas de
  code). Condition fausse : etape `skipped`. En `--dry-run` la condition est
  consideree vraie pour afficher les commandes.
- `params` (liste blanche, types verifies) :
  `nuclei` : `severity`, `exclude_severity`, `tags`, `exclude_tags`,
  `rate_limit`, `templates`, `update_templates`, `headless`, `include_custom`,
  `full_scan`, `scan_timeout` ; `ffuf` : `wordlist`, `filter_codes` ;
  `nmap` : `concurrency` ; `wpplugins`/`wpthemes` : `detection_mode`
  (`passive|mixed|aggressive`), `wordlist`. Les autres modules n'acceptent
  aucun param.

## Validation (avant toute execution)

Rejets : cles `run`/`exec`/`shell`/`command`/`cmd`/`script`/`sh`/`bash`/`eval`/`args`
a tout niveau, ancres/alias YAML, documents multiples, cles inconnues, module
inconnu, module repete, `wpbrute` (reste reserve aux flags CLI), ids en double,
`needs` inconnu / vers soi-meme / cyclique, `needs` incoherent avec les
artefacts (`Requires()` sans producteur dans `needs`, ou `needs` sans lien
d'artefact reel, car l'ordre est derive des artefacts), durees invalides,
params inconnus ou mal types, fichier > 256 Kio, plus de 64 etapes.

## Exemples

Voir `workflows/web-recon.yaml` et `workflows/ports-light.yaml`
(valides en CI par `TestExampleWorkflowsAreValid`).
