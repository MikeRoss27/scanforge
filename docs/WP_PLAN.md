# Plan — Parité wpscan dans ScanForge (`wp`)

> Statut : **proposition** — à valider avant implémentation.
> Auteur : brainstorming initial. Branche : `feat/wp-parity`.

## 1. Objectif et cadrage

Ajouter à ScanForge une couverture fonctionnelle **équivalente à celle de `wpscan`** (le scanner WordPress de WPScan) pour les engagements WordPress autorisés, **sans nouvelle dépendance externe** : modules natifs + dataset embarqué + templates Nuclei embarqués, le tout branché sur l'architecture artefacts existante (DAG, scope strict, `filterArtifact`).

- **Cible UX** : un preset `wp` + un flag `--wp`.
  - `scanforge run example.com --preset wp` (ou `--profile wp`) — équivalent d'un engagement wpscan complet.
  - `scanforge run example.com --profile web --wp` — force le mode WordPress sur n'importe quel profil (ajoute la chaîne WP au DAG choisi).
  - `scanforge plan example.com --preset wp` — preview du DAG ; `scanforge doctor --profile wp` — diagnostic (outils, dataset, wordlists).
- **Parity ≠ identical output** : wpscan fournit un *score de risque* et une DB CVE live ; nous livrons des **findings structurés** corrélés à un **dataset embarqué** (rafraîchi à chaque release), plus de la report taxonomy existante.
- **Hors périmètre** : aucune exploitation active (aucun RCE/PoC exécuté), aucune tentative d'authentification sans consentement explicite.

## 2. Décisions verrouillées (brainstorming)

| Décision | Choix |
| --- | --- |
| Exposition CLI | Profil/preset `wp` **et** flag `--wp` (les deux) |
| Données CVE | **Dataset embarqué** (comme `techcve`), raffrachi à chaque release. Pas d'API WPScan. |
| Brute-force wp-login / XML-RPC | **Oui, mais opt-in strict** (défaut OFF, voir garde-fous §7) |
| Rappel | Scope, `--confirm-scope`, `--dry-run`, artefacts `Scoped` + `scope-rejections.jsonl` : inchangés |

## 3. Référence fonctionnelle : inventaire wpscan → ScanForge

État : ✅ = déjà couvert, 🔧 = à construire.

| # | Capacité wpscan | Équivalent ScanForge | État |
| --- | --- | --- | --- |
| 1 | Détection WordPress + version core (generator meta, readme.html, feeds, /wp-json/, cookies) | `wpdetect` (nouveau, natif) + `whatweb` ✅ | 🔧 / ✅ |
| 2 | Enumeration plugins **passive** (assets `/wp-content/plugins/<slug>/…` dans le HTML, `?ver=`) | `wpplugins` mode passif (nouveau ; lit artefacts katana/httpx) | 🔧 |
| 3 | Enumeration plugins **agressive** (`/wp-content/plugins/<slug>/readme.txt`, "Stable tag") | `wpplugins` mode agressif (wordlist slugs + concurrence + anti-429) ; `--wp-detection-mode=passive\|mixed\|aggressive` | 🔧 |
| 4 | Détection version plugins (readme.txt / changelog.txt / assets) | intégré à `wpplugins` (champ `version`) | 🔧 |
| 5 | Enumeration thèmes (passive + agressive) | `wpthemes` (miroir de `wpplugins`) ; version via `style.css` `Version:` + readme.txt | 🔧 |
| 6 | Enumeration utilisateurs (`?author=N` → 301 → `/author/<slug>`, `/wp-json/wp/v2/users`, `/author/` feeds) | `wpusers` (natif, multi-sonde, scoped) | 🔧 |
| 7 | Vulnérabilités core (version → CVE, "fixed in") | extension `techcve` avec dataset WP (core + plugins + thèmes) | 🔧 |
| 8 | Vulnérabilités plugins/thèmes | dataset embarqué + templates Nuclei `templates/wordpress/` | 🔧 |
| 9 | `wp-config.php` backups/variantes exposés (`.bak`, `.old`, `.swp`, `~`, `.save`) | `wpexposure` (natif) | 🔧 |
| 10 | `debug.log` (`wp-content/debug.log`), `readme.html`/`license.txt`, `install.php`, `setup-config.php` | `wpexposure` | 🔧 |
| 11 | Directory listing (`/wp-content/uploads/`, plugins dirs, `Index of`) | `wpexposure` | 🔧 |
| 12 | XML-RPC activé (`/xmlrpc.php`, `system.listMethods`, multicall) | `wpxmlrpc` (natif) | 🔧 |
| 13 | Pingback = participation SSRF/DDoS reflection (info uniquement) | reporté par `wpxmlrpc` comme finding **informationnel** ; pas de rebinding réel | 🔧 |
| 14 | REST API exposée + `/wp-json/wp/v2/users` (user disclosure) | `wpexposure` + `wpusers` | 🔧 |
| 15 | `.git/HEAD`, `.env`, `.htaccess`, `phpinfo()`, `wp-config.php` parents | `wpexposure` (checks génériques, partagés) | 🔧 |
| 16 | Brute-force `wp-login.php` / XML-RPC `wp.getUsersBlogs` (`--usernames`, `--passwords`, threads, stop-on-hit) | `wpbrute` (natif, **opt-in strict**, §7) | 🔧 |
| 17 | Throttle / anti-ban / concurrence (`--throttle`, `--max-threads`) | `workerCount` + backoff 429 + jitter comme `httpcheck` ; `--wp-rate-limit` | 🔧 |
| 18 | Proxy / cookies / headers auth | `--proxy`, `-H/--header` existants ✓ | ✅ |
| 19 | WAF detection | `wafw00f` ✓ | ✅ |
| 20 | Technologie / CMS fingerprint | `whatweb` ✓ (enrichi par `wpdetect`) | ✅ / 🔧 |
| 21 | Screenshots, headers sécurité | `screenshot` ✓, `httpcheck` ✓ | ✅ |
| 22 | Rapport consolidé + SARIF / DefectDojo | rapports `report.json`/`report.md` + `scanforge export` avec `module:wordpress` | ✅ / 🔧 |
| 23 | Diff entre deux runs (plugins/thèmes/users en plus/moins) | `scanforge diff` (reprend les artefacts WP) | ✅ / 🔧 |
| 24 | robots.txt / sitemap.xml / dirs | `katana`, `ffuf` ✓ | ✅ |
| 25 | HTTP(S) non-200, redirects arbitraires sur sondes | délégué httpx + suivi de redirect scope-aware (défaut : ne pas sortir du scope) | ✅ / 🔧 |

**Conclusion parity** : les 25 axes wpscan sont tous planifiés ; 3 axes reposent sur l'existant, le reste est neuf mais suit les patrons existants (`httpcheck`, `techcve`, `screenshot`).

## 4. Architecture

### 4.0 Modules (nouveaux, sous `internal/modules/`)

Chaque module suit le patron `modules.Module` + `New()` + `Name/Description/Requires/Produces/Run`, enregistré dans `buildRegistry()` (`internal/app/registry.go`), exécuté via `runner.Executor`, artefacts texte host/URL déclarés `Scoped: true` dans `filterArtifact`.

| Module | `Requires` | `Produces` | Notes |
| --- | --- | --- | --- |
| `wpdetect` | `resolved_hosts` ou `alive_urls` (soft `alive_urls`) | `wp_fingerprint` (JSON) | Multi-sonde core : generator, readme.html, feed, cookies, `/wp-json/` ; sortie `is_wordpress`, `core_version`, `sources[]`, `confidence` |
| `wpplugins` | `wp_fingerprint` (+ `crawled_urls` en passif) | `wp_plugins` (JSONL) | Modes `passive` (défaut) / `mixed` / `aggressive` (`--wp-detection-mode`) ; passive = parse artefacts katana/httpx (paths + `?ver=`), agressif = `--wp-wordlist` (embarqué taillé, ~3k slugs + user-extensible) ; version via `readme.txt` ("Stable tag") ; 1 worker pool 8, backoff 429/403 |
| `wpthemes` | `wp_fingerprint` | `wp_themes` (JSONL) | Même patron ; version via `style.css` + readme.txt |
| `wpusers` | `wp_fingerprint` | `wp_users` (JSONL) | Sondes `?author=N` (N≤10), REST `/wp-json/wp/v2/users`, `/author/<slug>` ; login, display_name, id, source, confidence |
| `wpexposure` | `wp_fingerprint` | `wp_exposure` (JSONL) | wp-config backups (10 variantes), debug.log, readme.html/license.txt, install.php/setup-config.php, uploads listing, REST users, `.git/HEAD`, `.env`, `.htaccess`, phpinfo, directory listing ; finding par variante avec URL + "redacted=true" |
| `wpxmlrpc` | `wp_fingerprint` | `wp_xmlrpc` (JSON) | `/xmlrpc.php` : 200+`<?xml` → enabled ; `system.listMethods` ; détecte multicall + pingback (info) ; cap body ~1 Mo |
| `wpbrute` | `wp_fingerprint` (+ `wp_users` si produit) | `wp_brute` (JSONL) | **Opt-in strict** (§7) : défaut off, sévèrement limité |
| extension `techcve` | `techcve` existant | `cve_findings` (enrichi) | Dataset `internal/modules/techcve/data/wordpress.json` : core/plugins/thèmes → `fixed_in` ; clé `(slug, version)` |

`internatl/modules/nuclei` (inchangé) : ship `templates/wordpress/*.yaml` (expo backups, default files, CVE templates WP) — consommés via le mécanisme `--nuclei-include-custom` / `SCANFORGE_TEMPLATES_DIR` actuel.

### 4.1 Détection `--wp` (flag) vs profil `wp`

- **Profil `wp`** (`--preset wp` / `--profile wp`) : DAG dédié wordpress-only :
  `subfinder → dnsx → httpx → wpdetect → wpplugins / wpthemes / wpusers / wpexposure / wpxmlrpc → techcve → nuclei(wordpress) → report`
  (pas de JS/confusion: vue scanner WP = version + surface + vulns).
- **Flag `--wp`** : ajoute la chaîne WP (`wpdetect…wpxmlrpc`) **après** les artefacts prérequis sur n'importe quel profil (`web --wp`, `deep --wp`, `safe --wp`). Implémenté côté sélection de modules (dans `app.plan`/`run` : si `--wp`, append/replace set WP + ensure `wpdetect` présent).
- **Doctor** : profile `wp` ajoute checks : dataset présent + date de snapshot, wordlists agressives (warn si absentes), katana/nuclei présents.

### 4.2 Artefacts (tous déclarés, `Scoped` où applicable)

| Artefact | `Scoped` | Contenu |
| --- | --- | --- |
| `wp_fingerprint` | non (dérivé, données déjà scoped) | `{target, is_wordpress, core_version, sources[], confidence, detected_at}` |
| `wp_plugins` | non (métadonnées) / **`wp_plugin_urls` séparé Scoped** | slug, version, detection, source_url (dans JSON, pas d'artifact URL séparé) |
| `wp_themes` | non | idem |
| `wp_users` | non / `wp_author_urls` Scoped | login, display_name, id, source, confidence |
| `wp_exposure` | **via URLs dans chaque finding, artifacts texte `Scoped: true`** | kind, url, evidence, severity, remediation |
| `wp_xmlrpc` | non (JSON) | enabled, methods_count, has_multicall, pingback, evidence_url |
| `wp_brute` | n/a (pas d'artifact URL) | username, method, success, attempts, duration_ms, lockout_detected |

Règles : tout artefact texte host/URL/host:port produit → `Artifact.Scoped: true` (choke point `filterArtifact`). Les rejections atterrissent dans `00_meta/scope-rejections.jsonl` (existant).

### 4.3 Données embarquées (dataset)

- `internal/modules/techcve/data/wordpress.json` — snapshot **WP core / plugins / thèmes** : slug, noms, versions vulnérables, `fixed_in`, CVE, CVSS. Source candidate : **WPScan Vulnerability Database** (usage gratuit, attribution requise) — snapshot figé dans le repo + notice `NOTICES` + version dénotée `wp_data_version` (date) ; `scanforge doctor` affiche la date.
- `templates/wordpress/*.yaml` — templates Nuclei ciblés WordPress (expo backups, debug.log accessible, listing, payloads version discovery). livrés comme le pack existant `templates/`.
- `templates/wordpress/plugins-top.txt`, `themes-top.txt` — wordlists slugs taillées (~3 000 entrées chacune, largeur tokens courante). Possibilité `--wp-wordlist / chemin/full_list.txt` pour parité totale (wordlist complète de l'utilisateur, ex. export WPScan offline — pas embarquée pour taille/licence).
- Refresh : manuel à chaque release + job CI optionnel (`wp-data-refresh` non-bloquant).

### 4.4 Reporting / `diff` / `export`

- `report.json` : section `wordpress: { core, plugins[], themes[], users[], exposures[], xmlrpc{…} }`.
- `report.md` : section **WordPress** : core détecté (confiance), tableau plugins (version / fixed_in / CVEs), thèmes idem, users, exposures avec URLs, XML-RPC status, remediation concise.
- `scanforge diff` : compare artefacts `wp_*` (nouveau/ancien plugins, thèmes, users, exposures).
- `scanforge export` : finding `module: wordpress` (SARIF ruleId `WP-*`, DefectDojo `CWE/CVSS passthrough`).

### 4.5 Wordlist / rate-limit / stealth

- Défaut : **passive uniquement** (aucun fuzzing agressif sans opt-in) ; request cap global ~500 sondes WP par cible hors `--wp-detection-mode=aggressive`.
- Mode agressif : `-X` concurrence 8, backoff exponentiel 429/403/lockout, jitter ±20 %, ua réaliste + `-H` headers utilisateur, `--proxy` supporté.

## 5. UX cible (avant/après)

```bash
scanforge plan example.com --preset wp                       # preview du DAG
scanforge run example.com --preset wp                        # engagement WP complet (passif)
scanforge run example.com --preset wp --wp-detection-mode aggressive --wp-wordlist full.txt
scanforge run example.com --profile web --wp                 # WP + DAG web
scanforge doctor --profile wp                                # dataset/wordlists/outils présents ?
scanforge export runs/.../run --format sarif                 # ruleId WP-*
```

## 6. Plan d'exécution (milestones)

| M | Contenu | Livrables |
| --- | --- | --- |
| **M0 — Scaffolding** | branch `feat/wp-parity` ; preset `wp` (profile.go builtins) + `--wp` ; `scanforge plan` affiche la chaîne WP ; doctor stub ; docs skeleton ; tests plan/DAG | `profile` wp, CLI flag, doctor profile, tests DAG snapshots |
| **M1 — Détection + passif** | `wpdetect` multi-sonde ; `wpplugins`/`wpthemes` **passive** (parse katana/httpx) ; report section ; fixtures HTML/RSS/readme.txt | 3 modules + fixtures + report section |
| **M2 — Agressif + dataset CVE** | mode agressif + `--wp-wordlist`, `--wp-detection-mode` ; version detection ; dataset WP core/plugins/thèmes dans techcve ; templates nuclei WP ; doctor data checks | `wp_*.jsonl`, findings CVE corrélés |
| **M3 — Surface** | `wpusers`, `wpexposure` (backups/debug.log/listing/REST/…), `wpxmlrpc`, remediation strings FR/EN | findings exposure complets |
| **M4 — Opt-in brute + durcissement** | `wpbrute` opt-in strict ; docs README/AGENTS/USAGE + miroirs fr/zh ; export tagging ; gate CI ; comparaison `diff` WP | parity complète vs 25 axes §3 |

Aucune milestone ne livre de capacité active autre que §7.

## 7. Garde-fous (invariants, non négociables)

1. **`wpbrute` est OFF par défaut** ; exige les trois : `--wp-bruteforce` + `--confirm-scope` (scope implicite confirmé) + un wordlist explicite (`--wp-passwords`, jamais embarqué).
2. Cap dur : `--wp-bruteforce-max` (def. **100 tentatives**/cible max, configurable mais borné), stop-on-first-success, backoff sur 429/lockout, aucune parallélisation > 4.
3. `wpbrute` **refuse** : scope implicite non confirmé, mode `--dry-run` le journalise sans rien faire, wordlist absente/invalide, utilisateurs non énumérables par `?author`/REST (user-enum d'abord, brute uniquement sur des utilisateurs confirmés).
4. Pingback/SSRF : **détection uniquement**, jamais de rebinding réel. Pas de `system.multicall` spam, 1 sonde max.
5. Tous les endpoints sondés passent par le scope (`filterArtifact`) ; hors-scope = rejet + log dans `scope-rejections.jsonl`.
6. Mode passif par défaut : zéro requête agressive sans opt-in explicite ; `--wp-detection-mode` trace le choix dans `00_meta/commands.log`.
7. `--dry-run` imprime la liste de commandes/paquets sans requête ; wpbrute en dry-run n'émet rien.

## 8. Risques & limites honnêtes

- **Zéro-day/fresh CVEs** : parity limitée au snapshot dataset (rafraîchi par release) ; pas de live API → "très bonne" couverture, pas parfaite.
- **Wordlists agressives complètes** (~150k slugs) : non embarquées (taille/licence) → utilisateur fournit `--wp-wordlist` pour parity totale ; défaut taillé ~3k slugs.
- **Faux positifs** : multi-sonde + confidence ; readme.txt public ≠ vuln réelle ; reporting expose la confiance au lecteur.
- **Rate-limiting/ban** : backoff générique + documentation ; l'utilisateur reste responsable (scope déjà requis).
- **WordPress headless/découplé** (API-only, pas de readme.html) : détection dégradée → confidence reflète ; `wpdetect` liste les sources positives.
- **Scope juridique** : parité fonctionnelle ne change pas la responsabilité — outil réservé aux hôtes autorisés (rappel README/blockquote).

## 9. Stratégie de tests

- Fixtures : `testdata/wp/{generator.html, readme.html, feed_rss2.xml, plugin_readme.txt, theme_style.css, rest_users.json, xmlrpc_listmethods.xml, config_bak_200.html, debug_log_200.html, listing.html}` + 404/403/429/500 variants.
- Unit : parsers readme.txt/style.css, sondes (httptest server), scope rejection des artefacts WP, concurrence/backoff, `wpbrute` (httptest + fake successful login ; refuse sans flags), rapport section snapshot.
- Intégration : `plan --preset wp` wave snapshot ; `doctor --profile wp` JSON output.
- Rien n'atteint le réseau sans httptest ou `--dry-run`.

## 10. Effort indicatif

M0 ½ j · M1 2–3 j · M2 3–4 j · M3 2–3 j · M4 2–3 j + docs i18n ~1 j. **Total ≈ 10–14 j**. Aucune nouvelle dépendance Go majeure (stdlib HTTP comme `httpcheck`, nuclei déjà embarqué).

## 11. Docs à mettre à jour (M4)

`README.md` (+ fr/zh), `docs/{USAGE,SCOPE,ARCHITECTURE,ROADMAP}.md` (+ fr/zh), `AGENTS.md` (modules `wp_*`, artifacts, garde-fous), `docs/WP_PLAN.md` → version "livrée".

## 12. Décisions ouvertes (arbitrées comme experts le 2026-11-18)

1. **DAG du preset `wp`** : DAG WP-uniquement (proposé) **adopté** — `web --wp` couvre le cas mixte.
2. **Dataset** : snapshot statique + attribution, refresh manuel par release — **adopté**. La génération CI quotidienne est rejetée (fragilité + licence/attribution floue).
3. **Wordlists agressives** : liste taillée embarquée (`templates/wordpress/plugins.txt`, `themes.txt`, ~1 000–1 500 entrées, données publiques WP.org, attribution dans `NOTICES`) + `--wp-wordlist` pour la liste complète — **adopté**.
4. **wpbrute absent de `--preset wp`** : opt-in strict uniquement — **confirmé**.
5. **Nom du preset** : `wp` canonique + alias `wordpress` résolu vers la même chaîne — **adopté** (cohérence avec les noms de presets courts : `web`, `safe`).

## 13. Implémentation

Branche : `feat/wp-parity`. Ordre : M0 scaffold (profil, flag, doctor) → M1 modules de détection/passifs → M2 agressif + dataset CVE → M3 surface (users/exposure/xmlrpc) → M4 wpbrute + reporting/diff/export + docs. `wpcve` est un module natif dédié (artefact `wp_fingerprint`/`wp_plugins`/`wp_themes` → findings), sur le modèle technique de `techcve` (dataset YAML embarqué, version compare semi-semver).

**État au 2026-11-18 (itération M0–M4 livrée dans cette branche) :**

- ✅ M0 — preset `wp` (+ alias `wordpress`), flag `--wp`, chaîne WP injectable sur tout profil, `moduleRisk` WP, tests DAG/`applyWordPress`
- ✅ M1 — `wpdetect` (multi-signal : generator, RSS, readme.html, REST index, confidence), `wpplugins`/`wpthemes` mode **passive** par défaut (assets crawlés, `?ver=`), report parsers alimentés (`"wp_fingerprint" → technologies`)
- ✅ M2 — modes `mixed`/`aggressive` (`--wp-detection-mode`, wordlists embarquées plugins ~200 / thèmes ~116 + `--wp-wordlist`, sondes `readme.txt`/`style.css`), dataset `wpcve` (core + plugins, NVD-vérifié, 7 advisories), templates Nuclei livrés (`wordpress-config-backup-exposed`, `wordpress-install-exposed`, `wordpress-readme-exposed`)
- ✅ M3 — `wpusers` (?author=N + REST users), `wpexposure` (18 checks : wp-config backups, debug.log, install/setup-config, listings, .git/.env/phpinfo), `wpxmlrpc` (listMethods, multicall, pingback informatif), intégration report (`wp_users` info, `wp_exposure`, `wpxmlrpc`)
- ✅ M4 — `wpbrute` opt-in strict (wp-login + XML-RPC `wp.getUsersBlogs`, caps, stop-on-success/lockout, refus sans users énumérés ou sans `--wp-passwords`), `scanforge export` consomme les findings WP via le modèle `Vulnerability` existant (SARIF/DefectDojo gratis), docs USAGE/README/AGENTS + miroirs fr/zh
- Tests : unit (modules + helpers + refus de `wpbrute`), **intégration E2E** `internal/app/wordpress_integration_test.go` (faux site WP via httptest + chaîne complète orchestrée, assertions sur tous les artefacts dont `CVE-2020-35489` corrélation)

**Reste à faire / décisions reportées** : dataset WP riche (au-delà des 7 advisories vérifiées), wordlists agressives complètes (~150k slugs, non embarquées par licence/taille), refresh CI du dataset (rejeté), `wpbrute` jamais dans le preset, packaging `NOTICES.md` complet, licence/wordlist review avant merge.
