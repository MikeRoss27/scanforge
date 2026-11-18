# Third-party data bundled with ScanForge

## Embedded advisory datasets

`internal/modules/wpcve/cves_wp.yaml` is a merged dataset: a hand-curated
set of high-impact advisories (verified against the NVD,
https://nvd.nist.gov/) plus a generated export of the **OWVD**
(github.com/ihuzaifashoukat/wordpress-vulnerability-database, MIT license) —
which itself redistributes the **Wordfence Intelligence** vulnerability data
feed (https://www.wordfence.com/threat-intel/vulnerabilities/). It covers
~2,100 advisories selected for all Core rows, all Critical-rated rows and
all bundled plugins/themes slugs; references point at the NVD. Regenerate with
`python3 scripts/wpdata_refresh.py` (network) or `--csv <file>` offline.
The `techcve` dataset (`internal/modules/techcve/cves.yaml`) remains a
curated starter set of third-party advisories.

## WordPress plugin / theme slug wordlists

`internal/modules/wpplugins/plugins-top.txt` and
`internal/modules/wpthemes/themes-top.txt` are curated lists of the most
common plugin/theme slugs taken from the public WordPress.org directory
(https://wordpress.org/plugins/, https://wordpress.org/themes/), deduplicated
and normalized. They are used only in `--wp-detection-mode=aggressive` and
can be replaced wholesale with `--wp-wordlist`.

No commercial wordlist or proprietary dataset is bundled.

## Banners and artwork

`public/scanforge-*.png` and `internal/console/assets/forge-loading-*.png`
are original ScanForge artwork (pixel-art forge identity), generated for this
project.
