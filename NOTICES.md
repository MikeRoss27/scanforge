# Third-party data bundled with ScanForge

## Embedded advisory dataset

`internal/modules/wpcve/cves_wp.yaml` is a **curated starter set** of
high-impact WordPress advisories verified against the NVD
(https://nvd.nist.gov/) and WPScan (https://wpscan.com/) on 2026-11-18. Each
entry carries its NVD reference. Extend the file with the advisories relevant
to your assessments; keep `cvss`, `min-version`, `max-version` and the
`reference` link for every entry.

`internal/modules/techcve/cves.yaml` likewise bundles a curated starter set
of third-party technology advisories.

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
