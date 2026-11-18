#!/usr/bin/env python3
"""Regenerate the embedded WordPress advisory dataset (cves_wp.yaml) from the
OWVD CSV (Open WordPress Vulnerability Database, MIT-licensed wrapper around
Wordfence Threat Intelligence data).

Usage:
    wpdata_refresh.py                  # download the public CSV, write the dataset
    wpdata_refresh.py --csv local.csv  # use a local CSV (offline / reproducible)

Selection policy (deliberate, documented):
  * all Core rows
  * all rows rated Critical
  * all rows for the plugin/theme slugs bundled in the modules
    (internal/modules/wpplugins/plugins-top.txt,
     internal/modules/wpthemes/themes-top.txt)
Merged with the hand-curated entries kept in KEEP (hand-written CVE bounds we
trust more than the source ranges, e.g. NVD-fixed versions).

Semantics match the techcve/wpcve schema: `min-version` is inclusive,
`max-version` is exclusive by default, or inclusive with
`max-inclusive: true` (used for `<=` and `A - B` ranges).
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
import urllib.request
from collections import Counter
from pathlib import Path

OWVD_CSV_URL = (
    "https://raw.githubusercontent.com/ihuzaifashoukat/"
    "wordpress-vulnerability-database/main/vulnerabilities.csv"
)

ROOT = Path(__file__).resolve().parent.parent
DATASET = ROOT / "internal" / "modules" / "wpcve" / "cves_wp.yaml"
PLUGINS_TOP = ROOT / "internal" / "modules" / "wpplugins" / "plugins-top.txt"
THEMES_TOP = ROOT / "internal" / "modules" / "wpthemes" / "themes-top.txt"

# Hand-curated bounds we keep on top of the generated entries (deduped by id,
# tech, min and max).
KEEP = [
    {
        "id": "CVE-2022-21661",
        "tech": "wordpress",
        "title": "WordPress SQL injection via WP_Query before 5.8.3",
        "severity": "high",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2022-21661",
        "max-version": "5.8.3",
    },
    {
        "id": "CVE-2021-29447",
        "tech": "wordpress",
        "title": "WordPress XXE in Media Library (PHP 8, authenticated) before 5.7.1",
        "severity": "high",
        "min-version": "5.6.0",
        "max-version": "5.7.1",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-29447",
    },
    {
        "id": "CVE-2019-17671",
        "tech": "wordpress",
        "title": "WordPress unauthenticated view of private/draft content before 5.2.4",
        "severity": "medium",
        "max-version": "5.2.4",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2019-17671",
    },
    {
        "id": "CVE-2020-35489",
        "tech": "contact-form-7",
        "title": "Contact Form 7 unrestricted file upload (RCE) before 5.3.2",
        "severity": "critical",
        "cvss": 9.8,
        "max-version": "5.3.2",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2020-35489",
    },
    {
        "id": "CVE-2022-29455",
        "tech": "elementor",
        "title": "Elementor DOM-based reflected XSS through 3.5.5",
        "severity": "medium",
        "cvss": 6.1,
        "max-version": "3.5.6",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2022-29455",
    },
    {
        "id": "CVE-2020-11738",
        "tech": "duplicator",
        "title": "Duplicator directory traversal before 1.3.28",
        "severity": "high",
        "max-version": "1.3.28",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2020-11738",
    },
]

HEADER = """# WordPress advisory dataset for the wpcve module — GENERATED + curated.
#
# Source: OWVD (github.com/ihuzaifashoukat/wordpress-vulnerability-database,
# MIT license, distribution of the Wordfence Intelligence data feed compiled
# by Wordfence) merged with a hand-curated set (KEEP in scripts/wpdata_refresh.py).
# Every entry carries a CVE id where one is assigned; reference links point at
# NVD. Regenerate with:  python3 scripts/wpdata_refresh.py
# Semantics: min-version is inclusive, max-version is exclusive unless
# max-inclusive: true (used for `<= X` and `A - B` ranges).
#
# Selection: all Core rows + all Critical rows + all rows for the bundled
# plugin/theme slugs. Generated {today}; {count} entries.
"""

RANGE_RE = re.compile(
    r"^([0-9][0-9A-Za-z.\-_]*)\s*-\s*([0-9][0-9A-Za-z.\-_]*)\s*(\(exclusive\))?$"
)
LE_RE = re.compile(r"^<=\s*v?([0-9][0-9A-Za-z.\-_]*)")
LT_RE = re.compile(r"^<\s*v?([0-9][0-9A-Za-z.\-_]*)")
SINGLE_RE = re.compile(r"^v?([0-9][0-9A-Za-z.\-_]*)$")


def parse_interval(line: str):
    line = line.strip()
    if not line:
        return None
    low = line.lower()
    if low == "all versions" or low.startswith("all version"):
        return {"min": "", "max": "", "inclusive": False}
    m = LE_RE.match(line)
    if m:
        return {"min": "", "max": m.group(1), "inclusive": True}
    m = LT_RE.match(line)
    if m:
        return {"min": "", "max": m.group(1), "inclusive": False}
    m = RANGE_RE.match(line)
    if m:
        return {"min": m.group(1), "max": m.group(2), "inclusive": m.group(3) is None}
    m = SINGLE_RE.match(line)
    if m:
        return {"min": "", "max": m.group(1), "inclusive": True}
    return None


def load_slugs(path: Path) -> set:
    return {
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }


def selection_row(row: dict, p_slugs: set, t_slugs: set) -> bool:
    if (row.get("software_type") or "") == "Core":
        return True
    if (row.get("cvss_rating") or "") == "Critical":
        return True
    return (row.get("software_slug") or "") in p_slugs | t_slugs


def tech_for(row: dict) -> str:
    stype = (row.get("software_type") or "").strip()
    slug = (row.get("software_slug") or "").strip().lower()
    if stype == "Core":
        return "wordpress"
    if stype == "Theme":
        return "theme-" + slug
    return slug  # Plugin


def title_for(row: dict) -> str:
    return " ".join((row.get("title") or "").split())[:140]


def severity_for(row: dict) -> str:
    raw = (row.get("cvss_rating") or "").strip().lower()
    return raw or "medium"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", help="Use a local CSV instead of downloading")
    args = parser.parse_args()

    if args.csv:
        text = io.open(args.csv, encoding="utf-8-sig", errors="replace").read()
    else:
        req = urllib.request.Request(
            OWVD_CSV_URL, headers={"User-Agent": "scanforge-wpdata"}
        )
        with urllib.request.urlopen(req, timeout=300) as response:
            raw = response.read()
        text = raw.decode("utf-8-sig", errors="replace")

    rows = list(csv.DictReader(io.StringIO(text)))
    p_slugs = load_slugs(PLUGINS_TOP)
    t_slugs = load_slugs(THEMES_TOP)

    selected = [r for r in rows if selection_row(r, p_slugs, t_slugs)]
    print(f"total rows: {len(rows)}, selected: {len(selected)}")
    print("types:", Counter(r.get("software_type") for r in selected))

    entries = []
    skipped_cve, skipped_parse = 0, 0
    for row in selected:
        cve = (row.get("cve_id") or "").strip()
        if not cve.startswith("CVE-"):
            skipped_cve += 1
            continue
        intervals = [
            parse_interval(l) for l in (row.get("affected_versions") or "").splitlines()
        ]
        intervals = [i for i in intervals if i]
        if not intervals:
            skipped_parse += 1
            continue
        for interval in intervals:
            entries.append(
                {
                    "id": cve,
                    "tech": tech_for(row),
                    "title": title_for(row),
                    "severity": severity_for(row),
                    "cvss": float(row["cvss_score"])
                    if (row.get("cvss_score") or "").strip() not in ("", "0", "0.0")
                    else None,
                    "min-version": interval["min"] or None,
                    "max-version": interval["max"] or None,
                    "max-inclusive": True if interval["inclusive"] else None,
                    "reference": f"https://nvd.nist.gov/vuln/detail/{cve}",
                    "note": "Reference: Wordfence Intelligence",
                }
            )

    # Merge curated entries (dedupe by id+tech+min+max).
    seen = {
        (
            e["id"],
            e["tech"],
            e.get("min-version") or "",
            e.get("max-version") or "",
            bool(e.get("max-inclusive")),
        )
        for e in entries
    }
    merged = 0
    for keep in KEEP:
        key = (
            keep["id"],
            keep["tech"],
            keep.get("min-version") or "",
            keep.get("max-version") or "",
            bool(keep.get("max-inclusive")),
        )
        if key not in seen:
            entries.append(keep)
            seen.add(key)
            merged += 1

    entries.sort(
        key=lambda e: (
            e.get("tech", ""),
            e.get("id", ""),
            e.get("min-version") or "",
            e.get("max-version") or "",
        )
    )

    def esc(value: str) -> str:
        value = value.replace("\\", "\\\\").replace('"', '\\"')
        return value

    lines = [
        HEADER.format(
            today=__import__("datetime").date.today().isoformat(), count=len(entries)
        )
    ]
    for e in entries:
        lines.append(f"- id: {e['id']}")
        lines.append(f"  tech: {e['tech']}")
        lines.append(f'  title: "{esc(e["title"])}"')
        lines.append(f"  severity: {e['severity']}")
        if e.get("cvss") is not None:
            lines.append(f"  cvss: {e['cvss']}")
        if e.get("min-version"):
            lines.append(f'  min-version: "{e["min-version"]}"')
        if e.get("max-version"):
            lines.append(f'  max-version: "{e["max-version"]}"')
        if e.get("max-inclusive"):
            lines.append("  max-inclusive: true")
        lines.append(f"  reference: {e['reference']}")
        if e.get("note"):
            lines.append(f'  note: "{esc(e["note"])}"')
        lines.append("")

    DATASET.write_text("\n".join(lines).rstrip("\n") + "\n", encoding="utf-8")
    print(f"wrote {DATASET} with {len(entries)} entries ({merged} curated kept)")
    print(
        f"skipped rows without CVE id: {skipped_cve}, unparseable ranges: {skipped_parse}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
