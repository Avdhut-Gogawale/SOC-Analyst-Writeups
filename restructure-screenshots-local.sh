#!/usr/bin/env bash
# Run from inside D:\SOC-Analyst-Writeups\Investigations (the folder containing README.md, Brute-Force, Phishing...)
# Works with or without git.
set -e
[ -f README.md ] && [ -d Brute-Force ] || { echo "Run this from the folder that contains README.md and Brute-Force/"; exit 1; }

mkdir -p Screenshots

for d in */soc*-screenshots; do
  [ -d "$d" ] || continue
  id=$(basename "$d" | sed 's/-screenshots//')
  mv "$d" "Screenshots/$id"
  sed -i "s#(${id}-screenshots/#(../Screenshots/${id}/#g" "$(dirname "$d")"/*.md
done

if [ -d Practice/SOC-Sim-006-Phishing-AsyncRAT/screenshots ]; then
  mv Practice/SOC-Sim-006-Phishing-AsyncRAT/screenshots Screenshots/SOC-Sim-006
  sed -i 's#(screenshots/#(../../Screenshots/SOC-Sim-006/#g' Practice/SOC-Sim-006-Phishing-AsyncRAT/README.md
fi

sed -i 's#enrichment results in screenshots/ folder#enrichment results in the top-level `Screenshots/` folder (`Screenshots/SOC-Sim-006/`)#' Practice/README.md
sed -i 's#Each investigation folder contains a full markdown writeup and a `screenshots/` subfolder with the supporting evidence referenced inline in the report.#Each category folder contains the full markdown writeups. All supporting evidence screenshots live in the common top-level `Screenshots/` folder, with one subfolder per alert (e.g. `Screenshots/soc176/`), referenced inline in each report.#' README.md

# Verify every image link
bad=0
for f in $(find . -name "*.md"); do
  dir=$(dirname "$f")
  for p in $(grep -oE "\]\([^)]*\.png\)" "$f" | sed -E 's/^\]\(|\)$//g'); do
    [ -f "$dir/$p" ] || { echo "BROKEN: $f -> $p"; bad=1; }
  done
done
[ $bad -eq 0 ] && echo "All image links OK."
