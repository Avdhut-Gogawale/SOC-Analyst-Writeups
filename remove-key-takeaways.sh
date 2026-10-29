#!/usr/bin/env bash
# Run from the folder containing README.md (D:\SOC-Analyst-Writeups\Investigations).
# Removes the final "## Key Takeaways..." section (and the "---" line above it) from every writeup,
# and removes item 9 from the methodology list in README.md. Safe to run twice.
set -e
[ -f README.md ] && [ -d Brute-Force ] || { echo "Run from the folder that contains README.md and Brute-Force/"; exit 1; }

count=0
for f in $(grep -rlE '^## Key Takeaways' --include=*.md . | grep -v '^./README.md$'); do
  n=$(grep -nE '^## Key Takeaways' "$f" | head -1 | cut -d: -f1)
  # refuse if another H2 follows (would delete real content)
  if awk -v n="$n" 'NR>n && /^## /{found=1} END{exit !found}' "$f"; then
    echo "SKIPPED (another section follows Key Takeaways): $f"; continue
  fi
  cut_at=$n
  prev=$(sed -n "$((n-2))p" "$f")
  [ "$prev" = "---" ] && cut_at=$((n-2))
  head -n $((cut_at-1)) "$f" | sed -e :a -e '/^\n*$/{$d;N;ba' -e '}' > "$f.tmp"
  mv "$f.tmp" "$f"
  echo "cleaned: $f"; count=$((count+1))
done

sed -i '/^9\. \*\*Key Takeaways\*\*/d' README.md
echo "Sections removed: $count"
echo "Remaining mentions of 'Key Takeaways':"; grep -rn "Key Takeaways" --include=*.md . || echo "  none"
