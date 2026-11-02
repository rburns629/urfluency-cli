#!/bin/sh
# Prints one release's notes from RELEASE_NOTES.md, without its heading:
# scripts/release-notes.sh vX.Y.Z [FILE] > notes.md
# Fails when the release has no section, its heading has no date, or a change
# does not start with New:, Improved:, Fixed:, or Security:.
set -eu
tag=$1
file=${2:-RELEASE_NOTES.md}
# A plain assignment, so a failing awk stops the script under set -e; in a
# pipeline its status would be lost.
notes=$(awk -v tag="$tag" '
  BEGIN { pat = "^## " tag " \\([0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]\\)$" }
  /^## / { if (found) exit; if ($0 ~ pat) { found = 1; next } }
  found {
    if ($0 ~ /^- / && $0 !~ /^- (New|Improved|Fixed|Security): ./) { print "unlabelled change: " $0 > "/dev/stderr"; bad = 1 }
    if ($0 ~ /^- /) changes++
    print
  }
  END {
    if (!found) { print "RELEASE_NOTES.md has no \"## " tag " (YYYY-MM-DD)\" section" > "/dev/stderr"; exit 1 }
    if (!changes) { print tag " lists no changes" > "/dev/stderr"; exit 1 }
    if (bad) exit 1
  }
' "$file")
printf '%s\n' "$notes" | sed -e '/./,$!d'
