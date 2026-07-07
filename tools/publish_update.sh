#!/usr/bin/env bash
# Manually publish catalog.json + update-manifest.json (and optionally a new APK)
# to the GitHub release that `releases/latest/download/...` resolves to.
#
# Usage:
#   ./tools/publish_update.sh                # publish data files only
#   ./tools/publish_update.sh path/to.apk    # also upload a signed release APK
set -euo pipefail
cd "$(dirname "$0")/.."

tag="$(gh release list --limit 1 --json tagName --jq '.[0].tagName')"
if [ -z "$tag" ]; then
  echo "No release found; create one first (gh release create <tag>)." >&2
  exit 1
fi

echo "Publishing to release $tag"
gh release upload "$tag" catalog.json update-manifest.json --clobber

if [ $# -ge 1 ]; then
  apk="$1"
  expected="$(python3 -c "import json;print(json.load(open('update-manifest.json'))['app'].get('sha256',''))")"
  actual="$(shasum -a 256 "$apk" | cut -d' ' -f1)"
  if [ -z "$expected" ]; then
    echo "Manifest has no app.sha256 — run build_intel_feeds.py with --apk first." >&2
    exit 1
  fi
  if [ "$expected" != "$actual" ]; then
    echo "APK checksum mismatch: manifest=$expected file=$actual" >&2
    exit 1
  fi
  gh release upload "$tag" "$apk#stackradar-release-demo-signed.apk" --clobber
  echo "APK uploaded (checksum verified against manifest)."
fi

echo "Done. Apps verify database sha256 before applying this update."
