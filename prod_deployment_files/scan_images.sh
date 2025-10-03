#!/usr/bin/env bash
set -euo pipefail

# Inputs
FILES_OR_DIRS=("$@")
OUTDIR="${OUTDIR:-trivy-reports}"
EXIT_ON_VULN="${EXIT_ON_VULN:-0}"          # 1 => overall exit 1 if any image fails
TRIVY_IMAGE="${TRIVY_IMAGE:-aquasec/trivy:latest}"

mkdir -p "$OUTDIR" .cache

# 1) Get images
EXTRACTOR="${EXTRACTOR:-./extract_images.sh}"
if ! [ -x "$EXTRACTOR" ]; then
  echo "Extractor not found or not executable at: $EXTRACTOR" >&2
  exit 2
fi
mapfile -t IMAGES < <("$EXTRACTOR" "${FILES_OR_DIRS[@]}")
if ((${#IMAGES[@]}==0)); then
  echo "No images found." >&2
  exit 0
fi



# 2) Per-image scan
scan_one() {
  local img="$1"
  local safe out rc
  safe="$(echo "$img" | sed 's#[^A-Za-z0-9._-]#_#g')"
  out="${OUTDIR}/${safe}.json"

  # Build creds inside the worker (arrays don’t export across env)
  local DOCKER_CREDS=()
  if [ -f "$HOME/.docker/config.json" ]; then
    DOCKER_CREDS=(-v "$HOME/.docker":/root/.docker:ro -e DOCKER_CONFIG=/root/.docker)
  fi

  local IGNOREFILE="$PWD/.trivyignore.yml"

  echo "🔎 Scanning ${img} -> ${out}"
  set +e
    trivy image "$img" \
      --cache-dir "/home/jenkins/agent/caches/.trivy_cache" \
      --severity HIGH,CRITICAL \
      --ignore-unfixed \
      --ignorefile "$PWD/.trivyignore.yml" \
      --scanners vuln \
      --format json \
      --output "$out"

  rc=$?
  set -e

  echo "$rc" > "${out}.rc"
}

export -f scan_one
export OUTDIR SEVERITY IGNORE_UNFIXED TRIVY_IMAGE

for img in "${IMAGES[@]}"; do
  if [[ "$img" == "git.example.com/jenkins/bulkintel"* || "$img" == "---" ]]; then
    # Skip this element (don't add it back to the new array)
    continue
  fi
  NEW_IMAGES+=("$img")
done

IMAGES=("${NEW_IMAGES[@]}")

# 3) Run scans
for img in "${IMAGES[@]}"; do scan_one "$img"; done

# 4) Aggregate exit status
overall=0
if [ "$EXIT_ON_VULN" = "1" ]; then
  shopt -s nullglob
  for f in "$OUTDIR"/*.rc; do
    rc=$(<"$f")
    (( rc != 0 )) && overall=1
    rm -f "$f"
  done
else
  rm -f "$OUTDIR"/*.rc 2>/dev/null || true
fi

echo "Reports in $OUTDIR/"
exit $overall