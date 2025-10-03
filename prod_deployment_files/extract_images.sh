#!/usr/bin/env bash
set -euo pipefail

if ! command -v yq >/dev/null 2>&1; then
  echo "Please install mikefarah/yq v4 (https://github.com/mikefarah/yq)" >&2
  exit 1
fi

# If no args: read from stdin; else read listed files
if [ "$#" -eq 0 ]; then
  yq ea -r '
    .. | select(type == "!!map") |
    (.containers[]?.image, .initContainers[]?.image, .ephemeralContainers[]?.image)
  ' - | sed '/^null$/d;/^\s*$/d' | sort -u
else
  yq ea -r '
    .. | select(type == "!!map") |
    (.containers[]?.image, .initContainers[]?.image, .ephemeralContainers[]?.image)
  ' "$@" | sed '/^null$/d;/^\s*$/d' | sort -u
fi
