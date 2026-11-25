#!/usr/bin/env bash
# Generate database passwords into a private directory. Never overwrites.
# Usage: scripts/init-secrets.sh [secrets-dir]
set -euo pipefail
dir="${1:-${XPM_SECRETS_DIR:-./secrets}}"
mkdir -p "$dir"
chmod 700 "$dir"
for name in pg_owner_password pg_web_password pg_worker_password pg_vault_password pg_gateway_password \
            pg_pm_tools_password pg_dev_tools_password pm_runtime_token dev_runtime_token; do
  f="$dir/$name"
  if [[ -s "$f" ]]; then
    echo "exists:  $f"
    continue
  fi
  (umask 022; head -c 32 /dev/urandom | base64 | tr -d '/+=\n' > "$f")
  echo "created: $f"
done
# Files are world-readable *inside* a 700 directory so the postgres (uid 999)
# and node (uid 1000) container users can read their bind-mounted secrets.
