#!/usr/bin/env bash
# Post-boot / routine health check for the running installation.
# Usage: scripts/check-health.sh   (reads XPM_HOST / XPM_PUBLIC_ORIGIN from .env)
set -uo pipefail
cd "$(dirname "$0")/.."
set -a; [[ -f .env ]] && . ./.env; set +a
ORIGIN="${XPM_PUBLIC_ORIGIN:-https://${XPM_HOST:?XPM_HOST not set}}"
CA="${XPM_CA_FILE:-./questalina-desk-root.crt}"

FAIL=0
ok() { printf '  \033[32mOK\033[0m   %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; [[ -n "${2:-}" ]] && printf '       → %s\n' "$2"; }

for svc in postgres server worker gateway pm-runtime dev-runtime caddy; do
  state=$(docker compose ps -a --format '{{.State}}' "$svc" 2>/dev/null)
  [[ "$state" == "running" ]] && ok "$svc running" || bad "$svc is ${state:-missing}" "docker compose up -d --force-recreate $svc"
done
code=$(docker inspect -f '{{.State.ExitCode}}' "$(docker compose ps -aq migrate)" 2>/dev/null)
[[ "$code" == "0" ]] && ok "migrations applied" || bad "migrate exited with ${code:-?}" "docker compose logs migrate"

ports=$(docker port "$(docker compose ps -q caddy 2>/dev/null)" 2>/dev/null)
if grep -q ":443$" <<<"$ports"; then ok "caddy published on $(grep 443/tcp <<<"$ports" | head -1 | awk '{print $3}')"
else bad "caddy has no published ports (boot-time bind race?)" "docker compose up -d --force-recreate caddy; see docs/setup.md 'Boot-time network binding'"; fi

if [[ -f "$CA" ]]; then
  code=$(curl -sS --cacert "$CA" -o /dev/null -w '%{http_code}' --max-time 5 "$ORIGIN/" 2>/dev/null)
  [[ "$code" == "200" ]] && ok "dashboard reachable at $ORIGIN (certificate valid)" || bad "dashboard returned ${code:-no response}"
else
  bad "CA file $CA not found; cannot verify HTTPS" "docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt $CA"
fi

fresh=$(docker compose exec -T postgres psql -U xpm_owner -d xpm -tAc \
  "SELECT count(*) FROM worker_heartbeats WHERE last_seen_at > now() - interval '30 seconds'" 2>/dev/null)
[[ "${fresh:-0}" -ge 1 ]] && ok "worker heartbeat fresh ($fresh)" || bad "no fresh worker heartbeat" "docker compose logs worker"

if [[ -f "${XPM_SECRETS_DIR:-./secrets}/protected_master_key" ]]; then
  fp=$(docker compose run --rm -T keytool status 2>/dev/null | grep -o 'Fingerprint: [0-9a-f]*' | awk '{print $2}')
  [[ -n "$fp" ]] && ok "master key present (fingerprint $fp)" || bad "master key unreadable" "docker compose run --rm keytool status"
else
  bad "no master key" "docker compose run --rm keytool generate"
fi

[[ "$(sysctl -n net.ipv4.ip_nonlocal_bind 2>/dev/null)" == "1" ]] && ok "boot-time bind protection enabled" \
  || bad "net.ipv4.ip_nonlocal_bind is 0; caddy may fail after reboot" "see docs/setup.md 'Boot-time network binding'"

echo
((FAIL == 0)) && echo "All checks passed." || echo "$FAIL check(s) failed."
exit $((FAIL > 0))
