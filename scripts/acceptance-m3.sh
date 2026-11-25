#!/usr/bin/env bash
# Milestone 3 acceptance against the real containers: read-only Gmail intake
# (against a fake Google container) and manual SMS entry through the dashboard.
#
# Usage: scripts/acceptance-m3.sh          (tears down afterwards)
#        KEEP=1 scripts/acceptance-m3.sh   (leaves the stack running)
set -uo pipefail
cd "$(dirname "$0")/.."

WORK="$PWD/.acceptance"
export COMPOSE_PROJECT_NAME=xpm-accept
export COMPOSE_FILE="docker-compose.yml:docker-compose.accept-m3.yml"
export XPM_HOST="${XPM_HOST:-10.0.0.125}"
export XPM_BIND_ADDR="${XPM_BIND_ADDR:-$XPM_HOST}"
export XPM_HTTPS_PORT=18443 XPM_HTTP_PORT=18080
export XPM_PUBLIC_ORIGIN="https://$XPM_HOST:$XPM_HTTPS_PORT"
export XPM_DATA_DIR="$WORK/data" XPM_SECRETS_DIR="$WORK/secrets"
export XPM_SAMPLE_DATA=false XPM_IMAGE_TAG=accept
ACCOUNT=owner@questalina.example
FAKE=http://127.0.0.1:4500
BASE="$XPM_PUBLIC_ORIGIN"
CA="$WORK/root.crt"
JAR="$WORK/cookies.txt"
ADMIN_PW="acceptance-$(head -c 12 /dev/urandom | base64 | tr -d '/+=')"
dc() { docker compose "$@"; }

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; [[ -n "${2:-}" ]] && printf '       %s\n' "$2"; }
check() { local name="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi; }
section() { printf '\n\033[1m%s\033[0m\n' "$1"; }

cleanup() {
  if [[ "${KEEP:-0}" == "1" ]]; then echo; echo "KEEP=1: stack left running at $BASE"; return; fi
  dc --profile tools down -v --remove-orphans >/dev/null 2>&1
  docker run --rm -v "$WORK:/w" alpine:3.20 rm -rf /w/data >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT

psql_q() { dc exec -T postgres psql -U xpm_owner -d xpm -tAc "$1"; }
curl_api() { curl -sS --cacert "$CA" -b "$JAR" -c "$JAR" -H "Origin: $BASE" "$@"; }
csrf() { jq -r .csrfToken "$WORK/session.json"; }
mail() { curl -sS -X POST -H 'content-type: application/json' -d "$1" "$FAKE/__test/messages" >/dev/null; }
wait_for() { # timeout command...
  local deadline=$((SECONDS + $1)); shift
  while ((SECONDS < deadline)); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
  return 1
}
email_count() { psql_q "SELECT count(*) FROM messages WHERE source = 'email'"; }
status() { psql_q "SELECT status FROM connections"; }
connect_gmail() { # → output file
  local out="$WORK/connect-$RANDOM.log"
  dc run --rm -T -p 127.0.0.1:8765:8765 intake gmail-connect --account "$ACCOUNT" >"$out" 2>&1 &
  local pid=$!
  wait_for 60 grep -q 'http://fake-google:4500/o/oauth2' "$out" || { echo "$out"; return 1; }
  local url
  url=$(grep -o 'http://fake-google:4500/o/oauth2[^ ]*' "$out" | head -1)
  # The laptop browser's role: open the consent URL; the redirect reaches the helper via the loopback port.
  curl -sS -L --connect-to fake-google:4500:127.0.0.1:4500 "$url" >/dev/null
  wait "$pid"
  echo "$out"
}

# ---------------------------------------------------------------------------
section "Fresh installation with intake service"
# ---------------------------------------------------------------------------
cleanup >/dev/null 2>&1
mkdir -p "$WORK"
scripts/init-secrets.sh "$XPM_SECRETS_DIR" >/dev/null
printf '{"installed":{"client_id":"accept.apps.googleusercontent.com","client_secret":"GOCSPX-acceptance-secret","project_id":"accept","auth_uri":"x","token_uri":"x","redirect_uris":["http://localhost"]}}' >"$XPM_SECRETS_DIR/gmail_reader_client.json"
dc --profile tools build >"$WORK/build.log" 2>&1 || { bad "image build" "see $WORK/build.log"; KEEP=1; exit 1; }
dc run --rm -T keytool generate --no-paper-test-only >/dev/null 2>&1
if dc up -d --wait --wait-timeout 180 >"$WORK/up.log" 2>&1; then ok "stack healthy (intake service included)"; else bad "stack failed to start" "see $WORK/up.log"; KEEP=1; exit 1; fi
check "migration 0004 applied" test "$(psql_q "SELECT name FROM schema_migrations ORDER BY version DESC LIMIT 1")" = "0004_gmail_sms_intake"
check "intake holds the Gmail client and key; server does not" bash -c "docker compose exec -T intake ls /run/secrets | grep -q gmail_reader_client && ! docker compose exec -T server ls /run/secrets | grep -qE 'gmail_reader_client|protected_master_key'"
check "gateway and runtimes cannot reach Google" bash -c "! docker compose exec -T gateway node -e \"fetch('http://fake-google:4500/__test/requests',{signal:AbortSignal.timeout(3000)}).then(()=>process.exit(0),()=>process.exit(1))\""

# ---------------------------------------------------------------------------
section "One-time sign-in (loopback port, as over an SSH tunnel)"
# ---------------------------------------------------------------------------
mail '{"from":"Old Customer <old.customer@example.net>","subject":"historical before activation","text":"old","internalDate":1700000000000}'
mail '{"from":"Recent <recent@example.net>","subject":"arrived before activation","text":"recent"}'
sleep 1
out=$(connect_gmail)
check "sign-in completes and stores the connection" grep -q 'Connected owner@questalina.example' "$out"
check "connection active" test "$(status)" = "active"
check "refresh token stored only encrypted" test "$(psql_q "SELECT count(*) FROM vault.connection_secrets WHERE position('refresh-'::bytea in ciphertext) > 0")" = "0"
check "helper port is not reachable from the LAN" bash -c "! timeout 2 bash -c '</dev/tcp/$XPM_HOST/8765' 2>/dev/null"

# ---------------------------------------------------------------------------
section "Incremental import"
# ---------------------------------------------------------------------------
mail '{"from":"Avery Lindqvist <avery.lindqvist@example.net>","to":"Questalina <info@questalina.example>","subject":"Export broken","text":"Hi team,\nExport is broken. Call me at 503-555-0161.\n\nThanks,\nAvery Lindqvist"}'
mail '{"from":"Vendor <billing@vendor.example>","subject":"Invoice","text":"Invoice attached"}'
mail '{"from":"Me <owner@questalina.example>","subject":"my sent mail","text":"x","labels":["SENT"]}'
check "new mail imported" wait_for 30 bash -c "[[ \$(docker compose exec -T postgres psql -U xpm_owner -d xpm -tAc \"SELECT count(*) FROM messages WHERE source='email'\") == 2 ]]"
check "historical and pre-activation mail excluded" test "$(psql_q "SELECT count(*) FROM messages WHERE subject ILIKE '%activation%'")" = "0"
check "sent mail not imported" test "$(psql_q "SELECT count(*) FROM messages WHERE subject = 'my sent mail'")" = "0"
check "info@ mail flagged as likely customer" test "$(psql_q "SELECT metadata->>'deliveredVia' FROM messages WHERE subject = 'Export broken'")" = "info@questalina.example"
check "customer identifiers redacted" test "$(psql_q "SELECT count(*) FROM messages WHERE body ~* 'avery|lindqvist|555-0161'")" = "0"

mail '{"from":"Kai Moreno <kai@example.net>","subject":"around restart","text":"x"}'
dc restart intake >/dev/null 2>&1
check "import continues after intake restart" wait_for 40 bash -c "[[ \$(docker compose exec -T postgres psql -U xpm_owner -d xpm -tAc \"SELECT count(*) FROM messages WHERE subject='around restart'\") == 1 ]]"

net="${COMPOSE_PROJECT_NAME}_google_egress"
docker network disconnect "$net" "$(dc ps -q intake)" >/dev/null 2>&1
mail '{"from":"Lena Fischer <lena@example.net>","subject":"sent during outage","text":"x"}'
check "outage shows as degraded" wait_for 40 bash -c "[[ \$(docker compose exec -T postgres psql -U xpm_owner -d xpm -tAc 'SELECT status FROM connections') == degraded ]]"
docker network connect "$net" "$(dc ps -q intake)" >/dev/null 2>&1
check "recovers after outage and imports missed mail" wait_for 40 bash -c "[[ \$(docker compose exec -T postgres psql -U xpm_owner -d xpm -tAc \"SELECT count(*) FROM messages WHERE subject='sent during outage'\") == 1 ]]"
check "connection active again" wait_for 20 bash -c "[[ \$(docker compose exec -T postgres psql -U xpm_owner -d xpm -tAc 'SELECT status FROM connections') == active ]]"
check "no message imported twice" test "$(psql_q "SELECT count(*) FROM (SELECT source_id FROM vault.originals GROUP BY source_id HAVING count(*) > 1) d")" = "0"

# ---------------------------------------------------------------------------
section "Revocation and reconnection"
# ---------------------------------------------------------------------------
curl -sS -X POST "$FAKE/__test/revoke" >/dev/null
mail '{"from":"Omar Haddad <omar@example.net>","subject":"sent while paused","text":"x"}'
check "revocation shows as paused with a reason" wait_for 30 bash -c "[[ \$(docker compose exec -T postgres psql -U xpm_owner -d xpm -tAc 'SELECT status FROM connections') == paused ]]"
dc cp caddy:/data/caddy/pki/authorities/local/root.crt "$CA" >/dev/null 2>&1
printf '%s' "$ADMIN_PW" | dc run --rm --no-deps -T server node apps/server/dist/cli.js admin create --username accept --password-stdin >/dev/null 2>&1
curl_api -o "$WORK/session.json" -H 'content-type: application/json' -d "{\"username\":\"accept\",\"password\":\"$ADMIN_PW\"}" "$BASE/api/auth/login" >/dev/null
check "dashboard shows the paused state" bash -c "curl -sS --cacert '$CA' -b '$JAR' '$BASE/api/connections' | jq -e '.connections[0].status == \"paused\" and (.connections[0].status_reason | test(\"Reconnect\"))'"
out=$(connect_gmail)
check "reconnect succeeds" grep -q 'Reconnected owner@questalina.example' "$out"
check "mail sent while paused imported after reconnect" wait_for 30 bash -c "[[ \$(docker compose exec -T postgres psql -U xpm_owner -d xpm -tAc \"SELECT count(*) FROM messages WHERE subject='sent while paused'\") == 1 ]]"

# ---------------------------------------------------------------------------
section "Read-only guarantee"
# ---------------------------------------------------------------------------
curl -sS "$FAKE/__test/requests" >"$WORK/google-requests.json"
check "every Gmail API request was a GET" test "$(jq '[.[] | select(.path | startswith("/gmail/")) | select(.method != "GET")] | length' "$WORK/google-requests.json")" = "0"
check "POSTs only to the OAuth token endpoint" test "$(jq '[.[] | select(.method == "POST") | select(.path != "/token") | select(.path | startswith("/__test") | not)] | length' "$WORK/google-requests.json")" = "0"
check "Gmail was actually read" test "$(jq '[.[] | select(.path | startswith("/gmail/"))] | length' "$WORK/google-requests.json")" -gt 5

# ---------------------------------------------------------------------------
section "Manual SMS through the dashboard"
# ---------------------------------------------------------------------------
sub=$(cat /proc/sys/kernel/random/uuid)
sms="{\"submissionId\":\"$sub\",\"from\":\"+1 (971) 555-0187\",\"fromName\":\"Rosalind Okonkwo\",\"text\":\"Hi, this is Rosalind. The app logs me out every hour.\",\"receivedAt\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"
post_sms() { curl_api -o /dev/null -w '%{http_code}' -H "x-csrf-token: $(csrf)" -H 'content-type: application/json' -d "$1" "$BASE/api/intake/sms"; }
check "SMS saved" test "$(post_sms "$sms")" = "201"
check "repeated submission not duplicated" test "$(post_sms "$sms")" = "200"
check "exactly one SMS stored" test "$(psql_q "SELECT count(*) FROM messages WHERE source = 'sms'")" = "1"
check "SMS redacted (name and number)" test "$(psql_q "SELECT count(*) FROM messages WHERE source = 'sms' AND body ~* 'rosalind|okonkwo|555-0187|9715550187'")" = "0"
check "SMS without CSRF token rejected" test "$(curl_api -o /dev/null -w '%{http_code}' -H 'content-type: application/json' -d "$sms" "$BASE/api/intake/sms")" = "403"

# ---------------------------------------------------------------------------
section "Leak scan"
# ---------------------------------------------------------------------------
psql_q "SELECT concat_ws(' ', subject, body, thread_key, sender_placeholder, metadata::text, held_reasons::text) FROM messages
        UNION ALL SELECT concat_ws(' ', account, status_reason, last_error) FROM connections
        UNION ALL SELECT concat_ws(' ', details::text, target) FROM audit_log" >"$WORK/db-dump.txt"
dc logs --no-color >"$WORK/all-logs.txt" 2>&1
cat "$WORK"/connect-*.log >>"$WORK/all-logs.txt"
leaks=$(grep -o -i -E 'avery|lindqvist|503-555-0161|rosalind|okonkwo|555-0187|refresh-[0-9a-f]{32}|access-[0-9a-f]{24}|GOCSPX-acceptance-secret' "$WORK/db-dump.txt" "$WORK/all-logs.txt" | sort -u)
if [[ -z "$leaks" ]]; then ok "no identifiers, tokens, or client secret in database or logs"; else bad "leaks found" "$(echo "$leaks" | head -5)"; fi

printf '\n\033[1mResult: %d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
