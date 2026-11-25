#!/usr/bin/env bash
# Milestone 2 acceptance against the real containers: privacy, agent isolation,
# and trace capture, using the simulated (injection-obedient) provider.
#
# Usage: scripts/acceptance-m2.sh          (tears down afterwards)
#        KEEP=1 scripts/acceptance-m2.sh   (leaves the stack running)
set -uo pipefail
cd "$(dirname "$0")/.."

WORK="$PWD/.acceptance"
export COMPOSE_PROJECT_NAME=xpm-accept
export XPM_HOST="${XPM_HOST:-10.0.0.125}"
export XPM_BIND_ADDR="${XPM_BIND_ADDR:-$XPM_HOST}"
export XPM_HTTPS_PORT=18443 XPM_HTTP_PORT=18080
export XPM_PUBLIC_ORIGIN="https://$XPM_HOST:$XPM_HTTPS_PORT"
export XPM_DATA_DIR="$WORK/data" XPM_SECRETS_DIR="$WORK/secrets"
export XPM_SAMPLE_DATA=true XPM_IMAGE_TAG=accept
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
# Run a Node snippet inside a service container; exit code is the result.
in_svc() { local svc="$1"; shift; dc exec -T "$svc" node -e "$1"; }
tcp_from() { # service host port → exit 0 if a TCP connection succeeds
  in_svc "$1" "const s=require('net').connect({host:'$2',port:$3,timeout:3000});s.on('connect',()=>process.exit(0));s.on('error',()=>process.exit(1));s.on('timeout',()=>process.exit(1));"
}
http_from() { in_svc "$1" "fetch('$2',{signal:AbortSignal.timeout(4000)}).then(()=>process.exit(0),()=>process.exit(1))"; }
wait_job_type() { # type status count timeout
  local deadline=$((SECONDS + $4))
  while ((SECONDS < deadline)); do
    [[ "$(psql_q "SELECT count(*) FROM jobs WHERE type = '$1' AND status = '$2'")" -ge "$3" ]] && return 0
    sleep 1
  done
  return 1
}

# ---------------------------------------------------------------------------
section "Fresh installation with Milestone 2 services"
# ---------------------------------------------------------------------------
cleanup >/dev/null 2>&1
mkdir -p "$WORK"
scripts/init-secrets.sh "$XPM_SECRETS_DIR" >/dev/null
dc --profile tools build >"$WORK/build.log" 2>&1 || { bad "image build" "see $WORK/build.log"; KEEP=1; exit 1; }
dc run --rm -T keytool generate --no-paper-test-only >/dev/null 2>&1
check "master key created (test-only, no paper)" test -s "$XPM_SECRETS_DIR/protected_master_key"
if dc up -d --wait --wait-timeout 180 >"$WORK/up.log" 2>&1; then ok "stack healthy (gateway, pm-runtime, dev-runtime included)"; else bad "stack failed to start" "see $WORK/up.log"; KEEP=1; exit 1; fi
check "latest migration applied" test "$(psql_q "SELECT name FROM schema_migrations ORDER BY version DESC LIMIT 1")" = "0004_gmail_sms_intake"
dc run --rm -T reposync synthetic >"$WORK/reposync.log" 2>&1
check "sanitized snapshot built" grep -q '"held":1' "$WORK/reposync.log"
dc restart gateway >/dev/null 2>&1 && dc up -d --wait --wait-timeout 60 >/dev/null 2>&1
dc run --rm -T intake ingest-synthetic >"$WORK/intake.log" 2>&1
check "synthetic messages ingested" test "$(psql_q "SELECT count(*) FROM messages")" = "6"
check "ambiguous message held for review" test "$(psql_q "SELECT count(*) FROM messages WHERE status = 'held_for_review'")" = "1"
dc cp caddy:/data/caddy/pki/authorities/local/root.crt "$CA" >/dev/null 2>&1
printf '%s' "$ADMIN_PW" | dc run --rm --no-deps -T server node apps/server/dist/cli.js admin create --username accept --password-stdin >/dev/null 2>&1
curl_api -o "$WORK/session.json" -H 'content-type: application/json' -d "{\"username\":\"accept\",\"password\":\"$ADMIN_PW\"}" "$BASE/api/auth/login" >/dev/null

# ---------------------------------------------------------------------------
section "Agent isolation (network, secrets, filesystem)"
# ---------------------------------------------------------------------------
for rt in pm-runtime dev-runtime; do
  check "$rt reaches the gateway" http_from "$rt" "http://gateway:4100/healthz"
  check "$rt cannot reach PostgreSQL" bash -c "! docker compose exec -T $rt node -e \"const s=require('net').connect({host:'postgres',port:5432,timeout:3000});s.on('connect',()=>process.exit(0));s.on('error',()=>process.exit(1));s.on('timeout',()=>process.exit(1));\""
  check "$rt cannot reach the dashboard server" bash -c "! docker compose exec -T $rt node -e \"fetch('http://server:3000/healthz',{signal:AbortSignal.timeout(3000)}).then(()=>process.exit(0),()=>process.exit(1))\""
  check "$rt cannot reach the internet" bash -c "! docker compose exec -T $rt node -e \"fetch('https://example.com',{signal:AbortSignal.timeout(4000)}).then(()=>process.exit(0),()=>process.exit(1))\""
  check "$rt filesystem is read-only" bash -c "! docker compose exec -T $rt sh -c 'touch /app/x' 2>/dev/null"
  check "$rt holds no source snapshot" test -z "$(dc exec -T "$rt" ls -A /snapshots 2>/dev/null)"
done
check "pm-runtime holds only its own token" test "$(dc exec -T pm-runtime ls /run/secrets | tr '\n' ' ')" = "pm_runtime_token "
check "dev-runtime holds only its own token" test "$(dc exec -T dev-runtime ls /run/secrets | tr '\n' ' ')" = "dev_runtime_token "
check "pm-runtime cannot reach dev-runtime's network" bash -c "! docker compose exec -T pm-runtime node -e \"require('dns').lookup('dev-runtime',e=>process.exit(e?1:0))\""
check "gateway cannot reach the internet" bash -c "! docker compose exec -T gateway node -e \"fetch('https://example.com',{signal:AbortSignal.timeout(4000)}).then(()=>process.exit(0),()=>process.exit(1))\""
check "gateway snapshot mount is read-only" bash -c "! docker compose exec -T gateway sh -c 'touch /snapshots/current/x' 2>/dev/null"
check "gateway holds no master key or vault password" bash -c "! docker compose exec -T gateway ls /run/secrets | grep -qE 'protected_master_key|pg_vault|pg_owner'"
check "worker holds no master key" bash -c "! docker compose exec -T worker ls /run/secrets | grep -q protected_master_key"

# ---------------------------------------------------------------------------
section "Agent turns through the dashboard (simulated obedient model)"
# ---------------------------------------------------------------------------
post_turn() { curl_api -o /dev/null -w '%{http_code}' -H "x-csrf-token: $(csrf)" -H 'content-type: application/json' -d "$1" "$BASE/api/demo/agent-turn"; }
check "queue PM turn on injected SMS" test "$(post_turn '{"role":"pm","caseReference":"SAMPLE-005"}')" = "201"
check "queue dev turn on CSV export" test "$(post_turn '{"role":"dev","caseReference":"SAMPLE-002"}')" = "201"
check "both turns complete" wait_job_type agent.turn succeeded 2 60
check "PM: injected email.send denied" test "$(psql_q "SELECT count(*) FROM tool_calls WHERE agent_role='pm' AND tool='email.send' AND authz='denied'")" -ge 1
check "PM: injected source.read denied for role" test "$(psql_q "SELECT count(*) FROM tool_calls WHERE agent_role='pm' AND tool='source.read' AND denial_reason='not_permitted_for_role'")" -ge 1
check "dev: case brief tool used (source reads covered by integration tests)" test "$(psql_q "SELECT count(*) FROM tool_calls WHERE agent_role='dev' AND tool='case.brief' AND status='succeeded'")" -ge 1
check "no sending job exists anywhere" test "$(psql_q "SELECT count(*) FROM jobs WHERE type ILIKE '%send%' OR type ILIKE '%mail%'")" = "0"
check "every model call traced with request and response" test "$(psql_q "SELECT count(*) FROM llm_calls WHERE status='succeeded' AND (request IS NULL OR response IS NULL OR latency_ms IS NULL)")" = "0"
check "dev traces marked technical, PM traces product" test "$(psql_q "SELECT count(DISTINCT agent_role || sensitivity) FROM llm_calls")" = "2"
check "dashboard API shows turn detail" bash -c "id=\$(curl -sS --cacert '$CA' -b '$JAR' '$BASE/api/agent/turns' | jq -r '.turns[0].id'); curl -sS --cacert '$CA' -b '$JAR' \"$BASE/api/agent/turns/\$id\" | jq -e '.llmCalls | length > 0'"
check "dashboard API never exposes ticket hashes" bash -c "! curl -sS --cacert '$CA' -b '$JAR' \"$BASE/api/agent/turns/\$(curl -sS --cacert '$CA' -b '$JAR' '$BASE/api/agent/turns' | jq -r '.turns[0].id')\" | grep -q ticket_hash"

# ---------------------------------------------------------------------------
section "Leak scan: database and every container log"
# ---------------------------------------------------------------------------
dc run --rm -T --entrypoint node reposync -e "import('/app/packages/privacy/dist/index.js').then(m=>console.log(m.CANARIES.join('\n')))" >"$WORK/canaries.txt" 2>/dev/null
check "canary list loaded" test "$(wc -l <"$WORK/canaries.txt")" -ge 30
psql_q "SELECT concat_ws(' ', request::text, response::text, tool_requests::text, error) FROM llm_calls
        UNION ALL SELECT concat_ws(' ', arguments::text, result::text, error) FROM tool_calls
        UNION ALL SELECT concat_ws(' ', input::text, output::text, decision_summary::text, error) FROM agent_turns
        UNION ALL SELECT concat_ws(' ', subject, body, redaction_summary::text, held_reasons::text) FROM messages
        UNION ALL SELECT concat_ws(' ', payload::text, result::text, last_error) FROM jobs
        UNION ALL SELECT concat_ws(' ', details::text, target) FROM audit_log" >"$WORK/db-dump.txt"
dc --profile tools logs --no-color >"$WORK/all-logs.txt" 2>&1
cat "$WORK"/intake.log "$WORK"/reposync.log >>"$WORK/all-logs.txt"
check "database dump is non-trivial" test "$(wc -c <"$WORK/db-dump.txt")" -gt 20000
check "logs are non-trivial" test "$(wc -l <"$WORK/all-logs.txt")" -gt 50
leaks=$(grep -o -i -F -f "$WORK/canaries.txt" "$WORK/db-dump.txt" "$WORK/all-logs.txt" | sort -u)
if [[ -z "$leaks" ]]; then ok "no seeded identifier or secret in database or logs"; else bad "leaked canaries" "$(echo "$leaks" | head -5)"; fi
secret_values=$(cat "$XPM_SECRETS_DIR"/pg_* "$XPM_SECRETS_DIR"/*_token)
leaked_secrets=$(grep -c -F -f <(echo "$secret_values") "$WORK/db-dump.txt" "$WORK/all-logs.txt" | awk -F: '{s+=$2} END {print s}')
check "no database password or runtime token in database or logs" test "$leaked_secrets" = "0"
check "vault ciphertext holds no plaintext" test "$(psql_q "SELECT count(*) FROM vault.originals WHERE position('Marisol'::bytea in ciphertext) > 0")" = "0"

printf '\n\033[1mResult: %d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
