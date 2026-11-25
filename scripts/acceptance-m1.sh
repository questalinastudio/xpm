#!/usr/bin/env bash
# Milestone 1 end-to-end acceptance against the real containers.
#
# Brings up a disposable stack (project "xpm-accept", fresh data directory,
# HTTPS on port 18443) beside any real installation, then verifies:
#   fresh install + migrations, HTTPS via the local CA, login/logout, CSRF and
#   cross-origin rejection, duplicate-job suppression, abandoned-job recovery
#   after SIGKILL, persistence across restart and down/up, and that only the
#   dashboard is reachable from the LAN address.
#
# Usage: scripts/acceptance-m1.sh            (tears down afterwards)
#        KEEP=1 scripts/acceptance-m1.sh     (leaves the stack running)
set -uo pipefail
cd "$(dirname "$0")/.."

WORK="$PWD/.acceptance"
export COMPOSE_PROJECT_NAME=xpm-accept
export XPM_HOST="${XPM_HOST:-10.0.0.125}"
export XPM_BIND_ADDR="${XPM_BIND_ADDR:-$XPM_HOST}"
export XPM_HTTPS_PORT=18443 XPM_HTTP_PORT=18080
export XPM_PUBLIC_ORIGIN="https://$XPM_HOST:$XPM_HTTPS_PORT"
export XPM_DATA_DIR="$WORK/data" XPM_SECRETS_DIR="$WORK/secrets"
export XPM_SAMPLE_DATA=true XPM_JOB_LEASE_MS=4000 XPM_IMAGE_TAG=accept
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
  if [[ "${KEEP:-0}" == "1" ]]; then
    echo; echo "KEEP=1: stack left running at $BASE (project $COMPOSE_PROJECT_NAME)"
    return
  fi
  dc down --remove-orphans >/dev/null 2>&1
  # Postgres files belong to the container's uid; remove them from a container.
  docker run --rm -v "$WORK:/w" alpine:3.20 rm -rf /w/data >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT

psql_q() { dc exec -T postgres psql -U xpm_owner -d xpm -tAc "$1"; }
curl_api() { curl -sS --cacert "$CA" -b "$JAR" -c "$JAR" -H "Origin: $BASE" "$@"; }
status_of() { curl_api -o /dev/null -w '%{http_code}' "$@"; }
csrf() { jq -r .csrfToken "$WORK/session.json"; }
wait_job() { # id status timeout
  local deadline=$((SECONDS + $3))
  while ((SECONDS < deadline)); do
    [[ "$(psql_q "SELECT status FROM jobs WHERE id = '$1'")" == "$2" ]] && return 0
    sleep 1
  done
  return 1
}
login() {
  curl_api -o "$WORK/session.json" -w '%{http_code}' -H 'content-type: application/json' \
    -d "{\"username\":\"accept\",\"password\":\"$ADMIN_PW\"}" "$BASE/api/auth/login"
}

# ---------------------------------------------------------------------------
section "Fresh installation"
# ---------------------------------------------------------------------------
cleanup >/dev/null 2>&1
mkdir -p "$WORK"
scripts/init-secrets.sh "$XPM_SECRETS_DIR" >/dev/null
if dc up -d --build --wait --wait-timeout 180 >"$WORK/up.log" 2>&1; then ok "stack builds and becomes healthy"; else bad "stack failed to start" "see $WORK/up.log"; KEEP=1; exit 1; fi
check "migrations applied" test "$(psql_q "SELECT name FROM schema_migrations ORDER BY version DESC LIMIT 1")" = "0003_privacy_agents_traces"
check "migrate container exited successfully" test "$(docker inspect -f '{{.State.ExitCode}}' "$(dc ps -aq migrate)")" = "0"
dc cp caddy:/data/caddy/pki/authorities/local/root.crt "$CA" >/dev/null 2>&1
check "dashboard served over HTTPS with the local CA" test "$(curl -sS --cacert "$CA" -o /dev/null -w '%{http_code}' "$BASE/")" = "200"
check "HTTP redirects to HTTPS" bash -c "curl -sS -o /dev/null -w '%{http_code} %{redirect_url}' http://$XPM_HOST:$XPM_HTTP_PORT/ | grep -q '^30[18] https://'"
printf '%s' "$ADMIN_PW" | dc run --rm --no-deps -T server node apps/server/dist/cli.js admin create --username accept --password-stdin >/dev/null 2>&1
check "workstation CLI creates the administrator" test "$(psql_q "SELECT count(*) FROM admin_users WHERE username = 'accept'")" = "1"
check "password stored as an scrypt hash" bash -c "[[ \"\$(docker compose exec -T postgres psql -U xpm_owner -d xpm -tAc \"SELECT password_hash FROM admin_users\")\" == scrypt\\\$131072\\\$* ]]"

# ---------------------------------------------------------------------------
section "Authentication"
# ---------------------------------------------------------------------------
rm -f "$JAR"
check "API rejects unauthenticated requests" test "$(status_of "$BASE/api/jobs")" = "401"
check "wrong password rejected" test "$(curl_api -o /dev/null -w '%{http_code}' -H 'content-type: application/json' -d '{"username":"accept","password":"wrong-password"}' "$BASE/api/auth/login")" = "401"
check "login succeeds" test "$(login)" = "200"
check "session cookie is Secure + HttpOnly + __Host-" grep -q $'^#HttpOnly_'"$XPM_HOST"$'\tFALSE\t/\tTRUE\t.*__Host-xpm_session' "$JAR"
check "authenticated API access" test "$(status_of "$BASE/api/system/health")" = "200"
check "forged action without CSRF token rejected" test "$(status_of -X POST -H 'content-type: application/json' -d '{"kind":"echo"}' "$BASE/api/demo/jobs")" = "403"
check "cross-origin action rejected" test "$(curl -sS --cacert "$CA" -b "$JAR" -o /dev/null -w '%{http_code}' -H 'Origin: https://evil.example' -H "x-csrf-token: $(csrf)" -H 'content-type: application/json' -d '{"kind":"echo"}' -X POST "$BASE/api/demo/jobs")" = "403"
check "worker is heartbeating" test "$(curl_api "$BASE/api/system/health" | jq '[.workers[] | select(.healthy)] | length')" -ge 1

# ---------------------------------------------------------------------------
section "Durable jobs"
# ---------------------------------------------------------------------------
post_demo() { curl_api -H "x-csrf-token: $(csrf)" -H 'content-type: application/json' -d "$1" "$BASE/api/demo/jobs"; }
a=$(post_demo '{"kind":"echo","key":"dup-check"}' | jq -r .job.id)
b=$(post_demo '{"kind":"echo","key":"dup-check"}' | jq -r .job.id)
check "duplicate requests return the same job" test -n "$a" -a "$a" = "$b"
check "duplicate suppressed in the database" test "$(psql_q "SELECT count(*) FROM jobs WHERE idempotency_key = 'demo:dup-check'")" = "1"
check "echo job completes" wait_job "$a" succeeded 20
flaky=$(post_demo '{"kind":"fail","key":"flaky"}' | jq -r .job.id)
perm=$(post_demo '{"kind":"fail_permanent","key":"perm"}' | jq -r .job.id)
check "permanent failure stops without retry" wait_job "$perm" failed 20
check "permanent failure used one attempt" test "$(psql_q "SELECT attempts FROM jobs WHERE id = '$perm'")" = "1"
check "transient failures retried until success" wait_job "$flaky" succeeded 60
check "each retry recorded as a distinct attempt" test "$(psql_q "SELECT string_agg(status, ',' ORDER BY fence) FROM job_attempts WHERE job_id = '$flaky'")" = "failed,failed,succeeded"
# Backoff is 5s then 10s; allow scheduling slack.
check "retries honoured exponential backoff" test "$(psql_q "SELECT bool_and(gap >= interval '4 seconds') FROM (SELECT started_at - lag(finished_at) OVER (ORDER BY fence) AS gap FROM job_attempts WHERE job_id = '$flaky') g WHERE gap IS NOT NULL")" = "t"

# Abandoned-job recovery: SIGKILL the worker mid-job, restart it, and expect
# the job to be reclaimed after lease expiry with a distinct second attempt.
slow=$(post_demo '{"kind":"sleep","key":"crash-me","seconds":6}' | jq -r .job.id)
check "long job starts" wait_job "$slow" running 20
docker kill -s KILL "$(dc ps -q worker)" >/dev/null
dc up -d worker >/dev/null 2>&1
check "abandoned job reclaimed and completed after worker crash" wait_job "$slow" succeeded 40
check "crashed attempt preserved, retry recorded separately" test "$(psql_q "SELECT string_agg(status, ',' ORDER BY fence) FROM job_attempts WHERE job_id = '$slow'")" = "abandoned,succeeded"

# ---------------------------------------------------------------------------
section "Persistence"
# ---------------------------------------------------------------------------
psql_q "INSERT INTO checkpoints (key, value) VALUES ('acceptance:marker', '{\"v\":1}')" >/dev/null
jobs_before=$(psql_q "SELECT count(*) FROM jobs")
dc restart >/dev/null 2>&1 && dc up -d --wait --wait-timeout 120 >/dev/null 2>&1
check "data survives container restart" test "$(psql_q "SELECT value->>'v' FROM checkpoints WHERE key = 'acceptance:marker'")" = "1"
check "session survives container restart" test "$(status_of "$BASE/api/jobs")" = "200"
dc down >/dev/null 2>&1 && dc up -d --wait --wait-timeout 120 >/dev/null 2>&1
check "data survives down/up (container recreation)" test "$(psql_q "SELECT count(*) FROM jobs")" = "$jobs_before"
check "administrator survives down/up" test "$(psql_q "SELECT count(*) FROM admin_users")" = "1"
check "migrations idempotent on restart" test "$(docker inspect -f '{{.State.ExitCode}}' "$(dc ps -aq migrate)")" = "0"
check "services restart automatically (restart policy)" test "$(docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' "$(dc ps -q postgres)")" = "unless-stopped"

# ---------------------------------------------------------------------------
section "Network exposure"
# ---------------------------------------------------------------------------
published=$(for c in $(dc ps -q); do docker inspect -f '{{.Name}}{{range $p, $b := .NetworkSettings.Ports}}{{range $b}} {{$p}}={{.HostIp}}:{{.HostPort}}{{end}}{{end}}' "$c"; done)
echo "$published" | sed 's/^/       /'
check "only caddy publishes ports" bash -c "echo '$published' | grep -v '^/xpm-accept-caddy' | grep -q '=' && exit 1 || exit 0"
check "caddy binds only the LAN address" bash -c "echo '$published' | grep '^/xpm-accept-caddy' | tr ' ' '\n' | grep '=' | grep -qv '=$XPM_BIND_ADDR:' && exit 1 || exit 0"
tcp_open() { timeout 2 bash -c "</dev/tcp/$1/$2" 2>/dev/null; }
check "dashboard port reachable on LAN address" tcp_open "$XPM_HOST" "$XPM_HTTPS_PORT"
for port in 5432 3000; do
  check "port $port closed on LAN address" bash -c "! timeout 2 bash -c '</dev/tcp/$XPM_HOST/$port' 2>/dev/null"
done
check "database container has no published ports" test -z "$(docker port "$(dc ps -q postgres)")"
check "worker container has no published ports" test -z "$(docker port "$(dc ps -q worker)")"
check "worker has no internet egress (internal network)" dc exec -T worker node -e "fetch('https://example.com',{signal:AbortSignal.timeout(4000)}).then(()=>process.exit(1),()=>process.exit(0))"
check "server reachable only via caddy (no host port)" test -z "$(docker port "$(dc ps -q server)")"

# ---------------------------------------------------------------------------
section "Logout"
# ---------------------------------------------------------------------------
old_jar=$(cat "$JAR")
check "logout succeeds" test "$(status_of -X POST -H "x-csrf-token: $(csrf)" "$BASE/api/auth/logout")" = "200"
echo "$old_jar" >"$JAR.old"
check "old session cookie no longer works" test "$(curl -sS --cacert "$CA" -b "$JAR.old" -o /dev/null -w '%{http_code}' "$BASE/api/jobs")" = "401"

printf '\n\033[1mResult: %d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
