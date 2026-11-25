# Questalina Desk: setup and operations

Status: Milestone 1 (local foundation, authentication, durable jobs).

## What runs

| Service    | Purpose                                   | Network            | Published |
|------------|-------------------------------------------|--------------------|-----------|
| `caddy`    | HTTPS with a local certificate authority  | `edge`             | `XPM_BIND_ADDR:443`, `:80` (redirect) |
| `server`   | Dashboard and authenticated API           | `edge`, `internal` | no |
| `worker`   | Durable job worker                        | `internal`         | no |
| `migrate`  | One-shot schema migration and role setup  | `internal`         | no |
| `postgres` | PostgreSQL 17                             | `internal`         | no |

`internal` is a Docker `internal: true` network with no route to the internet.
PostgreSQL, the server and the worker publish no host ports; only Caddy does,
and only on the reserved LAN address.

Each service connects to PostgreSQL with its own role:

| Role         | Used by | Access |
|--------------|---------|--------|
| `xpm_owner`  | `migrate` | Schema owner. Never used by long-running services. |
| `xpm_web`    | `server`, admin CLI | Accounts, sessions, jobs, cases, audit. |
| `xpm_worker` | `worker` | Jobs, attempts, checkpoints, heartbeats. No access to accounts or sessions. |

## Prerequisites

- Ubuntu Server 24.04 with Docker Engine and the Compose plugin; `systemctl is-enabled docker` must say `enabled`.
- A DHCP reservation on the router for the workstation (currently `10.0.0.125`).
- Node.js 24 and pnpm (via `corepack enable`), for development and tests only.

## First installation

```bash
cp .env.example .env          # set XPM_HOST / XPM_BIND_ADDR / XPM_PUBLIC_ORIGIN
scripts/init-secrets.sh       # generates database passwords in ./secrets (never overwrites)
docker compose up -d --build --wait
```

Create the administrator in an interactive terminal. The password prompt does
not echo:

```bash
docker compose run --rm --no-deps server node apps/server/dist/cli.js admin create --username <name>
```

Passwords must be at least 12 characters. They are stored as scrypt hashes
(N=2^17, r=8, p=1).

## Trusting the local certificate

Caddy runs its own certificate authority. Export the root certificate once and
install it on each device that opens the dashboard:

```bash
docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./questalina-desk-root.crt
```

- **macOS:** open the file in Keychain Access, add it to the System keychain, and set it to "Always Trust".
- **iPhone/iPad:** AirDrop or email the file, install the profile, then enable it under Settings → General → About → Certificate Trust Settings.
- **Windows:** import it into "Trusted Root Certification Authorities".
- **Linux/Chrome:** Settings → Privacy and security → Security → Manage certificates → Authorities → Import.

The CA key lives in `${XPM_DATA_DIR}/caddy`. Keep that directory in backups;
if you delete it, a new CA is created and every device must trust the new root.

## Day-to-day operations

| Task | Command |
|------|---------|
| Status | `docker compose ps` |
| Logs | `docker compose logs -f server worker` |
| Reset a password (revokes all of that user's sessions) | `docker compose run --rm --no-deps server node apps/server/dist/cli.js admin reset-password --username <name>` |
| List administrators | `docker compose run --rm --no-deps server node apps/server/dist/cli.js admin list` |
| Remove sample cases | `docker compose run --rm --no-deps server node apps/server/dist/cli.js sample clear` |
| Stop | `docker compose down` (data stays in `XPM_DATA_DIR`) |
| Upgrade | `git pull && docker compose up -d --build --wait` (migrations run automatically) |

Containers use `restart: unless-stopped`, so they come back after a workstation
reboot as long as Docker is enabled at boot.

### Sessions and login protection

- The session cookie is `__Host-xpm_session`: `Secure`, `HttpOnly`, `SameSite=Strict`. Only a SHA-256 hash of the token is stored.
- Sessions expire after `XPM_SESSION_TTL_HOURS` (default 12) or `XPM_SESSION_IDLE_MINUTES` of inactivity (default 60).
- State-changing requests need a matching `Origin` and the per-session `X-CSRF-Token`.
- After 5 failed logins for a username (or 20 from one IP) within 15 minutes, logins are refused. The counter is stored in the database, so it survives restarts. A password reset clears it.

### Sample-data mode

`XPM_SAMPLE_DATA=true` seeds fictional cases and enables demo job types (echo,
sleep, flaky, permanent failure) on the Jobs tab, so you can watch retries,
cancellation and recovery. Set it to `false` before connecting real mail in
Milestone 3.

## Job queue semantics

- **Idempotency:** every job has a unique logical key, e.g. `gmail:{mailbox}:{message}`. Enqueuing an existing key returns the existing job.
- **Claiming:** `SELECT … FOR UPDATE SKIP LOCKED` inside a transaction, so no two workers can claim the same job.
- **Leases:** a claim grants a time-limited lease, which the worker renews at one third of the lease length. A job whose lease expires is reclaimed by another worker; the previous attempt is marked `abandoned`.
- **Fencing:** every claim or cancellation increments the job's `fence`. Results, failures and renewals must present the current fence; a late result from a stale worker is rejected and its attempt is marked `stale_rejected`.
- **Atomic completion:** a handler can return a `commit` function. It runs in the same transaction that accepts the result, so workflow state changes and follow-up jobs commit together or not at all.
- **Retries:** retryable failures back off exponentially (5 s, 10 s, 20 s, … up to 1 h) until `max_attempts`. `PermanentJobError` fails immediately. Each attempt is a separate `job_attempts` row.
- **Checkpoints:** compare-and-set records (`checkpoints` table) for durable cursors, such as mailbox sync positions.

The system guarantees at most one *accepted* result per job. It does not
promise that external side effects (LLM calls, email delivery) happen exactly
once across network failures; later milestones handle that with outbox
reconciliation.

## Testing

```bash
pnpm install
pnpm typecheck
pnpm test                     # unit + integration (Testcontainers PostgreSQL; needs Docker)
scripts/acceptance-m1.sh      # end-to-end against real containers on port 18443, disposable
```

The acceptance script runs a separate Compose project (`xpm-accept`) with its
own data directory, so it does not touch a running installation.

### Manual check: workstation reboot

The automated tests cover container restarts and recreation. To verify
persistence across a real reboot:

1. Sign in, open **Jobs**, and enqueue a few sample jobs.
2. `sudo reboot`
3. After boot, without running any commands, open `https://10.0.0.125`. You should still be signed in (if within the idle timeout), and the same jobs should be listed with no duplicates.

### Manual check: LAN exposure from another device

From a laptop on the LAN:

```bash
nmap -Pn -p 80,443,3000,5432 10.0.0.125
```

Expect 80 and 443 open. 3000 and 5432 must be closed or filtered.
