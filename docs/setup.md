# Questalina Desk: setup and operations

Status: Milestones 1–3 (foundation, authentication, durable jobs; privacy, agent isolation, traces; read-only Gmail and manual SMS intake).

## What runs

| Service    | Purpose                                   | Network            | Published |
|------------|-------------------------------------------|--------------------|-----------|
| `caddy`    | HTTPS with a local certificate authority  | `edge`             | `XPM_BIND_ADDR:443`, `:80` (redirect) |
| `server`   | Dashboard and authenticated API           | `edge`, `internal` | no |
| `worker`   | Durable job worker                        | `internal`         | no |
| `migrate`  | One-shot schema migration and role setup  | `internal`         | no |
| `postgres` | PostgreSQL 17                             | `internal`         | no |
| `gateway`  | Agent tool gateway: authorization, payload gating, traces | `internal`, `agents_pm`, `agents_dev` | no |
| `pm-runtime` | PM agent tool loop (empty, read-only container) | `agents_pm` only | no |
| `dev-runtime` | Dev-manager agent tool loop (empty, read-only container) | `agents_dev` only | no |
| `intake` | Gmail read-only polling and manual SMS; encrypts originals, redacts, stores sanitized messages | `internal`, `google_egress` | no |
| `reposync` (tool) | Builds the sanitized source snapshot | none | no |
| `keytool` (tool) | Master key: generate, verify, restore | none | no |

`internal` is a Docker `internal: true` network with no route to the internet.
PostgreSQL, the server and the worker publish no host ports; only Caddy does,
and only on the reserved LAN address.

Each service connects to PostgreSQL with its own role:

| Role         | Used by | Access |
|--------------|---------|--------|
| `xpm_owner`  | `migrate` | Schema owner. Never used by long-running services. |
| `xpm_web`    | `server`, admin CLI | Accounts, sessions, jobs, cases, audit. |
| `xpm_worker` | `worker` | Jobs, attempts, checkpoints, heartbeats, agent turn attempts. No accounts, sessions, or vault. |
| `xpm_vault`  | `intake` | The only role with the `vault` schema (encrypted originals, identity mappings). |
| `xpm_gateway` | `gateway` | Agent turns and traces. No correspondence, knowledge, or vault. |
| `xpm_pm_tools` | `gateway` (PM tools) | Cleared sanitized messages (`pm_messages` view), product knowledge. No source, briefs, or traces. |
| `xpm_dev_tools` | `gateway` (dev tools) | Case briefs. No correspondence, identities, knowledge, or traces. |

## Prerequisites

- Ubuntu Server 24.04 with Docker Engine and the Compose plugin; `systemctl is-enabled docker` must say `enabled`.
- A DHCP reservation on the router for the workstation (currently `10.0.0.125`).
- The boot-time binding setting below (one command, needs `sudo`).
- Node.js 24 and pnpm (via `corepack enable`), for development and tests only.

### Boot-time network binding

Caddy binds only to the reserved LAN address. At boot, Docker can start before
DHCP has assigned that address. When that happens, the bind fails with
`cannot assign requested address`, and Docker does not retry, so the dashboard
stays down after a reboot. This was observed on 2026-11-25, when Wi-Fi took
2.7 s longer than Docker to come up.

Allow binding to an address that is not assigned yet. Traffic flows as soon as
DHCP assigns it:

```bash
echo 'net.ipv4.ip_nonlocal_bind = 1' | sudo tee /etc/sysctl.d/60-xpm-nonlocal-bind.conf
sudo sysctl --system
```

A wired connection (`enp193s0`) is also recommended over Wi-Fi for an always-on
server.

## First installation

```bash
cp .env.example .env          # set XPM_HOST / XPM_BIND_ADDR / XPM_PUBLIC_ORIGIN
scripts/init-secrets.sh       # generates database passwords in ./secrets (never overwrites)
docker compose run --rm keytool generate   # master key + paper backup (interactive; required before first start)
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

## Master key and paper backup

Original messages and the placeholder↔identity mapping are encrypted with
AES-256-GCM under a master key held in `secrets/protected_master_key`. Only
the `intake` container receives it. PostgreSQL never sees it.

| Task | Command (run in your own terminal) |
|------|---------|
| Create the key and paper copy (once) | `docker compose run --rm keytool generate` |
| Check a paper copy | `docker compose run --rm keytool verify` |
| Show the fingerprint | `docker compose run --rm keytool status` |
| Rebuild the key file from paper | `docker compose run --rm keytool restore` |

The tool runs with no network. It shows or reads the key only on an
interactive terminal, so the key cannot end up in logs or chat transcripts.
The paper format is 14 groups of 4 characters, the last group being a
checksum. Lowercase and O/I/L mix-ups are tolerated, and a mistyped character
is rejected rather than silently accepted. **If both the key file and the paper
copy are lost, encrypted originals cannot be recovered.** Sanitized messages,
knowledge, and traces are not encrypted with this key and stay readable.

## Privacy pipeline

1. **Normalization.** NFKC, invisible/bidi control characters removed, HTML
   reduced to text (hidden elements, scripts, and comments dropped).
2. **Protected original.** The raw message is encrypted into `vault.originals`.
3. **Redaction.**
   - Identities become stable placeholders: `[PERSON_n]`, `[EMAIL_n]`, `[PHONE_n]`. The same person keeps the same placeholder across messages, and the mapping is encrypted in `vault.identities`, looked up by keyed hash.
   - Cards (Luhn-checked), US SSNs, street addresses, IP addresses, credentials, and URL token parameters become fixed markers.
4. **Hold for review.** Uncertain findings (long digit runs, random-looking
   tokens, weak credential assignments) are masked as `[HELD_n]`, and the
   message is marked `held_for_review`. Agents never see held messages.
5. **Defense in depth.** The gateway re-checks every outbound model payload and
   tool result. Anything that still looks like an email, phone, card,
   government ID, or credential is masked. If it appears in a model request,
   the call is blocked and recorded without the data.

**Known limitations.** Detection is pattern-based. Names are found from
headers, salutations, signatures, and self-introductions; a name that appears
only in free text (for example "my husband Desmond") is not detected. Treat
redaction as risk reduction, not a guarantee.

**Source snapshot.** `reposync` writes a read-only copy of the source to the
`source_snapshots` volume:
- Excluded: VCS metadata, dependencies, build output, symlinks, binaries, files over 512 KB, `.env*` (except `.env.example`-style templates), keys and certificates, credential files, and database dumps.
- Embedded credentials are replaced with `[REDACTED_SECRET:<rule>]`, and real-looking email addresses are replaced.
- Files with ambiguous findings are held (excluded and listed).
- The manifest records every decision, never the secret values.

## Agent isolation

| | PM agent | Dev-manager agent |
|---|---|---|
| Tools | `case.messages`, `knowledge.search` | `case.brief`, `source.search`, `source.read` |
| Can read | Cleared sanitized messages, product knowledge | Case briefs, sanitized snapshot (read-only) |
| Cannot read | Source, briefs, traces, held messages, vault | Mail, identities, knowledge, traces, vault |

- Neither agent has a send, write, shell, or mailbox tool. Those don't exist in the gateway at all.
- Runtimes hold only their own gateway token. They run read-only, on their own internal network, with no internet, database, or files.
- The gateway composes the system instructions and the tool list, so a runtime cannot change either.
- Each turn gets a ticket that is invalid once the turn finishes, is superseded, or passes its deadline.
- Model and tool calls per turn are capped (8 and 24).

## Traces

- **Model calls.** Each call is written to `llm_calls` as `pending` before it is sent. The record includes the exact outbound payload, instruction version, tool list, parameters, and source ref. It is completed afterwards with the response, tool requests, latency, usage, and provider request ID, or with a scrubbed error.
- **Tool calls.** Each `tool_calls` row records the role decision (allowed/denied and the reason), arguments, result, and evidence references.
- **Turns.** Turns carry a decision summary: evidence, assumptions, uncertainty, alternatives, outcome, and reason.
- **Retries.** A retry is a new turn attempt. The interrupted attempt and its calls stay visible as `abandoned` or `failed`.
- **Sensitivity.** Dev-manager traces are marked `technical`. The PM's database role cannot read any trace.

Errors and logs pass through credential scrubbing: every loaded secret value
is replaced by exact match, along with common credential patterns.

## Connecting Gmail (read-only)

The intake service reads **new** mail from one Gmail mailbox. Mail to the
addresses in `XPM_CUSTOMER_ADDRESSES` (for example the `info@` alias) is
flagged as likely customer correspondence. All other new mail is still read for
the briefing.

**What it never does.** It does not send, delete, label, archive, or mark mail
as read:
- The only scope it requests is `gmail.readonly`.
- Its HTTP client refuses any Gmail request that is not a GET, and any host that is not Google's.

### One-time Google Cloud setup (done 2026-11-25)

- **Project:** `questalina-desk-xpm`, in the `questalinastudio.com` organization, with the Gmail API enabled.
- **Consent screen:** Google Auth Platform → Audience **Internal**, Data access **only** `.../auth/gmail.readonly`.
- **Client:** Desktop client `desk-reader`. Its JSON file is stored as `secrets/gmail_reader_client.json` (mode 600, gitignored).

### Sign in (once, and again only if access is revoked)

The workstation has no browser, so the sign-in runs on the workstation while
your laptop's browser approves it through an SSH tunnel. No public callback
exists, and the helper's port is only on the workstation's 127.0.0.1.

1. On your laptop, open the tunnel and leave it running:
   ```bash
   ssh -N -L 8765:127.0.0.1:8765 eko@10.0.0.125
   ```
2. In a second terminal on the workstation (an SSH session is fine):
   ```bash
   cd ~/workspaces/xpm
   docker compose run --rm -p 127.0.0.1:8765:8765 intake gmail-connect --account chris.huang@questalinastudio.com
   ```
3. Open the printed `https://accounts.google.com/...` link in the laptop
   browser, sign in as that account, and approve read-only access. The page
   says **Connected**, and the terminal prints `✔ Connected`.

The helper refuses the result if a different Google account approves, or if
any scope broader than read-only is granted. The refresh token is stored
encrypted with the master key. **Only mail arriving after this moment is
imported. Nothing historical is.**

### Operation

| Situation | What happens |
|---|---|
| New mail | Imported within `XPM_GMAIL_POLL_SECONDS` (default 60). Sent mail, drafts, spam, trash, and chats are skipped. |
| Restart or crash | Resumes from the saved Gmail history checkpoint; each message is imported at most once. |
| Internet or Google outage | Status **degraded** on the dashboard; retries automatically and imports what arrived meanwhile. |
| Gmail history expired (long outage) | Recovers by listing mail since the last import (one hour of overlap), still excluding anything before activation. |
| Access revoked or expired | Status **paused** with a reason; nothing is lost. Run the sign-in again: the original activation boundary is kept and mail that arrived while paused is imported. |

Commands: `docker compose run --rm intake gmail-status` shows the state, and
`docker compose run --rm intake gmail-disconnect --account <email>` revokes
access at Google and stops reading.

**Network note.** The intake container has outbound internet on its own
`google_egress` network. The restriction to Google hosts is enforced in the
application's HTTP client. A network-level egress proxy is planned alongside
the AI provider in Milestone 4.

## Manual SMS entry

Dashboard → **Add SMS**. Paste the text, the sender's number, an optional
name, the time received, and optional context. The dashboard server forwards
it over the internal network to the intake service; the server itself holds no
encryption key. It goes through the same redaction as email, and texts from
the same number share a thread without the number being stored. Submitting the
same form twice does not create a duplicate.

Alternatively, forward an SMS from the iPhone by email to `info@`; it arrives
as ordinary mail.

## Day-to-day operations

| Task | Command |
|------|---------|
| Health check (run after every reboot) | `scripts/check-health.sh` |
| Status | `docker compose ps` |
| Logs | `docker compose logs -f server worker` |
| Reset a password (revokes all of that user's sessions) | `docker compose run --rm --no-deps server node apps/server/dist/cli.js admin reset-password --username <name>` |
| List administrators | `docker compose run --rm --no-deps server node apps/server/dist/cli.js admin list` |
| Remove sample cases | `docker compose run --rm --no-deps server node apps/server/dist/cli.js sample clear` |
| Stop | `docker compose down` (data stays in `XPM_DATA_DIR`) |
| Upgrade | `git pull && scripts/init-secrets.sh && docker compose up -d --build --wait` (new secrets are created if a release adds services; migrations run automatically) |
| Load synthetic sample data (sample mode only) | `docker compose run --rm reposync synthetic && docker compose restart gateway && docker compose run --rm intake ingest-synthetic` |

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
scripts/acceptance-m1.sh      # M1 end-to-end against real containers on port 18443, disposable
scripts/acceptance-m2.sh      # M2: isolation, injection, traces, and a leak scan of DB and all container logs
scripts/acceptance-m3.sh      # M3: Gmail intake against a fake Google container, outages, revocation, SMS
```

The acceptance script runs a separate Compose project (`xpm-accept`) with its
own data directory, so it does not touch a running installation.

### Manual check: workstation reboot

The automated tests cover container restarts and recreation. To verify
persistence across a real reboot:

1. Sign in, open **Jobs**, and enqueue a few sample jobs.
2. `sudo reboot`
3. After boot, without running any commands, open `https://10.0.0.125`. You should still be signed in (if within the idle timeout), and the same jobs should be listed with no duplicates.
4. Run `scripts/check-health.sh`; every check should pass.

### Manual check: LAN exposure from another device

From a laptop on the LAN:

```bash
nmap -Pn -p 80,443,3000,5432 10.0.0.125
```

Expect 80 and 443 open. 3000 and 5432 must be closed or filtered.
