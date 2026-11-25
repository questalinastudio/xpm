# xpm: Questalina Desk

A local internal tool that reads customer correspondence, prepares a daily
briefing, and runs PM and dev-manager agents to investigate product feedback.
It produces customer reply drafts for owner approval and development prompts
for a separate coding agent.

It runs on a single workstation with Docker Compose, and the dashboard is
reachable only on the local network.

**Status:** Milestones 1–2 complete (foundation, auth, durable jobs; privacy, agent isolation, traces with a simulated AI provider).

- Setup and operations: [docs/setup.md](docs/setup.md)
- Layout:
  - `packages/core`: database access, migrations, durable job queue, worker runtime, password hashing, encryption
  - `packages/privacy`: normalization, redaction, secret scanning, source sanitization, synthetic test data
  - `apps/server`: authenticated API, admin CLI, static dashboard hosting
  - `apps/worker`: background job worker
  - `apps/web`: React dashboard
  - `apps/intake`: protected originals, redaction, sanitized message storage
  - `apps/gateway`: agent tool gateway (authorization, payload gating, traces, provider adapter)
  - `apps/agent-runtime`: PM / dev-manager tool loop (isolated containers)
  - `deploy/caddy`: local HTTPS reverse proxy
  - `scripts/`: secret generation, acceptance tests
