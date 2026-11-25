# xpm: Questalina Desk

A local internal tool that reads customer correspondence, prepares a daily
briefing, and runs PM and dev-manager agents to investigate product feedback.
It produces customer reply drafts for owner approval and development prompts
for a separate coding agent.

It runs on a single workstation with Docker Compose, and the dashboard is
reachable only on the local network.

**Status:** Milestone 1 (local foundation, authentication, durable job queue).

- Setup and operations: [docs/setup.md](docs/setup.md)
- Layout:
  - `packages/core`: database access, migrations, durable job queue, worker runtime, password hashing
  - `apps/server`: authenticated API, admin CLI, static dashboard hosting
  - `apps/worker`: background job worker
  - `apps/web`: React dashboard
  - `deploy/caddy`: local HTTPS reverse proxy
  - `scripts/`: secret generation, acceptance tests
