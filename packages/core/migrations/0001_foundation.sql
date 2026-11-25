-- Milestone 1 foundation: administrator auth, durable jobs, checkpoints,
-- worker health, audit log, and initial case records.

-- Per-service database roles. They are created NOLOGIN here; the migration
-- runner grants LOGIN and sets passwords from secret files at deploy time.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'xpm_web') THEN
    CREATE ROLE xpm_web NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'xpm_worker') THEN
    CREATE ROLE xpm_worker NOLOGIN;
  END IF;
END
$$;

REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO xpm_web, xpm_worker;

-- ---------------------------------------------------------------------------
-- Administrator authentication
-- ---------------------------------------------------------------------------

CREATE TABLE admin_users (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  username            text NOT NULL UNIQUE CHECK (username ~ '^[a-z0-9._-]{3,64}$'),
  password_hash       text NOT NULL,
  created_at          timestamptz NOT NULL DEFAULT now(),
  password_changed_at timestamptz NOT NULL DEFAULT now(),
  disabled_at         timestamptz
);

-- Only a SHA-256 hash of the session token is stored; the raw token lives
-- solely in the browser's HTTP-only cookie.
CREATE TABLE sessions (
  id_hash      text PRIMARY KEY,
  user_id      uuid NOT NULL REFERENCES admin_users (id) ON DELETE CASCADE,
  csrf_token   text NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,
  revoked_at   timestamptz,
  ip           text,
  user_agent   text
);
CREATE INDEX sessions_user_idx ON sessions (user_id);

-- Failed login attempts, used for persistent rate limiting.
CREATE TABLE login_failures (
  id       bigserial PRIMARY KEY,
  username text NOT NULL,
  ip       text NOT NULL,
  at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX login_failures_username_idx ON login_failures (username, at);
CREATE INDEX login_failures_ip_idx ON login_failures (ip, at);

-- ---------------------------------------------------------------------------
-- Durable job queue
-- ---------------------------------------------------------------------------

CREATE TABLE jobs (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  idempotency_key  text NOT NULL UNIQUE,
  type             text NOT NULL,
  payload          jsonb NOT NULL DEFAULT '{}'::jsonb,
  status           text NOT NULL DEFAULT 'queued'
                   CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')),
  attempts         integer NOT NULL DEFAULT 0,
  max_attempts     integer NOT NULL DEFAULT 5 CHECK (max_attempts >= 1),
  run_at           timestamptz NOT NULL DEFAULT now(),
  -- Lease: which worker holds the job and until when.
  lease_owner      text,
  lease_expires_at timestamptz,
  -- Fencing version: incremented on every claim and cancellation. A result is
  -- accepted only if it carries the current fence.
  fence            bigint NOT NULL DEFAULT 0,
  last_error       text,
  result           jsonb,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  completed_at     timestamptz,
  CHECK ((status = 'running') = (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL))
);
CREATE INDEX jobs_claimable_idx ON jobs (run_at, created_at) WHERE status IN ('queued', 'running');
CREATE INDEX jobs_status_created_idx ON jobs (status, created_at DESC);
CREATE INDEX jobs_created_idx ON jobs (created_at DESC);

-- One row per claim. Retries reuse the job (logical operation key) but get a
-- distinct attempt record.
CREATE TABLE job_attempts (
  id          bigserial PRIMARY KEY,
  job_id      uuid NOT NULL REFERENCES jobs (id) ON DELETE CASCADE,
  attempt_no  integer NOT NULL,
  fence       bigint NOT NULL,
  worker_id   text NOT NULL,
  status      text NOT NULL DEFAULT 'running'
              CHECK (status IN ('running', 'succeeded', 'failed', 'abandoned',
                                'stale_rejected', 'cancelled', 'interrupted')),
  error       text,
  started_at  timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz,
  UNIQUE (job_id, fence)
);

-- Durable checkpoints (e.g. mailbox sync cursors) with optimistic versioning.
CREATE TABLE checkpoints (
  key        text PRIMARY KEY,
  value      jsonb NOT NULL,
  version    bigint NOT NULL DEFAULT 1,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE worker_heartbeats (
  worker_id    text PRIMARY KEY,
  started_at   timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  details      jsonb NOT NULL DEFAULT '{}'::jsonb
);

-- ---------------------------------------------------------------------------
-- Audit log and initial domain records
-- ---------------------------------------------------------------------------

CREATE TABLE audit_log (
  id      bigserial PRIMARY KEY,
  at      timestamptz NOT NULL DEFAULT now(),
  actor   text NOT NULL,
  action  text NOT NULL,
  target  text,
  details jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX audit_log_at_idx ON audit_log (at DESC);

CREATE TABLE cases (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  reference  text NOT NULL UNIQUE,
  title      text NOT NULL,
  kind       text NOT NULL DEFAULT 'uncertain'
             CHECK (kind IN ('bug', 'feature', 'product_question', 'other_actionable',
                             'informational', 'routine', 'uncertain')),
  status     text NOT NULL DEFAULT 'open'
             CHECK (status IN ('open', 'in_discussion', 'awaiting_owner', 'closed')),
  summary    text NOT NULL DEFAULT '',
  is_sample  boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX cases_created_idx ON cases (created_at DESC);

-- ---------------------------------------------------------------------------
-- Grants. The web service never needs worker internals beyond the queue; the
-- worker never sees administrator credentials or sessions.
-- ---------------------------------------------------------------------------

GRANT SELECT, INSERT, UPDATE, DELETE ON admin_users, sessions, login_failures TO xpm_web;
GRANT SELECT, INSERT, UPDATE ON jobs, job_attempts TO xpm_web;
GRANT SELECT ON checkpoints, worker_heartbeats, schema_migrations TO xpm_web;
GRANT SELECT, INSERT, UPDATE, DELETE ON cases TO xpm_web;
GRANT SELECT, INSERT ON audit_log TO xpm_web;

GRANT SELECT, INSERT, UPDATE ON jobs, job_attempts, checkpoints, worker_heartbeats TO xpm_worker;
GRANT SELECT ON cases TO xpm_worker;
GRANT INSERT ON audit_log TO xpm_worker;

GRANT USAGE ON SEQUENCE login_failures_id_seq, audit_log_id_seq, job_attempts_id_seq TO xpm_web;
GRANT USAGE ON SEQUENCE job_attempts_id_seq, audit_log_id_seq TO xpm_worker;
