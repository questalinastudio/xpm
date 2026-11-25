-- Milestone 2: protected originals, sanitized correspondence, agent turns,
-- and call/tool traces, with database-enforced boundaries between services.

DO $$
DECLARE r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['xpm_vault', 'xpm_gateway', 'xpm_pm_tools', 'xpm_dev_tools'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('CREATE ROLE %I NOLOGIN', r);
    END IF;
  END LOOP;
END
$$;
GRANT USAGE ON SCHEMA public TO xpm_vault, xpm_gateway, xpm_pm_tools, xpm_dev_tools;

-- ---------------------------------------------------------------------------
-- Vault: encrypted originals and identity mappings. Only the intake service
-- (xpm_vault) can touch this schema. Values are AES-256-GCM encrypted with the
-- owner's master key, which the database never sees.
-- ---------------------------------------------------------------------------

CREATE SCHEMA vault;
REVOKE ALL ON SCHEMA vault FROM PUBLIC;
GRANT USAGE ON SCHEMA vault TO xpm_vault;

CREATE TABLE vault.originals (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  source      text NOT NULL CHECK (source IN ('email', 'sms')),
  source_id   text NOT NULL,
  key_id      text NOT NULL,
  ciphertext  bytea NOT NULL,
  received_at timestamptz NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (source, source_id)
);

-- Placeholder ↔ identity. value_hmac is a keyed hash of the canonical value,
-- so lookups need the master key and the table alone reveals nothing.
CREATE TABLE vault.identities (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kind        text NOT NULL CHECK (kind IN ('person', 'email', 'phone')),
  value_hmac  text NOT NULL,
  placeholder text NOT NULL UNIQUE,
  key_id      text NOT NULL,
  ciphertext  bytea NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (kind, value_hmac)
);
CREATE SEQUENCE vault.placeholder_person_seq;
CREATE SEQUENCE vault.placeholder_email_seq;
CREATE SEQUENCE vault.placeholder_phone_seq;

GRANT SELECT, INSERT ON vault.originals, vault.identities TO xpm_vault;
GRANT USAGE ON SEQUENCE vault.placeholder_person_seq, vault.placeholder_email_seq, vault.placeholder_phone_seq TO xpm_vault;

-- ---------------------------------------------------------------------------
-- Sanitized correspondence (placeholders only). The PM reads it through a
-- view that exposes only messages cleared for model use.
-- ---------------------------------------------------------------------------

CREATE TABLE messages (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  original_id        uuid NOT NULL UNIQUE REFERENCES vault.originals (id),
  source             text NOT NULL CHECK (source IN ('email', 'sms')),
  thread_key         text NOT NULL,
  case_id            uuid REFERENCES cases (id),
  sender_placeholder text,
  subject            text NOT NULL DEFAULT '',
  body               text NOT NULL,
  received_at        timestamptz NOT NULL,
  status             text NOT NULL CHECK (status IN ('ready', 'held_for_review', 'excluded')),
  -- Counts by kind and rule names with offsets; never the detected values.
  redaction_summary  jsonb NOT NULL DEFAULT '{}'::jsonb,
  held_reasons       jsonb NOT NULL DEFAULT '[]'::jsonb,
  created_at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX messages_case_idx ON messages (case_id, received_at);
CREATE INDEX messages_fts_idx ON messages USING gin (to_tsvector('english', subject || ' ' || body));

CREATE VIEW pm_messages AS
  SELECT id, source, thread_key, case_id, sender_placeholder, subject, body, received_at
  FROM messages WHERE status = 'ready';

-- Product knowledge (PM-visible). Fuller provenance arrives in Milestone 5.
CREATE TABLE knowledge_entries (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  title      text NOT NULL,
  body       text NOT NULL,
  status     text NOT NULL DEFAULT 'proposal' CHECK (status IN ('proposal', 'approved', 'stale', 'retired')),
  provenance jsonb NOT NULL DEFAULT '{}'::jsonb,
  is_sample  boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX knowledge_fts_idx ON knowledge_entries USING gin (to_tsvector('english', title || ' ' || body));

-- Case briefs: sanitized problem statements handed to the dev manager.
CREATE TABLE case_briefs (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id    uuid NOT NULL REFERENCES cases (id),
  body       text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Agent turns and traces
-- ---------------------------------------------------------------------------

CREATE TABLE agent_turns (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  logical_key      text NOT NULL,
  attempt_no       integer NOT NULL,
  agent_role       text NOT NULL CHECK (agent_role IN ('pm', 'dev')),
  purpose          text NOT NULL,
  case_id          uuid REFERENCES cases (id),
  discussion_id    uuid,
  round            integer,
  input            jsonb NOT NULL DEFAULT '{}'::jsonb,
  status           text NOT NULL DEFAULT 'queued'
                   CHECK (status IN ('queued', 'claimed', 'succeeded', 'failed', 'abandoned')),
  ticket_hash      text,
  runtime_id       text,
  claimed_at       timestamptz,
  deadline_at      timestamptz NOT NULL,
  output           jsonb,
  decision_summary jsonb,
  error            text,
  llm_call_count   integer NOT NULL DEFAULT 0,
  tool_call_count  integer NOT NULL DEFAULT 0,
  created_at       timestamptz NOT NULL DEFAULT now(),
  finished_at      timestamptz,
  UNIQUE (logical_key, attempt_no)
);
CREATE INDEX agent_turns_claimable_idx ON agent_turns (agent_role, created_at) WHERE status = 'queued';
CREATE INDEX agent_turns_created_idx ON agent_turns (created_at DESC);

-- One row per model call, written as "pending" BEFORE the request is sent,
-- so crashed or hung calls stay visible. Retries are new rows.
CREATE TABLE llm_calls (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  turn_id             uuid NOT NULL REFERENCES agent_turns (id),
  seq                 integer NOT NULL,
  agent_role          text NOT NULL,
  sensitivity         text NOT NULL CHECK (sensitivity IN ('product', 'technical')),
  logical_key         text NOT NULL,
  attempt_no          integer NOT NULL,
  case_id             uuid,
  discussion_id       uuid,
  round               integer,
  purpose             text NOT NULL,
  provider            text NOT NULL,
  model               text NOT NULL,
  instruction_version text NOT NULL,
  request             jsonb NOT NULL,
  tools_available     jsonb NOT NULL,
  parameters          jsonb NOT NULL DEFAULT '{}'::jsonb,
  context_versions    jsonb NOT NULL DEFAULT '{}'::jsonb,
  status              text NOT NULL DEFAULT 'pending'
                      CHECK (status IN ('pending', 'succeeded', 'failed', 'blocked', 'abandoned')),
  response            jsonb,
  tool_requests       jsonb,
  validation          jsonb,
  provider_request_id text,
  latency_ms          integer,
  usage               jsonb,
  cost_usd            numeric(12, 6),
  error               text,
  started_at          timestamptz NOT NULL DEFAULT now(),
  finished_at         timestamptz,
  UNIQUE (turn_id, seq)
);
CREATE INDEX llm_calls_turn_idx ON llm_calls (turn_id, seq);

CREATE TABLE tool_calls (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  turn_id        uuid NOT NULL REFERENCES agent_turns (id),
  llm_call_id    uuid REFERENCES llm_calls (id),
  seq            integer NOT NULL,
  agent_role     text NOT NULL,
  sensitivity    text NOT NULL CHECK (sensitivity IN ('product', 'technical')),
  tool           text NOT NULL,
  arguments      jsonb NOT NULL,
  authz          text NOT NULL CHECK (authz IN ('allowed', 'denied')),
  denial_reason  text,
  status         text NOT NULL CHECK (status IN ('pending', 'succeeded', 'failed', 'denied', 'abandoned')),
  result         jsonb,
  evidence_refs  jsonb NOT NULL DEFAULT '[]'::jsonb,
  error          text,
  started_at     timestamptz NOT NULL DEFAULT now(),
  finished_at    timestamptz,
  UNIQUE (turn_id, seq)
);
CREATE INDEX tool_calls_turn_idx ON tool_calls (turn_id, seq);

-- ---------------------------------------------------------------------------
-- Grants
-- ---------------------------------------------------------------------------

-- Intake: writes protected originals and sanitized messages.
GRANT SELECT, INSERT ON messages TO xpm_vault;
GRANT SELECT ON cases TO xpm_vault;
GRANT INSERT ON audit_log TO xpm_vault;
GRANT USAGE ON SEQUENCE audit_log_id_seq TO xpm_vault;

-- Gateway: turn lifecycle and trace writing only. No correspondence, no knowledge, no vault.
GRANT SELECT, UPDATE ON agent_turns TO xpm_gateway;
GRANT SELECT, INSERT, UPDATE ON llm_calls, tool_calls TO xpm_gateway;

-- PM tools: sanitized, cleared correspondence and product knowledge. No source, no traces.
GRANT SELECT ON pm_messages, knowledge_entries TO xpm_pm_tools;
GRANT SELECT (id, reference, title, kind, status) ON cases TO xpm_pm_tools;

-- Dev tools: case briefs. No correspondence, identities, or traces.
GRANT SELECT ON case_briefs TO xpm_dev_tools;
GRANT SELECT (id, reference, title, kind, status) ON cases TO xpm_dev_tools;

-- Worker: creates turn attempts and marks superseded ones abandoned.
GRANT SELECT, INSERT, UPDATE ON agent_turns TO xpm_worker;
GRANT SELECT, UPDATE ON llm_calls, tool_calls TO xpm_worker;

-- Owner dashboard: read everything except the vault; manage sample knowledge and briefs.
GRANT SELECT ON messages, agent_turns, llm_calls, tool_calls TO xpm_web;
GRANT SELECT, INSERT, UPDATE, DELETE ON knowledge_entries, case_briefs TO xpm_web;
