-- Milestone 3: read-only Gmail intake and manual SMS entry.

-- Connection status is visible to the dashboard; the credentials are not.
CREATE TABLE connections (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kind             text NOT NULL CHECK (kind IN ('gmail_reader')),
  -- The owner's own mailbox address (not customer data).
  account          text NOT NULL,
  status           text NOT NULL CHECK (status IN ('active', 'degraded', 'paused', 'disconnected')),
  status_reason    text,
  -- Activation boundary: mail received before this instant is never imported.
  activated_at     timestamptz NOT NULL,
  activation_ref   text,
  last_sync_at     timestamptz,
  last_success_at  timestamptz,
  last_error       text,
  imported_count   integer NOT NULL DEFAULT 0,
  skipped_count    integer NOT NULL DEFAULT 0,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (kind, account)
);

-- OAuth refresh token, encrypted with the master key. Intake role only.
CREATE TABLE vault.connection_secrets (
  connection_id uuid PRIMARY KEY REFERENCES connections (id),
  key_id        text NOT NULL,
  ciphertext    bytea NOT NULL,
  updated_at    timestamptz NOT NULL DEFAULT now()
);

-- Non-identifying facts about a message: delivery alias, labels, attachment
-- types and sizes (never names or content).
ALTER TABLE messages ADD COLUMN metadata jsonb NOT NULL DEFAULT '{}'::jsonb;

GRANT SELECT, INSERT, UPDATE ON connections TO xpm_vault;
GRANT SELECT, INSERT, UPDATE ON vault.connection_secrets TO xpm_vault;
GRANT SELECT, INSERT, UPDATE ON checkpoints TO xpm_vault;
GRANT SELECT ON connections TO xpm_web;
