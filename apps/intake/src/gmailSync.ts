import {
  CheckpointConflictError,
  decryptString,
  encrypt,
  getCheckpoint,
  setCheckpoint,
  withTx,
  type Logger,
  type MasterKey,
  type Pool,
} from '@xpm/core';
import { scrubSecrets } from '@xpm/privacy';
import {
  GmailClient,
  GmailNotFoundError,
  GoogleAuthError,
  HistoryExpiredError,
  type GmailMessage,
  type GoogleHttp,
  type OAuthClient,
} from './google.js';
import { decodeEncodedWords, extractBody, header, parseAddressList, skipReason } from './mime.js';
import { ingestMessage, type RawMessage } from './vault.js';

export interface Connection {
  id: string;
  account: string;
  status: 'active' | 'degraded' | 'paused' | 'disconnected';
  activatedAt: Date;
}

interface HistoryCheckpoint {
  historyId: string;
  /** Latest internalDate (ms) imported; recovery listings start an hour before it. */
  lastInternalDate: number;
}

const checkpointKey = (connectionId: string) => `gmail:${connectionId}:history`;
const aad = (connectionId: string) => `connection:${connectionId}`;

/**
 * Store (or replace) a Gmail reader connection after a successful sign-in.
 *
 * A first connection sets the activation boundary and history checkpoint, so
 * only mail arriving after this moment is imported. A reconnection after
 * revocation keeps the original boundary and checkpoint, so mail that arrived
 * while paused is picked up and nothing historical is imported.
 */
export async function saveConnection(
  pool: Pool,
  mk: MasterKey,
  args: { account: string; refreshToken: string; historyId: string },
): Promise<{ id: string; reconnected: boolean }> {
  const account = args.account.toLowerCase();
  return withTx(pool, async (tx) => {
    const existing = await tx.query(`SELECT id FROM connections WHERE kind = 'gmail_reader' AND account = $1 FOR UPDATE`, [account]);
    let id: string;
    let reconnected = false;
    if (existing.rows[0]) {
      id = existing.rows[0].id;
      reconnected = true;
      await tx.query(
        `UPDATE connections SET status = 'active', status_reason = NULL, last_error = NULL, updated_at = now() WHERE id = $1`,
        [id],
      );
    } else {
      const created = await tx.query(
        `INSERT INTO connections (kind, account, status, activated_at, activation_ref)
         VALUES ('gmail_reader', $1, 'active', now(), $2) RETURNING id, activated_at`,
        [account, args.historyId],
      );
      id = created.rows[0].id;
      await setCheckpoint(tx, checkpointKey(id), { historyId: args.historyId, lastInternalDate: created.rows[0].activated_at.getTime() }, null);
    }
    const blob = encrypt(mk, JSON.stringify({ refreshToken: args.refreshToken }), aad(id));
    await tx.query(
      `INSERT INTO vault.connection_secrets (connection_id, key_id, ciphertext) VALUES ($1, $2, $3)
       ON CONFLICT (connection_id) DO UPDATE SET key_id = excluded.key_id, ciphertext = excluded.ciphertext, updated_at = now()`,
      [id, mk.id, blob],
    );
    await tx.query(`INSERT INTO audit_log (actor, action, target, details) VALUES ('intake', $1, $2, '{}'::jsonb)`, [
      reconnected ? 'gmail.reconnect' : 'gmail.connect',
      account,
    ]);
    return { id, reconnected };
  });
}

export async function listConnections(pool: Pool, statuses: Connection['status'][] = ['active', 'degraded']): Promise<Connection[]> {
  const { rows } = await pool.query(
    `SELECT id, account, status, activated_at FROM connections WHERE kind = 'gmail_reader' AND status = ANY($1::text[]) ORDER BY account`,
    [statuses],
  );
  return rows.map((r) => ({ id: r.id, account: r.account, status: r.status, activatedAt: r.activated_at }));
}

export async function loadRefreshToken(pool: Pool, mk: MasterKey, connectionId: string): Promise<string> {
  const { rows } = await pool.query(`SELECT ciphertext FROM vault.connection_secrets WHERE connection_id = $1`, [connectionId]);
  if (!rows[0]) throw new GoogleAuthError('No stored authorization for this connection');
  return (JSON.parse(decryptString(mk, rows[0].ciphertext, aad(connectionId))) as { refreshToken: string }).refreshToken;
}

export async function setConnectionStatus(
  pool: Pool,
  connectionId: string,
  status: Connection['status'],
  reason: string | null,
  error: string | null = null,
): Promise<void> {
  await pool.query(
    `UPDATE connections SET status = $2, status_reason = $3, last_error = $4, last_sync_at = now(), updated_at = now() WHERE id = $1`,
    [connectionId, status, reason, error === null ? null : scrubSecrets(error).slice(0, 2000)],
  );
}

export interface SyncOptions {
  customerAddresses: string[];
  log: Logger;
}

export interface SyncResult {
  imported: number;
  skipped: Record<string, number>;
  recovered: boolean;
  historyId: string;
}

function toRawMessage(msg: GmailMessage, account: string, customerAddresses: string[]): { raw: RawMessage; metadata: Record<string, unknown> } {
  const p = msg.payload;
  const from = parseAddressList(header(p, 'From'))[0] ?? { address: 'unknown@invalid' };
  const to = parseAddressList(header(p, 'To'));
  const cc = parseAddressList(header(p, 'Cc'));
  const deliveredTo = [header(p, 'Delivered-To'), header(p, 'X-Original-To')].filter(Boolean).flatMap((v) => parseAddressList(v));
  const recipients = [...to, ...cc, ...deliveredTo].map((a) => a.address.toLowerCase());
  const via = customerAddresses.find((c) => recipients.includes(c.toLowerCase())) ?? null;
  const body = extractBody(p);
  const labels = (msg.labelIds ?? []).filter((l) => l === 'INBOX' || l === 'IMPORTANT' || l === 'UNREAD' || l.startsWith('CATEGORY_'));
  return {
    raw: {
      source: 'email',
      sourceId: `${account}:${msg.id}`,
      threadKey: `gmail:${msg.threadId}`,
      receivedAt: new Date(Number(msg.internalDate)).toISOString(),
      from,
      to,
      cc,
      subject: decodeEncodedWords(header(p, 'Subject') ?? ''),
      text: body.text,
      html: body.text === undefined ? body.html : undefined,
    },
    metadata: { channel: 'gmail', deliveredVia: via, likelyCustomer: via !== null, labels, attachments: body.attachments },
  };
}

/**
 * One incremental sync pass for a connection.
 *
 * - Uses Gmail history from the saved checkpoint; if Gmail has expired that
 *   history, falls back to listing messages received since the last import
 *   (minus an hour of overlap). Both paths enforce the activation boundary.
 * - Imports each message idempotently (unique per mailbox + message id), so
 *   overlaps, retries, and crashes never duplicate anything.
 * - Advances the checkpoint only after every listed message was handled.
 *   Mail arriving during the pass is picked up by the next pass.
 * - Serialized per connection with an advisory lock.
 */
export async function syncConnection(
  pool: Pool,
  mk: MasterKey,
  http: GoogleHttp,
  client: OAuthClient,
  conn: Connection,
  opts: SyncOptions,
): Promise<SyncResult | null> {
  const lockClient = await pool.connect();
  try {
    const lock = await lockClient.query(`SELECT pg_try_advisory_lock(hashtextextended($1, 0)) AS ok`, [checkpointKey(conn.id)]);
    if (!lock.rows[0].ok) return null; // another pass is running

    const gmail = new GmailClient(http, client, await loadRefreshToken(pool, mk, conn.id));
    const cp = await getCheckpoint<HistoryCheckpoint>(pool, checkpointKey(conn.id));
    if (!cp) throw new Error(`Missing checkpoint for connection ${conn.id}`);

    let ids: string[];
    let historyId: string;
    let recovered = false;
    try {
      ({ ids, historyId } = await gmail.messagesAddedSince(cp.value.historyId));
    } catch (err) {
      if (!(err instanceof HistoryExpiredError)) throw err;
      // Take the new position first, so anything arriving during the listing is caught next pass.
      historyId = (await gmail.profile()).historyId;
      const since = Math.max(cp.value.lastInternalDate, conn.activatedAt.getTime()) - 3_600_000;
      ids = await gmail.messageIdsAfter(since / 1000);
      recovered = true;
      opts.log.warn({ connection: conn.id, listed: ids.length }, 'gmail history expired; recovered by listing');
    }

    const skipped: Record<string, number> = {};
    const skip = (r: string) => (skipped[r] = (skipped[r] ?? 0) + 1);
    let imported = 0;
    let lastInternalDate = cp.value.lastInternalDate;
    for (const id of ids) {
      const known = await pool.query(`SELECT 1 FROM vault.originals WHERE source = 'email' AND source_id = $1`, [`${conn.account}:${id}`]);
      if (known.rowCount) {
        skip('already_imported');
        continue;
      }
      let msg: GmailMessage;
      try {
        msg = await gmail.message(id);
      } catch (err) {
        if (err instanceof GmailNotFoundError) {
          skip('deleted');
          continue;
        }
        throw err;
      }
      const internal = Number(msg.internalDate);
      if (internal < conn.activatedAt.getTime()) {
        skip('before_activation');
        continue;
      }
      const reason = skipReason(msg);
      if (reason) {
        skip(reason);
        continue;
      }
      const { raw, metadata } = toRawMessage(msg, conn.account, opts.customerAddresses);
      const r = await ingestMessage(pool, mk, raw, { metadata });
      if (r.created) imported++;
      lastInternalDate = Math.max(lastInternalDate, internal);
    }

    try {
      await setCheckpoint(pool, checkpointKey(conn.id), { historyId, lastInternalDate }, cp.version);
    } catch (err) {
      if (err instanceof CheckpointConflictError) return null; // another pass advanced it; nothing lost
      throw err;
    }
    const skippedTotal = Object.values(skipped).reduce((a, b) => a + b, 0);
    await pool.query(
      `UPDATE connections SET status = 'active', status_reason = NULL, last_error = NULL, last_sync_at = now(), last_success_at = now(),
              imported_count = imported_count + $2, skipped_count = skipped_count + $3, updated_at = now()
       WHERE id = $1 AND status IN ('active', 'degraded')`,
      [conn.id, imported, skippedTotal],
    );
    return { imported, skipped, recovered, historyId };
  } finally {
    await lockClient.query(`SELECT pg_advisory_unlock(hashtextextended($1, 0))`, [checkpointKey(conn.id)]).catch(() => {});
    lockClient.release();
  }
}

/** Run a pass and translate failures into visible connection states. */
export async function syncAndRecord(
  pool: Pool,
  mk: MasterKey,
  http: GoogleHttp,
  client: OAuthClient,
  conn: Connection,
  opts: SyncOptions,
): Promise<SyncResult | null> {
  try {
    const result = await syncConnection(pool, mk, http, client, conn, opts);
    if (result && (result.imported > 0 || result.recovered)) opts.log.info({ connection: conn.id, ...result }, 'gmail sync');
    return result;
  } catch (err) {
    const message = (err as Error).message;
    if (err instanceof GoogleAuthError) {
      await setConnectionStatus(pool, conn.id, 'paused', 'Google authorization was revoked or expired. Reconnect to resume.', message);
      opts.log.error({ connection: conn.id, err }, 'gmail connection paused');
    } else {
      await setConnectionStatus(pool, conn.id, 'degraded', 'Temporary problem reaching Gmail; retrying automatically.', message);
      opts.log.warn({ connection: conn.id, err }, 'gmail sync failed; will retry');
    }
    return null;
  }
}
