import { createHmac } from 'node:crypto';
import { encrypt, withTx, type MasterKey, type Pool, type PoolClient, type Queryable } from '@xpm/core';
import {
  canonicalIdentity,
  htmlToText,
  normalizeText,
  redactText,
  type IdentityKind,
  type KnownPerson,
  type PlaceholderResolver,
  SYNTHETIC_MESSAGES,
} from '@xpm/privacy';

/**
 * The shared intake contract. Gmail (Milestone 3), manual SMS entry, and any
 * future provider adapter produce this shape; everything after it is common.
 */
export interface RawMessage {
  source: 'email' | 'sms';
  /** Provider message identifier; with source, the idempotency key. */
  sourceId: string;
  threadKey: string;
  receivedAt: string;
  from: { name?: string; address: string };
  to: { name?: string; address: string }[];
  cc?: { name?: string; address: string }[];
  subject?: string;
  text?: string;
  html?: string;
}

export interface IngestResult {
  messageId: string;
  created: boolean;
  status: 'ready' | 'held_for_review';
}

function identityHmac(mk: MasterKey, kind: IdentityKind, canonical: string): string {
  const subkey = createHmac('sha256', mk.key).update('xpm-identity-hmac-v1').digest();
  return createHmac('sha256', subkey).update(`${kind}:${canonical}`).digest('hex');
}

/**
 * Resolves identities to stable placeholders stored in the vault. Lookups use
 * a keyed hash, so the database never holds a searchable plaintext value.
 */
export function vaultResolver(db: Queryable, mk: MasterKey): PlaceholderResolver {
  const cache = new Map<string, string>();
  return async (kind, canonical) => {
    const hmac = identityHmac(mk, kind, canonical);
    const cached = cache.get(hmac);
    if (cached) return cached;
    const existing = await db.query(`SELECT placeholder FROM vault.identities WHERE kind = $1 AND value_hmac = $2`, [kind, hmac]);
    let placeholder: string | undefined = existing.rows[0]?.placeholder;
    if (!placeholder) {
      const n = (await db.query(`SELECT nextval($1::regclass) AS n`, [`vault.placeholder_${kind}_seq`])).rows[0].n;
      const candidate = `[${kind.toUpperCase()}_${n}]`;
      const inserted = await db.query(
        `INSERT INTO vault.identities (kind, value_hmac, placeholder, key_id, ciphertext)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (kind, value_hmac) DO NOTHING RETURNING placeholder`,
        [kind, hmac, candidate, mk.id, encrypt(mk, canonical, `identity:${kind}:${hmac}`)],
      );
      placeholder =
        inserted.rows[0]?.placeholder ??
        (await db.query(`SELECT placeholder FROM vault.identities WHERE kind = $1 AND value_hmac = $2`, [kind, hmac])).rows[0].placeholder;
    }
    cache.set(hmac, placeholder!);
    return placeholder!;
  };
}

function senderIdentity(raw: RawMessage): { kind: IdentityKind; value: string } {
  return raw.source === 'sms' || !raw.from.address.includes('@')
    ? { kind: 'phone', value: canonicalIdentity('phone', raw.from.address) }
    : { kind: 'email', value: canonicalIdentity('email', raw.from.address) };
}

/**
 * Store the encrypted original, redact, and save the sanitized message.
 * Idempotent on (source, sourceId). Messages with ambiguous findings are held
 * for owner review and never shown to agents until cleared.
 */
export async function ingestMessage(
  pool: Pool,
  mk: MasterKey,
  raw: RawMessage,
  opts: { caseId?: string | null } = {},
): Promise<IngestResult> {
  return withTx(pool, async (tx: PoolClient) => {
    const original = await tx.query(
      `INSERT INTO vault.originals (source, source_id, key_id, ciphertext, received_at)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (source, source_id) DO NOTHING RETURNING id`,
      [raw.source, raw.sourceId, mk.id, encrypt(mk, JSON.stringify(raw), `original:${raw.source}:${raw.sourceId}`), raw.receivedAt],
    );
    if (!original.rows[0]) {
      const existing = await tx.query(
        `SELECT m.id, m.status FROM messages m JOIN vault.originals o ON o.id = m.original_id
         WHERE o.source = $1 AND o.source_id = $2`,
        [raw.source, raw.sourceId],
      );
      return { messageId: existing.rows[0].id, created: false, status: existing.rows[0].status };
    }

    const resolve = vaultResolver(tx, mk);
    const people: KnownPerson[] = [raw.from, ...raw.to, ...(raw.cc ?? [])].map((p) => ({ name: p.name, email: p.address }));
    const body = normalizeText(raw.html ? htmlToText(raw.html) : (raw.text ?? ''));
    const subject = normalizeText(raw.subject ?? '');
    // Ambiguous spans are masked as [HELD_n] even in the held copy, so the
    // sanitized table never holds unconfirmed values. The owner reviews them
    // against the encrypted original.
    let held = 0;
    const holdMarker = () => `[HELD_${++held}]`;
    const redactedSubject = await redactText(subject, { knownPeople: people, resolve, holdMarker });
    const redactedBody = await redactText(body, { knownPeople: people, resolve, holdMarker });
    const sender = senderIdentity(raw);
    const senderPlaceholder = await resolve(sender.kind, sender.value);

    const ambiguous = [
      ...redactedSubject.ambiguous.map((a) => ({ rule: a.rule, field: 'subject', marker: a.marker })),
      ...redactedBody.ambiguous.map((a) => ({ rule: a.rule, field: 'body', marker: a.marker })),
    ];
    const status = ambiguous.length > 0 ? 'held_for_review' : 'ready';
    const counts: Record<string, number> = {};
    for (const r of [redactedBody, redactedSubject]) {
      for (const [k, v] of Object.entries(r.counts)) counts[k] = (counts[k] ?? 0) + (v ?? 0);
    }
    const msg = await tx.query(
      `INSERT INTO messages (original_id, source, thread_key, case_id, sender_placeholder, subject, body, received_at,
                             status, redaction_summary, held_reasons)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11::jsonb) RETURNING id`,
      [
        original.rows[0].id,
        raw.source,
        raw.threadKey,
        opts.caseId ?? null,
        senderPlaceholder,
        redactedSubject.text,
        redactedBody.text,
        raw.receivedAt,
        status,
        JSON.stringify({ counts, placeholders: [...new Set([...redactedBody.placeholders, ...redactedSubject.placeholders])] }),
        JSON.stringify(ambiguous),
      ],
    );
    await tx.query(`INSERT INTO audit_log (actor, action, target, details) VALUES ('intake', 'message.ingest', $1, $2::jsonb)`, [
      msg.rows[0].id,
      JSON.stringify({ source: raw.source, status, redactions: counts }),
    ]);
    return { messageId: msg.rows[0].id, created: true, status };
  });
}

/** Synthetic thread → sample case reference (sample-data mode). */
const SAMPLE_CASE_FOR_THREAD: Record<string, string> = {
  'thread-login-loop': 'SAMPLE-001',
  'thread-csv-export': 'SAMPLE-002',
  'thread-invoice': 'SAMPLE-004',
  'thread-photo-crash': 'SAMPLE-005',
  'thread-pasted-secrets': 'SAMPLE-006',
  'thread-hidden-injection': 'SAMPLE-007',
};

export async function ingestSynthetic(pool: Pool, mk: MasterKey): Promise<(IngestResult & { sourceId: string })[]> {
  const results: (IngestResult & { sourceId: string })[] = [];
  for (const m of SYNTHETIC_MESSAGES) {
    const ref = SAMPLE_CASE_FOR_THREAD[m.threadKey];
    const c = ref ? await pool.query(`SELECT id FROM cases WHERE reference = $1`, [ref]) : null;
    results.push({ sourceId: m.sourceId, ...(await ingestMessage(pool, mk, m, { caseId: c?.rows[0]?.id ?? null })) });
  }
  return results;
}
