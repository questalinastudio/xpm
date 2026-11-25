import type { Queryable } from '@xpm/core';

/** Fictional cases for sample-data mode. No real customer data. */
const SAMPLE_CASES = [
  {
    reference: 'SAMPLE-001',
    title: 'Portal login loop after password reset',
    kind: 'bug',
    status: 'open',
    summary: 'Sample: a customer reports returning to the login page after resetting their password.',
  },
  {
    reference: 'SAMPLE-002',
    title: 'Request: export quest history as CSV',
    kind: 'feature',
    status: 'in_discussion',
    summary: 'Sample: a customer asks for a CSV export of their history from the mobile app.',
  },
  {
    reference: 'SAMPLE-003',
    title: 'Does the app support family accounts?',
    kind: 'product_question',
    status: 'awaiting_owner',
    summary: 'Sample: a prospective customer asks whether several people can share one subscription.',
  },
  {
    reference: 'SAMPLE-004',
    title: 'Vendor invoice for October',
    kind: 'routine',
    status: 'closed',
    summary: 'Sample: non-product correspondence that should not start a technical discussion.',
  },
  {
    reference: 'SAMPLE-005',
    title: 'App crashes when uploading a photo',
    kind: 'bug',
    status: 'open',
    summary: 'Sample: SMS report of a crash, containing a prompt-injection attempt.',
  },
  {
    reference: 'SAMPLE-006',
    title: 'Customer integration failing with 401',
    kind: 'bug',
    status: 'open',
    summary: 'Sample: the customer pasted credentials, which intake must redact.',
  },
  {
    reference: 'SAMPLE-007',
    title: 'Export button does nothing in Safari',
    kind: 'bug',
    status: 'open',
    summary: 'Sample: hidden HTML injection and an ambiguous account number (held for review).',
  },
];

const SAMPLE_KNOWLEDGE = [
  {
    title: 'Quest history',
    body: 'Customers can view completed quests and their dates on the history page in the portal and mobile app. There is no export today.',
    status: 'approved',
  },
  {
    title: 'Password reset flow',
    body: 'Password reset sends an email link. After reset, the customer is signed in automatically on the device used to reset.',
    status: 'proposal',
  },
];

export async function seedSampleData(db: Queryable): Promise<number> {
  let inserted = 0;
  for (const c of SAMPLE_CASES) {
    const r = await db.query(
      `INSERT INTO cases (reference, title, kind, status, summary, is_sample)
       VALUES ($1, $2, $3, $4, $5, true) ON CONFLICT (reference) DO NOTHING`,
      [c.reference, c.title, c.kind, c.status, c.summary],
    );
    inserted += r.rowCount ?? 0;
  }
  for (const k of SAMPLE_KNOWLEDGE) {
    const exists = await db.query(`SELECT 1 FROM knowledge_entries WHERE title = $1 AND is_sample`, [k.title]);
    if (exists.rowCount === 0) {
      await db.query(
        `INSERT INTO knowledge_entries (title, body, status, provenance, is_sample) VALUES ($1, $2, $3, '{"source":"sample"}', true)`,
        [k.title, k.body, k.status],
      );
    }
  }
  const brief = await db.query(`SELECT id FROM cases WHERE reference = 'SAMPLE-002'`);
  const briefExists = await db.query(`SELECT 1 FROM case_briefs WHERE case_id = $1`, [brief.rows[0]?.id]);
  if (brief.rows[0] && briefExists.rowCount === 0) {
    await db.query(`INSERT INTO case_briefs (case_id, body) VALUES ($1, $2)`, [
      brief.rows[0].id,
      'Customers ask for a CSV export of quest history with dates and completion status. Determine where history is stored and how an export could be added.',
    ]);
  }
  return inserted;
}

export async function clearSampleData(db: Queryable): Promise<number> {
  await db.query(`DELETE FROM knowledge_entries WHERE is_sample`);
  await db.query(`DELETE FROM case_briefs WHERE case_id IN (SELECT id FROM cases WHERE is_sample)`);
  const r = await db.query(`DELETE FROM cases WHERE is_sample AND id NOT IN (SELECT case_id FROM messages WHERE case_id IS NOT NULL)
       AND id NOT IN (SELECT case_id FROM agent_turns WHERE case_id IS NOT NULL)`);
  return r.rowCount ?? 0;
}
