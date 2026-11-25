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
  return inserted;
}

export async function clearSampleData(db: Queryable): Promise<number> {
  const r = await db.query(`DELETE FROM cases WHERE is_sample`);
  return r.rowCount ?? 0;
}
