import { z } from 'zod';
import type { MasterKey, Pool } from '@xpm/core';
import { canonicalIdentity } from '@xpm/privacy';
import { identityHmac, ingestMessage, type IngestResult } from './vault.js';

/**
 * Manual SMS entry: the owner pastes a text from their iPhone. It follows the
 * same intake contract and privacy pipeline as email. Future SMS providers
 * submit the same shape.
 */
export const smsSubmissionSchema = z.object({
  /** Client-generated id; repeated submissions of the same form are imported once. */
  submissionId: z.string().uuid(),
  from: z.string().min(3).max(40).refine((v) => v.replace(/\D/g, '').length >= 7, 'Sender must be a phone number'),
  fromName: z.string().max(120).optional(),
  text: z.string().min(1).max(10_000),
  receivedAt: z.string().datetime({ offset: true }),
  context: z.string().max(2_000).optional(),
});

export type SmsSubmission = z.infer<typeof smsSubmissionSchema>;

export async function ingestSms(pool: Pool, mk: MasterKey, sub: SmsSubmission): Promise<IngestResult> {
  const phone = canonicalIdentity('phone', sub.from);
  // Thread key groups texts by sender without storing the number.
  const threadKey = `sms:${identityHmac(mk, 'phone', phone).slice(0, 16)}`;
  const text = sub.context?.trim() ? `${sub.text}\n\n[Owner note] ${sub.context.trim()}` : sub.text;
  return ingestMessage(
    pool,
    mk,
    {
      source: 'sms',
      sourceId: `manual:${sub.submissionId}`,
      threadKey,
      receivedAt: new Date(sub.receivedAt).toISOString(),
      from: { name: sub.fromName, address: sub.from },
      to: [],
      text,
    },
    { metadata: { channel: 'manual_sms', likelyCustomer: true } },
  );
}
