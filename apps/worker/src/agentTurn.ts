import { setTimeout as delay } from 'node:timers/promises';
import { withTx, type JobHandler, type Pool } from '@xpm/core';

export interface AgentTurnPayload {
  /** Logical turn key, e.g. `turn:{discussion}:{revision}:{round}:{speaker}`. */
  logicalKey: string;
  agentRole: 'pm' | 'dev';
  purpose: string;
  caseId?: string | null;
  discussionId?: string | null;
  round?: number | null;
  input?: { question?: string };
  deadlineSeconds?: number;
}

/**
 * Starts a fresh attempt of an agent turn and waits for a runtime to finish
 * it. Each job attempt is a new agent_turns row; earlier unfinished attempts
 * and their pending model/tool calls are marked abandoned, not deleted, so
 * the trace history shows exactly what happened.
 */
export function agentTurnHandler(pool: Pool, pollMs = 500): JobHandler<AgentTurnPayload> {
  return async ({ job, signal, log }) => {
    const p = job.payload;
    const deadlineSeconds = Math.min(Math.max(p.deadlineSeconds ?? 300, 5), 3600);
    const turnId = await withTx(pool, async (tx) => {
      const superseded = await tx.query(
        `UPDATE agent_turns SET status = 'abandoned', finished_at = now(),
                error = coalesce(error, 'superseded by attempt ' || $2::text)
         WHERE logical_key = $1 AND status IN ('queued', 'claimed') RETURNING id`,
        [p.logicalKey, job.attempts],
      );
      const ids = superseded.rows.map((r) => r.id);
      if (ids.length > 0) {
        await tx.query(
          `UPDATE llm_calls SET status = 'abandoned', finished_at = now(),
                  error = coalesce(error, 'turn attempt abandoned before the call completed')
           WHERE turn_id = ANY($1::uuid[]) AND status = 'pending'`,
          [ids],
        );
        await tx.query(
          `UPDATE tool_calls SET status = 'abandoned', finished_at = now() WHERE turn_id = ANY($1::uuid[]) AND status = 'pending'`,
          [ids],
        );
      }
      const { rows } = await tx.query(
        `INSERT INTO agent_turns (logical_key, attempt_no, agent_role, purpose, case_id, discussion_id, round, input, deadline_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, now() + ($9::int * interval '1 second'))
         ON CONFLICT (logical_key, attempt_no) DO UPDATE SET status = 'queued' -- unreachable: attempts are unique per claim
         RETURNING id`,
        [p.logicalKey, job.attempts, p.agentRole, p.purpose, p.caseId ?? null, p.discussionId ?? null, p.round ?? null,
          JSON.stringify(p.input ?? {}), deadlineSeconds],
      );
      return rows[0].id as string;
    });
    log.info({ turnId, logicalKey: p.logicalKey }, 'agent turn queued for runtime');

    for (;;) {
      if (signal.aborted) throw new Error(`turn wait aborted (${String(signal.reason)})`);
      const { rows } = await pool.query(`SELECT status, output, error, deadline_at < now() AS expired FROM agent_turns WHERE id = $1`, [turnId]);
      const t = rows[0];
      if (t.status === 'succeeded') return { result: { turnId, output: t.output } };
      if (t.status === 'failed') throw new Error(`agent turn failed: ${t.error ?? 'unknown error'}`);
      if (t.status === 'abandoned') throw new Error('agent turn was abandoned');
      if (t.expired) {
        await pool.query(
          `UPDATE agent_turns SET status = 'abandoned', finished_at = now(), error = 'deadline exceeded'
           WHERE id = $1 AND status IN ('queued', 'claimed')`,
          [turnId],
        );
        await pool.query(
          `UPDATE llm_calls SET status = 'abandoned', finished_at = now(), error = 'turn deadline exceeded' WHERE turn_id = $1 AND status = 'pending'`,
          [turnId],
        );
        throw new Error(`agent turn exceeded its ${deadlineSeconds}s deadline`);
      }
      await delay(pollMs, undefined, { signal }).catch(() => {});
    }
  };
}
