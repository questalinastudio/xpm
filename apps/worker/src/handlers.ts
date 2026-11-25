import { setTimeout as delay } from 'node:timers/promises';
import { PermanentJobError, type JobHandler } from '@xpm/core';

interface DemoPayload {
  seconds?: number;
}

/**
 * Demonstration handlers for sample-data mode. Real intake, agent, and send
 * handlers arrive in later milestones and register here the same way.
 */
export const demoHandlers: Record<string, JobHandler<DemoPayload>> = {
  'demo.echo': async ({ job }) => ({ result: { echoed: job.payload, at: new Date().toISOString() } }),

  'demo.sleep': async ({ job, signal }) => {
    const seconds = Math.min(job.payload.seconds ?? 5, 600);
    await delay(seconds * 1000, undefined, { signal });
    return { result: { sleptSeconds: seconds } };
  },

  // Fails on its first two attempts, then succeeds: shows retry with backoff.
  'demo.fail': async ({ job }) => {
    if (job.attempts < 3) throw new Error(`simulated transient failure on attempt ${job.attempts}`);
    return { result: { succeededOnAttempt: job.attempts } };
  },

  'demo.fail_permanent': async () => {
    throw new PermanentJobError('simulated permanent failure');
  },
};
