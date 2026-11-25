import { setTimeout as delay } from 'node:timers/promises';
import type { Logger } from '@xpm/core';

/**
 * Agent runtime: the tool loop for one role (PM or dev manager).
 *
 * It runs in an empty, read-only container. Its only capabilities are HTTP
 * calls to the gateway with its role token. It cannot choose its system
 * instructions or tool list (the gateway composes those), has no database,
 * filesystem data, shell, or network route other than the gateway, and has
 * no sending capability of any kind.
 */

interface ChatMessage {
  role: 'user' | 'assistant' | 'tool';
  content: string | null;
  toolCalls?: { id: string; name: string; arguments: unknown }[];
  toolCallId?: string;
}

export interface RuntimeOptions {
  gatewayUrl: string;
  token: string;
  runtimeId: string;
  log: Logger;
  pollMs?: number;
  maxSteps?: number;
}

class GatewayError extends Error {
  constructor(readonly status: number, readonly body: Record<string, unknown>) {
    super(`gateway ${status}: ${String(body.error ?? '')} ${String(body.message ?? '')}`.trim());
  }
}

export class AgentRuntime {
  private running = false;
  private loop?: Promise<void>;
  private readonly wake = new AbortController();

  constructor(private readonly opts: RuntimeOptions) {}

  private async post(path: string, body: unknown): Promise<{ status: number; data: Record<string, unknown> }> {
    const res = await fetch(`${this.opts.gatewayUrl}${path}`, {
      method: 'POST',
      headers: { authorization: `Bearer ${this.opts.token}`, 'content-type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(180_000),
    });
    const data = res.status === 204 ? {} : ((await res.json().catch(() => ({}))) as Record<string, unknown>);
    return { status: res.status, data };
  }

  start(): void {
    this.running = true;
    this.loop = this.run();
  }

  async stop(): Promise<void> {
    this.running = false;
    this.wake.abort();
    await this.loop;
  }

  private async run(): Promise<void> {
    while (this.running) {
      try {
        const worked = await this.runOne();
        if (!worked) await delay(this.opts.pollMs ?? 2000, undefined, { signal: this.wake.signal }).catch(() => {});
      } catch (err) {
        this.opts.log.error({ err }, 'runtime loop error');
        await delay(5000, undefined, { signal: this.wake.signal }).catch(() => {});
      }
    }
  }

  /** Claim and run one turn. Returns false when no work was available. */
  async runOne(): Promise<boolean> {
    const claim = await this.post('/v1/turns/claim', { runtimeId: this.opts.runtimeId });
    if (claim.status === 204) return false;
    if (claim.status !== 200) throw new GatewayError(claim.status, claim.data);
    const turn = claim.data.turn as { id: string; purpose: string };
    const ticket = claim.data.ticket as string;
    const log = this.opts.log.child({ turnId: turn.id });
    log.info({ purpose: turn.purpose }, 'turn claimed');

    try {
      const result = await this.toolLoop(turn.id, ticket, claim.data.opening as string, log);
      const done = await this.post(`/v1/turns/${turn.id}/complete`, { ticket, ...result });
      if (done.status === 409) log.warn('turn result rejected as stale');
      else if (done.status !== 200) throw new GatewayError(done.status, done.data);
      else log.info('turn completed');
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      log.warn({ err: { message } }, 'turn failed');
      await this.post(`/v1/turns/${turn.id}/fail`, { ticket, error: message }).catch(() => {});
    }
    return true;
  }

  private async toolLoop(turnId: string, ticket: string, opening: string, log: Logger): Promise<{ output: unknown; decisionSummary: unknown }> {
    const messages: ChatMessage[] = [{ role: 'user', content: opening }];
    for (let step = 0; step < (this.opts.maxSteps ?? 8); step++) {
      const res = await this.post('/v1/llm', { turnId, ticket, messages });
      if (res.status !== 200) throw new GatewayError(res.status, res.data);
      const content = (res.data.content as string | null) ?? null;
      const toolCalls = (res.data.toolCalls as ChatMessage['toolCalls']) ?? [];
      messages.push({ role: 'assistant', content, toolCalls });
      if (toolCalls.length === 0) {
        const parsed = JSON.parse(content ?? '') as { output: unknown; decisionSummary: unknown };
        return parsed;
      }
      for (const call of toolCalls) {
        const t = await this.post('/v1/tools/call', { turnId, ticket, llmCallId: res.data.llmCallId, name: call.name, arguments: call.arguments });
        if (t.status !== 200) throw new GatewayError(t.status, t.data);
        log.info({ tool: call.name, status: t.data.status }, 'tool call');
        messages.push({ role: 'tool', toolCallId: call.id, content: t.data.content as string });
      }
    }
    throw new Error('Turn exceeded the maximum number of model steps');
  }
}
