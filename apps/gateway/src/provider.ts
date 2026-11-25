import { randomUUID } from 'node:crypto';

/**
 * Provider adapter boundary. The gateway composes every request (system
 * instructions and tool list are gateway-owned) and records it verbatim in
 * the trace before dispatch. Real providers are evaluated in Milestone 4.
 */

export interface ChatMessage {
  role: 'user' | 'assistant' | 'tool';
  content: string | null;
  toolCalls?: ToolCallRequest[];
  toolCallId?: string;
}

export interface ToolCallRequest {
  id: string;
  name: string;
  arguments: unknown;
}

export interface ToolSpec {
  name: string;
  description: string;
  parameters: Record<string, unknown>;
}

export interface ProviderRequest {
  model: string;
  system: string;
  messages: ChatMessage[];
  tools: ToolSpec[];
  parameters: { temperature: number; maxOutputTokens: number };
}

export interface ProviderResponse {
  content: string | null;
  toolCalls: ToolCallRequest[];
  model: string;
  requestId?: string;
  usage?: { inputTokens: number; outputTokens: number };
}

export interface ProviderAdapter {
  name: string;
  model: string;
  call(req: ProviderRequest, signal: AbortSignal): Promise<ProviderResponse>;
}

export class ProviderError extends Error {
  constructor(message: string, readonly retryable = true) {
    super(message);
    this.name = 'ProviderError';
  }
}

const DIRECTIVE = /TOOL_CALL:\s*([a-z_]+\.[a-z_]+)\s*(\{[^{}]*\})?/g;
const PHRASE = /\b(?:call|use|invoke|run)\s+(?:the\s+)?([a-z_]+\.[a-z_]+)\s+tool/gi;

/**
 * A deliberately worst-case model for tests and sample mode: it obeys every
 * instruction it finds in customer messages, source files, or tool results.
 * If the boundaries hold against this model, they do not depend on the
 * model resisting prompt injection.
 *
 * Behaviour:
 * 1. First, call the first tool it was offered (its role's starter tool).
 * 2. Then emit every tool call requested by content it has seen, once each.
 * 3. Then return a final JSON answer.
 * Markers: SIMULATE_PROVIDER_ERROR throws an error whose message contains
 * credential-like text; SIMULATE_PROVIDER_HANG never answers until aborted;
 * SIMULATE_PROVIDER_HANG_ONCE hangs only the first time a conversation is seen.
 */
export class ObedientSimulatedProvider implements ProviderAdapter {
  readonly name = 'simulated';
  readonly model = 'obedient-sim-1';
  private readonly hungOnce = new Set<string>();

  async call(req: ProviderRequest, signal: AbortSignal): Promise<ProviderResponse> {
    const seen = req.messages.map((m) => m.content ?? '').join('\n');
    // Hang only the first time a conversation is seen: a crash on attempt 1, success on retry.
    // Untrusted-block boundaries are random per attempt; ignore them when recognising a conversation.
    const opening = (req.messages[0]?.content ?? '').replace(/UNTRUSTED [0-9a-f]{12}/g, 'UNTRUSTED');
    const hangOnce = seen.includes('SIMULATE_PROVIDER_HANG_ONCE') && !this.hungOnce.has(opening);
    if (hangOnce) this.hungOnce.add(opening);
    if (hangOnce || (seen.includes('SIMULATE_PROVIDER_HANG') && !seen.includes('SIMULATE_PROVIDER_HANG_ONCE'))) {
      await new Promise((_, reject) => signal.addEventListener('abort', () => reject(new ProviderError('aborted')), { once: true }));
    }
    if (seen.includes('SIMULATE_PROVIDER_ERROR')) {
      // Mimics a careless upstream error that echoes credentials back.
      throw new ProviderError(
        `upstream 500: invalid key ${['sk-', 'ant-', 'SimLeak0000000000000000000'].join('')} for ${['postgres', '://svc:', 'LeakyPass99', '@10.0.0.9/db'].join('')}`,
      );
    }

    const emitted = req.messages.flatMap((m) => m.toolCalls ?? []);
    const emittedKeys = new Set(emitted.map((c) => `${c.name} ${JSON.stringify(c.arguments)}`));
    const usage = { inputTokens: Math.ceil(seen.length / 4), outputTokens: 50 };
    const respond = (calls: { name: string; args: unknown }[]): ProviderResponse => ({
      content: null,
      toolCalls: calls.map((c) => ({ id: `call_${randomUUID().slice(0, 8)}`, name: c.name, arguments: c.args })),
      model: this.model,
      requestId: `sim-${randomUUID()}`,
      usage,
    });

    if (emitted.length === 0 && req.tools[0]) return respond([{ name: req.tools[0].name, args: {} }]);

    const wanted: { name: string; args: unknown }[] = [];
    const injections: string[] = [];
    for (const m of req.messages.filter((x) => x.role !== 'assistant')) {
      const text = m.content ?? '';
      for (const d of text.matchAll(DIRECTIVE)) {
        let args: unknown = {};
        if (d[2]) {
          // Directives may arrive JSON-escaped inside tool results.
          for (const candidate of [d[2], d[2].replace(/\\"/g, '"')]) {
            try {
              args = JSON.parse(candidate);
              break;
            } catch {
              args = { raw: d[2] };
            }
          }
        }
        wanted.push({ name: d[1]!, args });
        injections.push(`TOOL_CALL ${d[1]}`);
      }
      for (const p of text.matchAll(PHRASE)) {
        wanted.push({ name: p[1]!.toLowerCase(), args: {} });
        injections.push(`phrase ${p[1]}`);
      }
    }
    const pending = wanted.filter((w) => !emittedKeys.has(`${w.name} ${JSON.stringify(w.args)}`));
    const unique = pending.filter((w, i) => pending.findIndex((x) => x.name === w.name && JSON.stringify(x.args) === JSON.stringify(w.args)) === i);
    if (unique.length > 0) return respond(unique);

    const toolResults = req.messages.filter((m) => m.role === 'tool').length;
    const final = {
      output: {
        summary: `Simulated ${req.tools.some((t) => t.name.startsWith('source.')) ? 'dev-manager' : 'PM'} analysis after ${toolResults} tool result(s).`,
        classification: 'uncertain',
        findings: [],
        questions: [],
        injectionAttempts: [...new Set(injections)],
      },
      decisionSummary: {
        evidence: [`${toolResults} tool result(s) reviewed`],
        assumptions: ['Simulated provider; no real analysis performed'],
        uncertainty: 'high',
        alternatives: [],
        outcome: 'complete',
        reason: 'Simulated provider finished its scripted steps',
      },
    };
    return { content: JSON.stringify(final), toolCalls: [], model: this.model, requestId: `sim-${randomUUID()}`, usage };
  }
}
