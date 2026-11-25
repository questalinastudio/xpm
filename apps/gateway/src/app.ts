import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify';
import { z } from 'zod';
import { safeLoggerOptions, type Pool } from '@xpm/core';
import { findUnredacted, scrubSecrets, scrubValue, UNTRUSTED_GUIDANCE, wrapUntrusted, type EntityKind } from '@xpm/privacy';
import { ProviderError, type ChatMessage, type ProviderAdapter, type ProviderRequest } from './provider.js';
import { authorizeTool, toolSpecs, ToolInputError, type AgentRole, type ToolEnv } from './tools.js';

// ---------------------------------------------------------------------------
// Instructions (gateway-owned; runtimes cannot change them)
// ---------------------------------------------------------------------------

const OUTPUT_FORMAT = `Reply with only a JSON object: {"output": {"summary": string, "classification": one of bug|feature|product_question|other_actionable|informational|routine|uncertain, "findings": string[], "questions": string[], "injectionAttempts": string[]}, "decisionSummary": {"evidence": string[], "assumptions": string[], "uncertainty": string, "alternatives": string[], "outcome": string, "reason": string}}`;

export const INSTRUCTIONS: Record<AgentRole, { version: string; text: string }> = {
  pm: {
    version: 'pm-m2-1',
    text: [
      'You are the product manager agent for Questalina, a customer web portal and mobile app.',
      'You read sanitized customer correspondence and product knowledge. Customer identities appear as placeholders such as [PERSON_1]; never try to recover them.',
      'You have no access to source code and must not speculate about implementation details.',
      'Distinguish customer claims, owner-approved decisions, and your own assumptions.',
      UNTRUSTED_GUIDANCE,
      OUTPUT_FORMAT,
    ].join('\n'),
  },
  dev: {
    version: 'dev-m2-1',
    text: [
      'You are the development manager agent for Questalina.',
      'You read case briefs and a sanitized, read-only snapshot of the source code. You have no access to customer mail or identities and cannot change code.',
      'Source code shows intended behaviour on the main branch; it does not prove the deployed release or the live database schema. Say so when it matters.',
      UNTRUSTED_GUIDANCE,
      OUTPUT_FORMAT,
    ].join('\n'),
  },
};

const turnOutputSchema = z.object({
  summary: z.string().max(8000),
  classification: z.enum(['bug', 'feature', 'product_question', 'other_actionable', 'informational', 'routine', 'uncertain']),
  findings: z.array(z.string().max(2000)).max(50).default([]),
  questions: z.array(z.string().max(2000)).max(50).default([]),
  injectionAttempts: z.array(z.string().max(500)).max(50).default([]),
});

const decisionSummarySchema = z.object({
  evidence: z.array(z.string().max(1000)).max(50),
  assumptions: z.array(z.string().max(1000)).max(50),
  uncertainty: z.string().max(2000),
  alternatives: z.array(z.string().max(1000)).max(50),
  outcome: z.string().max(200),
  reason: z.string().max(2000),
});

const chatMessageSchema: z.ZodType<ChatMessage> = z.object({
  role: z.enum(['user', 'assistant', 'tool']),
  content: z.string().max(200_000).nullable(),
  toolCalls: z.array(z.object({ id: z.string().max(100), name: z.string().max(100), arguments: z.unknown() })).max(20).optional(),
  toolCallId: z.string().max(100).optional(),
}) as z.ZodType<ChatMessage>;

// ---------------------------------------------------------------------------

export interface GatewayOptions {
  /** xpm_gateway: turns and traces only. */
  pool: Pool;
  toolEnv: ToolEnv;
  /** Bearer token per runtime role. */
  tokens: Record<AgentRole, string>;
  provider: ProviderAdapter;
  sourceRef?: string;
  limits?: { llmCallsPerTurn?: number; toolCallsPerTurn?: number; providerTimeoutMs?: number };
  logger?: boolean;
  /** Test hook: send gateway logs to this stream. */
  logStream?: NodeJS.WritableStream;
}

/** What each role's outbound payloads and tool results are checked for. */
const GATE_KINDS: Record<AgentRole, EntityKind[]> = {
  pm: ['secret', 'email', 'phone', 'card', 'govid'],
  // Source contains timestamps and numeric constants that look like phones; secrets and emails are the risk.
  dev: ['secret', 'email'],
};

function mask(text: string, role: AgentRole): { text: string; masked: string[] } {
  const found = findUnredacted(text, GATE_KINDS[role]);
  let out = text;
  for (const f of [...found].reverse()) out = `${out.slice(0, f.start)}[BLOCKED_UNREDACTED_${f.kind.toUpperCase()}]${out.slice(f.end)}`;
  return { text: out, masked: found.map((f) => f.kind) };
}

function maskValue<T>(value: T, role: AgentRole): { value: T; masked: string[] } {
  const r = mask(JSON.stringify(value), role);
  return { value: JSON.parse(r.text) as T, masked: r.masked };
}

const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');

interface TurnRow {
  id: string;
  logical_key: string;
  attempt_no: number;
  agent_role: AgentRole;
  purpose: string;
  case_id: string | null;
  discussion_id: string | null;
  round: number | null;
  input: { question?: string };
  deadline_at: Date;
}

export async function buildGateway(opts: GatewayOptions): Promise<FastifyInstance> {
  const { pool, provider } = opts;
  const maxLlm = opts.limits?.llmCallsPerTurn ?? 8;
  const maxTools = opts.limits?.toolCallsPerTurn ?? 24;
  const providerTimeoutMs = opts.limits?.providerTimeoutMs ?? 120_000;

  const app = Fastify({
    logger: opts.logStream ? { ...safeLoggerOptions('gateway'), stream: opts.logStream } : opts.logger ? safeLoggerOptions('gateway') : false,
    bodyLimit: 2 * 1024 * 1024,
    forceCloseConnections: true,
  });

  // -------------------------------------------------------------------------
  // Runtime authentication: token → role. A runtime can act only as its role.
  // -------------------------------------------------------------------------
  const tokenHashes = Object.entries(opts.tokens).map(([role, token]) => ({ role: role as AgentRole, hash: Buffer.from(sha256(token), 'hex') }));
  function roleOf(req: FastifyRequest): AgentRole | null {
    const header = req.headers.authorization;
    if (!header?.startsWith('Bearer ')) return null;
    const presented = Buffer.from(sha256(header.slice(7)), 'hex');
    return tokenHashes.find((t) => timingSafeEqual(t.hash, presented))?.role ?? null;
  }

  app.decorateRequest('agentRole', null);
  app.addHook('preHandler', async (req, reply) => {
    if (req.url === '/healthz') return;
    const role = roleOf(req);
    if (!role) return reply.code(401).send({ error: 'unauthorized' });
    (req as FastifyRequest & { agentRole: AgentRole }).agentRole = role;
  });
  const roleFor = (req: FastifyRequest) => (req as FastifyRequest & { agentRole: AgentRole }).agentRole;

  app.setErrorHandler((err: { statusCode?: number; message: string }, req, reply) => {
    const status = err.statusCode && err.statusCode < 500 ? err.statusCode : 500;
    req.log.error({ err: { message: scrubSecrets(err.message) } }, 'gateway error');
    reply.code(status).send({ error: status === 500 ? 'internal_error' : 'bad_request', message: status === 500 ? 'Internal error' : scrubSecrets(err.message) });
  });

  /** Fenced turn lookup: right role, still claimed, matching ticket, before deadline. */
  async function activeTurn(turnId: string, ticket: string, role: AgentRole): Promise<TurnRow | null> {
    const { rows } = await pool.query(
      `SELECT * FROM agent_turns WHERE id = $1 AND agent_role = $2 AND status = 'claimed' AND ticket_hash = $3 AND deadline_at > now()`,
      [turnId, role, sha256(ticket)],
    );
    return rows[0] ?? null;
  }

  const stale = (reply: FastifyReply) =>
    reply.code(409).send({ error: 'stale_turn', message: 'Turn is not active for this ticket (finished, superseded, cancelled, or past its deadline)' });

  app.get('/healthz', async () => ({ status: 'ok' }));

  // -------------------------------------------------------------------------
  // Claim the next turn for this runtime's role
  // -------------------------------------------------------------------------
  app.post('/v1/turns/claim', async (req, reply) => {
    const role = roleFor(req);
    const body = z.object({ runtimeId: z.string().max(100) }).safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: 'bad_request' });
    const ticket = randomBytes(32).toString('base64url');
    const { rows } = await pool.query(
      `UPDATE agent_turns SET status = 'claimed', ticket_hash = $2, runtime_id = $3, claimed_at = now()
       WHERE id = (SELECT id FROM agent_turns WHERE status = 'queued' AND agent_role = $1 AND deadline_at > now()
                   ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1)
       RETURNING *`,
      [role, sha256(ticket), body.data.runtimeId],
    );
    const turn: TurnRow | undefined = rows[0];
    if (!turn) return reply.code(204).send();
    const opening = [
      `Task: ${turn.purpose}.`,
      turn.input.question ? wrapUntrusted('task question', turn.input.question) : '',
      `Use your tools to gather what you need, then answer in the required JSON format.`,
    ]
      .filter(Boolean)
      .join('\n\n');
    return { turn: { id: turn.id, purpose: turn.purpose, attemptNo: turn.attempt_no }, ticket, opening };
  });

  // -------------------------------------------------------------------------
  // Model calls: gateway composes, gates, traces, and dispatches
  // -------------------------------------------------------------------------
  app.post('/v1/llm', async (req, reply) => {
    const role = roleFor(req);
    const body = z.object({ turnId: z.string().uuid(), ticket: z.string().max(100), messages: z.array(chatMessageSchema).min(1).max(200) }).safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: 'bad_request', message: 'Invalid model request' });
    const turn = await activeTurn(body.data.turnId, body.data.ticket, role);
    if (!turn) return stale(reply);

    const reserved = await pool.query(
      `UPDATE agent_turns SET llm_call_count = llm_call_count + 1
       WHERE id = $1 AND status = 'claimed' AND ticket_hash = $2 AND llm_call_count < $3 RETURNING llm_call_count`,
      [turn.id, sha256(body.data.ticket), maxLlm],
    );
    if (!reserved.rows[0]) return reply.code(429).send({ error: 'call_limit', message: `Turn reached its limit of ${maxLlm} model calls` });
    const seq: number = reserved.rows[0].llm_call_count;

    const instructions = INSTRUCTIONS[role];
    const request: ProviderRequest = {
      model: provider.model,
      system: instructions.text,
      messages: body.data.messages,
      tools: toolSpecs(role),
      parameters: { temperature: 0.2, maxOutputTokens: 4000 },
    };
    const base = [
      turn.id, seq, role, role === 'pm' ? 'product' : 'technical', turn.logical_key, turn.attempt_no, turn.case_id,
      turn.discussion_id, turn.round, turn.purpose, provider.name, provider.model, instructions.version,
    ];

    // Defense in depth: nothing unredacted leaves, whatever the runtime sent.
    const gated = maskValue(request, role);
    if (gated.masked.length > 0) {
      const { rows } = await pool.query(
        `INSERT INTO llm_calls (turn_id, seq, agent_role, sensitivity, logical_key, attempt_no, case_id, discussion_id, round, purpose,
                                provider, model, instruction_version, request, tools_available, parameters, context_versions,
                                status, validation, finished_at, error)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb,$15::jsonb,$16::jsonb,$17::jsonb,'blocked',$18::jsonb, now(),
                 'Payload contained unredacted data; not sent')
         RETURNING id`,
        [...base, JSON.stringify(gated.value), JSON.stringify(request.tools), JSON.stringify(request.parameters),
          JSON.stringify({ sourceRef: opts.sourceRef ?? null }), JSON.stringify({ blocked: gated.masked })],
      );
      return reply.code(422).send({ error: 'unsanitized_payload', llmCallId: rows[0].id, kinds: [...new Set(gated.masked)] });
    }

    // Persist the exact outbound payload BEFORE dispatch, so a crash leaves a visible pending call.
    const { rows } = await pool.query(
      `INSERT INTO llm_calls (turn_id, seq, agent_role, sensitivity, logical_key, attempt_no, case_id, discussion_id, round, purpose,
                              provider, model, instruction_version, request, tools_available, parameters, context_versions)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb,$15::jsonb,$16::jsonb,$17::jsonb) RETURNING id`,
      [...base, JSON.stringify(request), JSON.stringify(request.tools), JSON.stringify(request.parameters), JSON.stringify({ sourceRef: opts.sourceRef ?? null })],
    );
    const llmCallId: string = rows[0].id;
    const started = performance.now();
    try {
      // Never wait past the turn's deadline: the worker abandons the turn then anyway.
      const remaining = Math.max(1000, new Date(turn.deadline_at).getTime() - Date.now());
      const res = await provider.call(request, AbortSignal.timeout(Math.min(providerTimeoutMs, remaining)));
      const clean = scrubValue(res);
      const masked = maskValue(clean, role);
      await pool.query(
        `UPDATE llm_calls SET status = 'succeeded', response = $2::jsonb, tool_requests = $3::jsonb, provider_request_id = $4,
                latency_ms = $5, usage = $6::jsonb, validation = $7::jsonb, finished_at = now()
         WHERE id = $1 AND status = 'pending'`,
        [llmCallId, JSON.stringify({ content: masked.value.content, model: res.model }), JSON.stringify(masked.value.toolCalls),
          res.requestId ?? null, Math.round(performance.now() - started), JSON.stringify(res.usage ?? null),
          JSON.stringify({ maskedInResponse: masked.masked })],
      );
      return { llmCallId, content: masked.value.content, toolCalls: masked.value.toolCalls };
    } catch (err) {
      const message = scrubSecrets(err instanceof Error ? err.message : String(err));
      await pool.query(
        `UPDATE llm_calls SET status = 'failed', error = $2, latency_ms = $3, finished_at = now() WHERE id = $1 AND status = 'pending'`,
        [llmCallId, message, Math.round(performance.now() - started)],
      );
      const retryable = !(err instanceof ProviderError) || err.retryable;
      return reply.code(502).send({ error: 'provider_error', llmCallId, message, retryable });
    }
  });

  // -------------------------------------------------------------------------
  // Tool calls: authorize by role, validate, execute, gate, trace
  // -------------------------------------------------------------------------
  app.post('/v1/tools/call', async (req, reply) => {
    const role = roleFor(req);
    const body = z
      .object({ turnId: z.string().uuid(), ticket: z.string().max(100), llmCallId: z.string().uuid().optional(), name: z.string().max(100), arguments: z.unknown() })
      .safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: 'bad_request', message: 'Invalid tool request' });
    const turn = await activeTurn(body.data.turnId, body.data.ticket, role);
    if (!turn) return stale(reply);

    const reserved = await pool.query(
      `UPDATE agent_turns SET tool_call_count = tool_call_count + 1
       WHERE id = $1 AND status = 'claimed' AND ticket_hash = $2 AND tool_call_count < $3 RETURNING tool_call_count`,
      [turn.id, sha256(body.data.ticket), maxTools],
    );
    if (!reserved.rows[0]) return reply.code(429).send({ error: 'call_limit', message: `Turn reached its limit of ${maxTools} tool calls` });
    const seq: number = reserved.rows[0].tool_call_count;
    const sensitivity = role === 'pm' ? 'product' : 'technical';
    const args = maskValue(scrubValue(body.data.arguments ?? {}), role).value;
    const insert = (authz: string, status: string, extra: { denial?: string; error?: string } = {}) =>
      pool.query(
        `INSERT INTO tool_calls (turn_id, llm_call_id, seq, agent_role, sensitivity, tool, arguments, authz, denial_reason, status, error,
                                 finished_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10,$11, CASE WHEN $10 = 'pending' THEN NULL ELSE now() END) RETURNING id`,
        [turn.id, body.data.llmCallId ?? null, seq, role, sensitivity, body.data.name.slice(0, 100), JSON.stringify(args), authz,
          extra.denial ?? null, status, extra.error ?? null],
      );

    const auth = authorizeTool(role, body.data.name);
    if (!auth.ok) {
      await insert('denied', 'denied', { denial: auth.reason });
      return { status: 'denied', content: JSON.stringify({ error: 'tool_denied', tool: body.data.name, reason: auth.reason }) };
    }
    const parsed = auth.tool.schema.safeParse(body.data.arguments ?? {});
    if (!parsed.success) {
      await insert('allowed', 'failed', { error: 'invalid arguments' });
      return { status: 'error', content: JSON.stringify({ error: 'invalid_arguments', tool: auth.tool.name }) };
    }
    const { rows } = await insert('allowed', 'pending');
    const toolCallId: string = rows[0].id;
    try {
      const result = await auth.tool.run({ id: turn.id, role, caseId: turn.case_id }, parsed.data as never, opts.toolEnv);
      const gated = maskValue(scrubValue(result.content), role);
      await pool.query(
        `UPDATE tool_calls SET status = 'succeeded', result = $2::jsonb, evidence_refs = $3::jsonb, finished_at = now() WHERE id = $1`,
        [toolCallId, JSON.stringify({ content: gated.value, maskedUnredacted: gated.masked }), JSON.stringify(result.evidenceRefs)],
      );
      return { status: 'ok', content: wrapUntrusted(`tool result ${auth.tool.name}`, JSON.stringify(gated.value)), evidenceRefs: result.evidenceRefs };
    } catch (err) {
      const message = err instanceof ToolInputError ? err.message : `Tool failed: ${scrubSecrets((err as Error).message)}`;
      await pool.query(`UPDATE tool_calls SET status = 'failed', error = $2, finished_at = now() WHERE id = $1`, [toolCallId, message]);
      return { status: 'error', content: JSON.stringify({ error: 'tool_error', message }) };
    }
  });

  // -------------------------------------------------------------------------
  // Finish a turn (fenced by ticket)
  // -------------------------------------------------------------------------
  app.post('/v1/turns/:id/complete', async (req, reply) => {
    const role = roleFor(req);
    const id = z.string().uuid().safeParse((req.params as { id: string }).id);
    const body = z.object({ ticket: z.string().max(100), output: turnOutputSchema, decisionSummary: decisionSummarySchema }).safeParse(req.body);
    if (!id.success || !body.success) return reply.code(422).send({ error: 'invalid_output', message: 'Output does not match the required format' });
    const turn = await activeTurn(id.data, body.data.ticket, role);
    if (!turn) return stale(reply);
    const output = maskValue(scrubValue(body.data.output), role);
    const decision = maskValue(scrubValue(body.data.decisionSummary), role);
    const { rowCount } = await pool.query(
      `UPDATE agent_turns SET status = 'succeeded', output = $3::jsonb, decision_summary = $4::jsonb, finished_at = now()
       WHERE id = $1 AND ticket_hash = $2 AND status = 'claimed'`,
      [id.data, sha256(body.data.ticket), JSON.stringify(output.value), JSON.stringify(decision.value)],
    );
    if (rowCount !== 1) return stale(reply);
    return { ok: true };
  });

  app.post('/v1/turns/:id/fail', async (req, reply) => {
    const role = roleFor(req);
    const id = z.string().uuid().safeParse((req.params as { id: string }).id);
    const body = z.object({ ticket: z.string().max(100), error: z.string().max(4000) }).safeParse(req.body);
    if (!id.success || !body.success) return reply.code(400).send({ error: 'bad_request' });
    const turn = await activeTurn(id.data, body.data.ticket, role);
    if (!turn) return stale(reply);
    await pool.query(
      `UPDATE agent_turns SET status = 'failed', error = $3, finished_at = now() WHERE id = $1 AND ticket_hash = $2 AND status = 'claimed'`,
      [id.data, sha256(body.data.ticket), scrubSecrets(body.data.error)],
    );
    return { ok: true };
  });

  return app;
}
