import { open, readdir, readFile, realpath, stat } from 'node:fs/promises';
import { join, sep } from 'node:path';
import { z } from 'zod';
import type { Pool } from '@xpm/core';
import type { ToolSpec } from './provider.js';

export type AgentRole = 'pm' | 'dev';

export interface TurnContext {
  id: string;
  role: AgentRole;
  caseId: string | null;
}

export interface ToolEnv {
  /** xpm_pm_tools: sanitized, cleared correspondence and product knowledge. */
  pmPool: Pool;
  /** xpm_dev_tools: case briefs. */
  devPool: Pool;
  /** Read-only sanitized source snapshot. */
  snapshotDir: string;
}

export interface ToolResult {
  content: unknown;
  evidenceRefs: string[];
}

export interface ToolDef {
  name: string;
  role: AgentRole;
  description: string;
  parameters: Record<string, unknown>;
  schema: z.ZodTypeAny;
  run(turn: TurnContext, args: never, env: ToolEnv): Promise<ToolResult>;
}

export class ToolInputError extends Error {}

// ---------------------------------------------------------------------------
// PM tools: sanitized correspondence and product knowledge. Never source.
// ---------------------------------------------------------------------------

const caseMessages: ToolDef = {
  name: 'case.messages',
  role: 'pm',
  description: 'Sanitized customer messages for the current case. Identities appear as placeholders.',
  parameters: { type: 'object', properties: {}, additionalProperties: false },
  schema: z.object({}).strict(),
  async run(turn, _args, env) {
    if (!turn.caseId) return { content: [], evidenceRefs: [] };
    const { rows } = await env.pmPool.query(
      `SELECT id, source, sender_placeholder, subject, body, received_at
       FROM pm_messages WHERE case_id = $1 ORDER BY received_at LIMIT 50`,
      [turn.caseId],
    );
    return {
      content: rows.map((r) => ({ id: r.id, source: r.source, from: r.sender_placeholder, subject: r.subject, body: r.body, receivedAt: r.received_at })),
      evidenceRefs: rows.map((r) => `message:${r.id}`),
    };
  },
};

const knowledgeSearch: ToolDef = {
  name: 'knowledge.search',
  role: 'pm',
  description: 'Search product knowledge (approved decisions and proposals). Returns product language, never source code.',
  parameters: { type: 'object', properties: { query: { type: 'string', minLength: 2, maxLength: 200 } }, required: ['query'], additionalProperties: false },
  schema: z.object({ query: z.string().min(2).max(200) }).strict(),
  async run(_turn, args: { query: string }, env) {
    const { rows } = await env.pmPool.query(
      `SELECT id, title, body, status FROM knowledge_entries
       WHERE status IN ('approved', 'proposal')
         AND to_tsvector('english', title || ' ' || body) @@ websearch_to_tsquery('english', $1)
       ORDER BY status = 'approved' DESC, updated_at DESC LIMIT 10`,
      [args.query],
    );
    return { content: rows, evidenceRefs: rows.map((r) => `knowledge:${r.id}`) };
  },
};

// ---------------------------------------------------------------------------
// Dev tools: case briefs and the read-only sanitized snapshot. Never mail.
// ---------------------------------------------------------------------------

const caseBrief: ToolDef = {
  name: 'case.brief',
  role: 'dev',
  description: 'The sanitized problem statement for the current case, written for engineering.',
  parameters: { type: 'object', properties: {}, additionalProperties: false },
  schema: z.object({}).strict(),
  async run(turn, _args, env) {
    if (!turn.caseId) return { content: [], evidenceRefs: [] };
    const { rows } = await env.devPool.query(`SELECT id, body, created_at FROM case_briefs WHERE case_id = $1 ORDER BY created_at`, [turn.caseId]);
    return { content: rows, evidenceRefs: rows.map((r) => `brief:${r.id}`) };
  },
};

const SAFE_REL_PATH = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[\w@.+\-/ ]{1,300}$/;

/** Resolve a snapshot-relative path, refusing traversal and anything outside the snapshot. */
async function resolveInSnapshot(root: string, rel: string): Promise<string> {
  if (!SAFE_REL_PATH.test(rel)) throw new ToolInputError('Path must be relative to the repository root, without ".."');
  const rootReal = await realpath(root);
  let real: string;
  try {
    real = await realpath(join(rootReal, rel));
  } catch {
    throw new ToolInputError(`No such file in the sanitized snapshot: ${rel}`);
  }
  if (real !== rootReal && !real.startsWith(rootReal + sep)) throw new ToolInputError('Path escapes the snapshot');
  return real;
}

async function* walkFiles(dir: string, root: string): AsyncGenerator<string> {
  for (const e of await readdir(dir, { withFileTypes: true })) {
    const abs = join(dir, e.name);
    if (e.isDirectory()) yield* walkFiles(abs, root);
    else if (e.isFile() && e.name !== '.snapshot-manifest.json') yield abs.slice(root.length + 1).split(sep).join('/');
  }
}

const sourceSearch: ToolDef = {
  name: 'source.search',
  role: 'dev',
  description: 'Case-insensitive literal search over the sanitized, read-only source snapshot.',
  parameters: {
    type: 'object',
    properties: { query: { type: 'string', minLength: 2, maxLength: 200 }, pathPrefix: { type: 'string', maxLength: 300 } },
    required: ['query'],
    additionalProperties: false,
  },
  schema: z.object({ query: z.string().min(2).max(200), pathPrefix: z.string().max(300).optional() }).strict(),
  async run(_turn, args: { query: string; pathPrefix?: string }, env) {
    const root = await realpath(env.snapshotDir);
    const needle = args.query.toLowerCase();
    const hits: { path: string; line: number; text: string }[] = [];
    for await (const rel of walkFiles(root, root)) {
      if (args.pathPrefix && !rel.startsWith(args.pathPrefix)) continue;
      const lines = (await readFile(join(root, rel), 'utf8')).split('\n');
      lines.forEach((l, i) => {
        if (hits.length < 40 && l.toLowerCase().includes(needle)) hits.push({ path: rel, line: i + 1, text: l.slice(0, 200) });
      });
      if (hits.length >= 40) break;
    }
    return { content: { hits, truncated: hits.length >= 40 }, evidenceRefs: hits.map((h) => `source:${h.path}:${h.line}`) };
  },
};

const sourceRead: ToolDef = {
  name: 'source.read',
  role: 'dev',
  description: 'Read lines from a file in the sanitized, read-only source snapshot (max 400 lines per call).',
  parameters: {
    type: 'object',
    properties: { path: { type: 'string' }, startLine: { type: 'integer', minimum: 1 }, endLine: { type: 'integer', minimum: 1 } },
    required: ['path'],
    additionalProperties: false,
  },
  schema: z.object({ path: z.string().min(1).max(300), startLine: z.number().int().min(1).optional(), endLine: z.number().int().min(1).optional() }).strict(),
  async run(_turn, args: { path: string; startLine?: number; endLine?: number }, env) {
    const abs = await resolveInSnapshot(env.snapshotDir, args.path);
    if (!(await stat(abs)).isFile()) throw new ToolInputError('Not a file');
    // Opened read-only; the snapshot is also mounted read-only.
    const fh = await open(abs, 'r');
    const text = await fh.readFile('utf8').finally(() => fh.close());
    const lines = text.split('\n');
    const start = args.startLine ?? 1;
    const end = Math.min(args.endLine ?? start + 399, start + 399, lines.length);
    return {
      content: { path: args.path, startLine: start, endLine: end, totalLines: lines.length, text: lines.slice(start - 1, end).join('\n') },
      evidenceRefs: [`source:${args.path}:${start}-${end}`],
    };
  },
};

export const TOOLS: ToolDef[] = [caseMessages, knowledgeSearch, caseBrief, sourceSearch, sourceRead];

export function toolsForRole(role: AgentRole): ToolDef[] {
  return TOOLS.filter((t) => t.role === role);
}

export function toolSpecs(role: AgentRole): ToolSpec[] {
  return toolsForRole(role).map((t) => ({ name: t.name, description: t.description, parameters: t.parameters }));
}

export type Authorization = { ok: true; tool: ToolDef } | { ok: false; reason: 'unknown_tool' | 'not_permitted_for_role' };

/** The single authorization decision for every tool request. */
export function authorizeTool(role: AgentRole, name: string): Authorization {
  const tool = TOOLS.find((t) => t.name === name);
  if (!tool) return { ok: false, reason: 'unknown_tool' };
  if (tool.role !== role) return { ok: false, reason: 'not_permitted_for_role' };
  return { ok: true, tool };
}
