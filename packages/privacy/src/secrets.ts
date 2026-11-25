import { entropy } from './text.js';

/**
 * Secret detection for messages, source files, tool results, and error text.
 * "high" findings are redacted automatically. "ambiguous" findings are held
 * for owner review rather than guessed at. Detection reduces risk; it is not
 * a guarantee.
 */

export type Confidence = 'high' | 'ambiguous';

export interface SecretFinding {
  rule: string;
  start: number;
  end: number;
  confidence: Confidence;
}

interface Rule {
  id: string;
  pattern: RegExp;
  /** Capture group holding the secret; 0 = whole match. */
  group?: number;
  confidence: Confidence | ((value: string, match: RegExpMatchArray) => Confidence | null);
}

/** Values that look like placeholders or references, not real secrets. */
function looksLikePlaceholder(v: string): boolean {
  return (
    /^(process\.env|import\.meta\.env|Deno\.env|env\(|os\.environ|\$\{|\{\{|<|%|\$[A-Z_])/i.test(v) ||
    /^(x+|\*+|\.+|changeme|change_me|example|placeholder|your[-_]?\w*|redacted|dummy|test|password|secret|none|null|undefined|true|false)$/i.test(v) ||
    /^\[REDACTED/.test(v)
  );
}

function charClasses(v: string): number {
  return [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((re) => re.test(v)).length;
}

/**
 * Judge a value assigned to a secret-sounding name. Code is full of such
 * names (csrfToken, passwordHash, PG_PASSWORD_FILE), so values that are
 * expressions, paths, or identifiers are not secrets.
 */
function assignmentConfidence(value: string, quoted: boolean): Confidence | null {
  if (looksLikePlaceholder(value)) return null;
  if (/[()<>{}[\]!]/.test(value) || /^(\.{0,2}\/|~\/|\$)/.test(value)) return null; // expression or path
  if (/^[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)+$/.test(value)) return null; // member access
  if (!quoted && /^[A-Za-z_$][\w$-]*$/.test(value) && !/\d/.test(value)) return null; // bare identifier
  const wordLike = /^[a-z]+(?:[-_][a-z]+)+$/i.test(value);
  if (value.length >= 12 && entropy(value) >= 3.3 && charClasses(value) >= 2 && !wordLike) return 'high';
  return quoted || /\d/.test(value) ? 'ambiguous' : null;
}

const RULES: Rule[] = [
  { id: 'private_key', pattern: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)/g, confidence: 'high' },
  { id: 'aws_access_key', pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, confidence: 'high' },
  { id: 'github_token', pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b/g, confidence: 'high' },
  { id: 'slack_token', pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, confidence: 'high' },
  { id: 'stripe_key', pattern: /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g, confidence: 'high' },
  { id: 'google_api_key', pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g, confidence: 'high' },
  { id: 'ai_api_key', pattern: /\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}\b/g, confidence: 'high' },
  { id: 'supabase_key', pattern: /\bsb_(?:secret|publishable)_[A-Za-z0-9_-]{16,}\b/g, confidence: 'high' },
  { id: 'jwt', pattern: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, confidence: 'high' },
  {
    id: 'connection_string',
    pattern: /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql):\/\/[^\s:@/'"`]+:[^\s@/'"`]+@[^\s'"`<>]+/gi,
    confidence: 'high',
  },
  { id: 'url_credentials', pattern: /\bhttps?:\/\/[^\s:@/'"`]+:[^\s@/'"`]+@[^\s'"`<>]+/gi, confidence: 'high' },
  { id: 'bearer_token', pattern: /\bBearer\s+([A-Za-z0-9._~+/-]{20,}=*)/g, group: 1, confidence: 'high' },
  {
    id: 'secret_assignment',
    // Same-line only. Group 1 is an opening quote (if any), group 2 the value.
    pattern:
      /\b[A-Za-z0-9_.-]*(?:secret|passw(?:or)?d|pwd|token|api[_-]?key|apikey|private[_-]?key|access[_-]?key|client[_-]?secret|auth[_-]?key|service[_-]?role)[A-Za-z0-9_.-]*["']?[ \t]*[:=][ \t]*(["'`]?)([^\s"'`,;)}\]]{8,})/gi,
    group: 2,
    confidence: (value, m) => {
      // A plural name ("secrets", "tokens") usually labels a collection or a path, not a credential.
      const key = m[0].slice(0, m[0].search(/["']?[ \t]*[:=]/));
      if (/(?:secrets|tokens|passwords|passwds|keys)$/i.test(key)) return null;
      return assignmentConfidence(value, m[1] !== '');
    },
  },
];

/** Long random-looking strings not caught by a specific rule. */
const HIGH_ENTROPY = /(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{32,}={0,2}(?![A-Za-z0-9+/_-])/g;

function hasSequentialRun(v: string, length: number): boolean {
  let run = 1;
  for (let i = 1; i < v.length; i++) {
    run = v.charCodeAt(i) === v.charCodeAt(i - 1) + 1 ? run + 1 : 1;
    if (run >= length) return true;
  }
  return false;
}

export interface ScanOptions {
  /** Report long high-entropy strings as ambiguous (default true). Disable for lockfiles. */
  entropyScan?: boolean;
}

export function scanSecrets(text: string, opts: ScanOptions = {}): SecretFinding[] {
  const findings: SecretFinding[] = [];
  for (const rule of RULES) {
    for (const m of text.matchAll(rule.pattern)) {
      const group = rule.group ?? 0;
      const value = m[group];
      if (!value) continue;
      const start = m.index! + (group === 0 ? 0 : m[0].indexOf(value));
      const confidence = typeof rule.confidence === 'function' ? rule.confidence(value, m) : rule.confidence;
      if (confidence) findings.push({ rule: rule.id, start, end: start + value.length, confidence });
    }
  }
  if (opts.entropyScan ?? true) {
    for (const m of text.matchAll(HIGH_ENTROPY)) {
      const v = m[0];
      // Skip hex hashes (commit SHAs, checksums), paths, and identifiers.
      if (/^[0-9a-f]+$/i.test(v) || v.includes('/') || /^[A-Za-z_]+$/.test(v) || entropy(v) < 4.2) continue;
      if (hasSequentialRun(v, 6)) continue; // alphabet or charset tables, not random tokens
      findings.push({ rule: 'high_entropy', start: m.index!, end: m.index! + v.length, confidence: 'ambiguous' });
    }
  }
  return mergeFindings(findings);
}

/** Remove overlaps, preferring high-confidence and longer findings. */
function mergeFindings(findings: SecretFinding[]): SecretFinding[] {
  const sorted = [...findings].sort(
    (a, b) =>
      (a.confidence === b.confidence ? 0 : a.confidence === 'high' ? -1 : 1) || b.end - b.start - (a.end - a.start),
  );
  const kept: SecretFinding[] = [];
  for (const f of sorted) {
    if (!kept.some((k) => f.start < k.end && k.start < f.end)) kept.push(f);
  }
  return kept.sort((a, b) => a.start - b.start);
}

// ---------------------------------------------------------------------------
// Credential scrubbing for logs, stored errors, and API responses.
// ---------------------------------------------------------------------------

const knownSecrets = new Set<string>();

/** Register an exact secret value (DB passwords, tokens) so it is always scrubbed. */
export function registerKnownSecret(value: string | undefined): void {
  if (value && value.length >= 8) knownSecrets.add(value);
}

/**
 * Replace known secret values and anything the secret rules flag as
 * high-confidence. Used on every error message and log line.
 */
export function scrubSecrets(text: string): string {
  let out = text;
  for (const secret of knownSecrets) {
    if (out.includes(secret)) out = out.split(secret).join('[REDACTED_SECRET]');
  }
  const findings = scanSecrets(out, { entropyScan: false }).filter((f) => f.confidence === 'high');
  for (const f of [...findings].reverse()) {
    out = `${out.slice(0, f.start)}[REDACTED_SECRET:${f.rule}]${out.slice(f.end)}`;
  }
  return out;
}

/** Deep-scrub strings inside a JSON-like value. */
export function scrubValue<T>(value: T, depth = 0): T {
  if (depth > 8) return value;
  if (typeof value === 'string') return scrubSecrets(value) as T;
  if (Array.isArray(value)) return value.map((v) => scrubValue(v, depth + 1)) as T;
  if (value && typeof value === 'object' && !(value instanceof Date) && !Buffer.isBuffer(value)) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = scrubValue(v, depth + 1);
    return out as T;
  }
  return value;
}
