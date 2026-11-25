import { scanSecrets } from './secrets.js';

/**
 * Redaction of customer correspondence before it reaches any model.
 *
 * Identities (people, emails, phones) become stable placeholders such as
 * [PERSON_3]. The placeholder↔value mapping lives only in the encrypted vault,
 * so the PM can tell that two messages came from the same person without
 * learning who it is. Other sensitive data (cards, government IDs, addresses,
 * IPs, secrets) is replaced with fixed markers. Uncertain findings are
 * reported as ambiguous so the message can be held for owner review.
 *
 * This reduces risk; it does not guarantee that every identifier is found.
 * In particular, names that appear only in free text, and not in headers,
 * salutations, signatures, or "my name is" phrases, can be missed.
 */

export type IdentityKind = 'person' | 'email' | 'phone';
export type FixedKind = 'secret' | 'card' | 'govid' | 'address' | 'ip' | 'url_param';
export type EntityKind = IdentityKind | FixedKind;

export interface DetectedEntity {
  kind: EntityKind;
  /** Canonical value used for identity lookup (identities only). */
  value: string;
  start: number;
  end: number;
}

export interface AmbiguousFinding {
  rule: string;
  start: number;
  end: number;
}

export interface KnownPerson {
  name?: string | null;
  email?: string | null;
  phone?: string | null;
}

/** Returns the stable placeholder for an identity, e.g. "[PERSON_3]". */
export type PlaceholderResolver = (kind: IdentityKind, canonicalValue: string) => Promise<string> | string;

export interface RedactionResult {
  text: string;
  /** Counts only, never values. */
  counts: Partial<Record<EntityKind, number>>;
  placeholders: string[];
  /** Offsets refer to the input text. `marker` is set when spans were masked. */
  ambiguous: (AmbiguousFinding & { marker?: string })[];
}

const FIXED_MARKER: Record<FixedKind, string> = {
  secret: '[REDACTED_SECRET]',
  card: '[REDACTED_CARD]',
  govid: '[REDACTED_GOVID]',
  address: '[REDACTED_ADDRESS]',
  ip: '[REDACTED_IP]',
  url_param: '[REDACTED]',
};

/** Lower number wins when spans overlap. */
const PRIORITY: Record<EntityKind, number> = {
  secret: 0,
  email: 1,
  url_param: 2,
  card: 3,
  govid: 4,
  phone: 5,
  ip: 6,
  address: 7,
  person: 8,
};

// Words that look like names in salutations/signatures but are not people.
const NOT_NAMES = new Set(
  [
    'team', 'support', 'there', 'all', 'everyone', 'folks', 'guys', 'sir', 'madam', 'customer', 'customers', 'friend',
    'questalina', 'thanks', 'thank', 'regards', 'best', 'cheers', 'sincerely', 'hello', 'hi', 'hey', 'dear', 'morning',
    'afternoon', 'evening', 'again', 'so', 'very', 'much', 'you', 'the', 'and', 'from', 'sent', 'iphone', 'android',
    'admin', 'owner', 'manager', 'billing', 'sales', 'info', 'service', 'help', 'desk', 'app', 'mobile', 'portal',
  ].map((w) => w.toLowerCase()),
);

export function canonicalIdentity(kind: IdentityKind, value: string): string {
  switch (kind) {
    case 'email':
      return value.trim().toLowerCase();
    case 'phone': {
      const digits = value.replace(/\D/g, '');
      return digits.length === 11 && digits.startsWith('1') ? digits.slice(1) : digits;
    }
    case 'person':
      return value.normalize('NFKC').trim().replace(/\s+/g, ' ').toLowerCase();
  }
}

function luhn(digits: string): boolean {
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = Number(digits[digits.length - 1 - i]);
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return sum % 10 === 0;
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Case-insensitive alternation of keywords without the regex "i" flag. */
function ci(...words: string[]): string {
  return words
    .map((w) =>
      [...w].map((c) => (/[a-z]/i.test(c) ? `[${c.toLowerCase()}${c.toUpperCase()}]` : c === ' ' ? '\\s+' : escapeRegex(c))).join(''),
    )
    .join('|');
}

const NAME_WORD = "\\p{Lu}[\\p{L}'’-]+";
const NAME = `${NAME_WORD}(?:\\s+${NAME_WORD}){0,2}`;

function isPlausibleName(name: string): boolean {
  const words = name.split(/\s+/);
  return words.length > 0 && words.every((w) => w.length >= 2 && !NOT_NAMES.has(w.toLowerCase()));
}

/** Find candidate names in salutations, signatures, and self-introductions. */
function heuristicNames(text: string): string[] {
  const names = new Set<string>();
  const add = (n: string | undefined) => {
    const trimmed = n?.trim();
    if (trimmed && isPlausibleName(trimmed)) names.add(trimmed);
  };
  // Keywords are case-insensitive; names must start uppercase. (A regex "i"
  // flag would make \p{Lu} match lowercase too, so keywords are spelled out.)
  const salutation = new RegExp(`^[ \\t>]*(?:${ci('hi', 'hello', 'hey', 'dear', 'good morning', 'good afternoon', 'good evening')})[ \\t,]+(${NAME})`, 'gmu');
  for (const m of text.matchAll(salutation)) add(m[1]);
  const intro = new RegExp(`(?<![\\p{L}])(?:${ci('my name is', "my name's", 'this is', 'i am', "i'm")})\\s+(${NAME})(?=\\s*(?:,|\\.|${ci('from', 'and', 'here')}|$))`, 'gmu');
  for (const m of text.matchAll(intro)) add(m[1]);
  const field = new RegExp(`^[ \\t]*(?:${ci('name', 'from', 'customer', 'contact')})\\s*:\\s*(${NAME})\\s*$`, 'gmu');
  for (const m of text.matchAll(field)) add(m[1]);
  // Signature: a sign-off line followed by a short line of capitalized words.
  const lines = text.split('\n');
  const signoff = /^[ \t>]*(?:thanks|thank you|many thanks|regards|best|best regards|kind regards|warm regards|cheers|sincerely|warmly|cordially|take care|--|—)[ \t,.!]*$/i;
  for (let i = 0; i < lines.length; i++) {
    if (!signoff.test(lines[i]!)) continue;
    for (let j = i + 1; j < Math.min(lines.length, i + 3); j++) {
      const line = lines[j]!.replace(/^[ \t>]+/, '').trim();
      if (!line) continue;
      const m = new RegExp(`^(${NAME})$`, 'u').exec(line);
      if (m) add(m[1]);
      break;
    }
  }
  return [...names];
}

export function detectSensitive(text: string, opts: { knownPeople?: KnownPerson[] } = {}): {
  entities: DetectedEntity[];
  ambiguous: AmbiguousFinding[];
} {
  const found: DetectedEntity[] = [];
  const ambiguous: AmbiguousFinding[] = [];
  const push = (kind: EntityKind, start: number, end: number, value = '') => found.push({ kind, start, end, value });

  for (const s of scanSecrets(text)) {
    if (s.confidence === 'high') push('secret', s.start, s.end);
    else ambiguous.push({ rule: `secret:${s.rule}`, start: s.start, end: s.end });
  }
  for (const m of text.matchAll(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi)) {
    push('email', m.index!, m.index! + m[0].length, canonicalIdentity('email', m[0]));
  }
  for (const m of text.matchAll(/([?&](?:token|key|code|signature|sig|auth|session|sessionid|password|pwd|access_token|id_token|refresh_token|otp|apikey|api_key)=)([^&\s#"'<>]+)/gi)) {
    const start = m.index! + m[1]!.length;
    push('url_param', start, start + m[2]!.length);
  }
  for (const m of text.matchAll(/(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])/g)) {
    const digits = m[0].replace(/\D/g, '');
    if (digits.length >= 13 && digits.length <= 19 && luhn(digits)) push('card', m.index!, m.index! + m[0].length);
  }
  for (const m of text.matchAll(/\b\d{3}-\d{2}-\d{4}\b/g)) push('govid', m.index!, m.index! + m[0].length);
  const phonePatterns = [
    /(?<![\w+])(?:\+?1[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]?\d{3}[\s.-]?\d{4}(?![\w])/g,
    /(?<![\w+])\+\d{1,3}[\s.-]?\d[\d\s.-]{6,14}\d(?![\w])/g,
  ];
  for (const re of phonePatterns) {
    for (const m of text.matchAll(re)) push('phone', m.index!, m.index! + m[0].length, canonicalIdentity('phone', m[0]));
  }
  for (const m of text.matchAll(/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g)) {
    push('ip', m.index!, m.index! + m[0].length);
  }
  const address =
    /\b\d{1,6}\s+(?:[NSEW]\.?\s+)?(?:[A-Z][a-z]+\.?\s+){1,4}(?:St|Street|Ave|Avenue|Rd|Road|Blvd|Boulevard|Ln|Lane|Dr|Drive|Way|Ct|Court|Pl|Place|Ter|Terrace|Pkwy|Parkway|Hwy|Highway|Cir|Circle)\b\.?(?:,?\s*(?:Apt|Apartment|Unit|Suite|Ste|#)\.?\s*[\w-]+)?/g;
  for (const m of text.matchAll(address)) push('address', m.index!, m.index! + m[0].length);

  // People: known identities first (full name and each name part), then heuristics.
  const nameToCanonical = new Map<string, string>();
  for (const p of opts.knownPeople ?? []) {
    if (!p.name || !isPlausibleName(p.name.trim().replace(/[^\p{L}\s'’-]/gu, ''))) continue;
    const full = p.name.trim().replace(/\s+/g, ' ');
    const canonical = canonicalIdentity('person', full);
    nameToCanonical.set(full, canonical);
    for (const part of full.split(' ')) if (part.length >= 2 && !NOT_NAMES.has(part.toLowerCase())) nameToCanonical.set(part, canonical);
  }
  for (const name of heuristicNames(text)) {
    if (![...nameToCanonical.keys()].some((k) => k.toLowerCase() === name.toLowerCase())) {
      const canonical = canonicalIdentity('person', name);
      nameToCanonical.set(name, canonical);
      // A heuristic full name also covers its parts elsewhere in the text.
      if (name.includes(' ')) for (const part of name.split(' ')) if (!nameToCanonical.has(part)) nameToCanonical.set(part, canonical);
    }
  }
  // Longest names first so "Jane Doe" wins over "Jane".
  for (const [name, canonical] of [...nameToCanonical.entries()].sort((a, b) => b[0].length - a[0].length)) {
    // Full names match in any case. A single name part matches only as written
    // (capitalized) or in capitals, so "Will" or "Grace" do not blank out the
    // words "will" and "grace".
    const single = !/\s/.test(name);
    const pattern = single ? `(?:${escapeRegex(name)}|${escapeRegex(name.toUpperCase())})` : escapeRegex(name);
    const re = new RegExp(`(?<![\\p{L}\\p{N}_])${pattern}(?![\\p{L}\\p{N}_])`, single ? 'gu' : 'giu');
    for (const m of text.matchAll(re)) push('person', m.index!, m.index! + m[0].length, canonical);
  }

  // Resolve overlaps by priority, then by length.
  found.sort((a, b) => PRIORITY[a.kind] - PRIORITY[b.kind] || b.end - b.start - (a.end - a.start));
  const kept: DetectedEntity[] = [];
  for (const e of found) if (!kept.some((k) => e.start < k.end && k.start < e.end)) kept.push(e);
  kept.sort((a, b) => a.start - b.start);

  // Long digit runs that are not phones or cards could be account numbers: hold for review.
  for (const m of text.matchAll(/(?<!\d|\d\.)\d{9,}(?!\d|\.\d)/g)) {
    const start = m.index!;
    const end = start + m[0].length;
    if (!kept.some((k) => start < k.end && k.start < end)) ambiguous.push({ rule: 'long_number', start, end });
  }
  const ambiguousKept = ambiguous.filter((a) => !kept.some((k) => a.start >= k.start && a.end <= k.end));
  return { entities: kept, ambiguous: ambiguousKept };
}

export async function redactText(
  text: string,
  opts: {
    knownPeople?: KnownPerson[];
    resolve: PlaceholderResolver;
    /** If set, ambiguous spans are masked with the returned marker (e.g. "[HELD_1]"). */
    holdMarker?: () => string;
  },
): Promise<RedactionResult> {
  const { entities, ambiguous } = detectSensitive(text, opts);
  const counts: Partial<Record<EntityKind, number>> = {};
  const placeholders = new Set<string>();
  const replacements: { start: number; end: number; with: string }[] = [];
  for (const e of entities) {
    counts[e.kind] = (counts[e.kind] ?? 0) + 1;
    let marker: string;
    if (e.kind === 'person' || e.kind === 'email' || e.kind === 'phone') {
      marker = await opts.resolve(e.kind, e.value);
      placeholders.add(marker);
    } else {
      marker = FIXED_MARKER[e.kind];
    }
    replacements.push({ start: e.start, end: e.end, with: marker });
  }
  const reported: (AmbiguousFinding & { marker?: string })[] = [];
  for (const a of [...ambiguous].sort((x, y) => x.start - y.start)) {
    if (reported.some((r) => a.start < r.end && r.start < a.end)) continue;
    const marker = opts.holdMarker?.();
    if (marker) replacements.push({ start: a.start, end: a.end, with: marker });
    reported.push(marker ? { ...a, marker } : a);
  }
  replacements.sort((a, b) => a.start - b.start);
  let out = text;
  for (const r of replacements.reverse()) out = out.slice(0, r.start) + r.with + out.slice(r.end);
  return { text: out, counts, placeholders: [...placeholders], ambiguous: reported };
}

/** In-memory resolver for tests and previews. Production uses the vault. */
export function createMemoryResolver(): PlaceholderResolver & { entries: Map<string, string> } {
  const entries = new Map<string, string>();
  const counters: Record<IdentityKind, number> = { person: 0, email: 0, phone: 0 };
  const fn = ((kind: IdentityKind, value: string) => {
    const key = `${kind}:${value}`;
    let p = entries.get(key);
    if (!p) {
      p = `[${kind.toUpperCase()}_${++counters[kind]}]`;
      entries.set(key, p);
    }
    return p;
  }) as PlaceholderResolver & { entries: Map<string, string> };
  fn.entries = entries;
  return fn;
}

/**
 * Defense in depth before anything leaves for a model: report identifiers or
 * secrets that should have been redacted upstream. Placeholders are ignored.
 */
export function findUnredacted(
  text: string,
  kinds: EntityKind[] = ['secret', 'email', 'phone', 'card', 'govid'],
): { kind: string; start: number; end: number }[] {
  const { entities } = detectSensitive(text);
  return entities
    .filter((e) => kinds.includes(e.kind) && !(e.kind === 'email' && isExampleEmail(e.value)))
    .map((e) => ({ kind: e.kind, start: e.start, end: e.end }));
}

/** Reserved example domains (RFC 2606) are not personal data. */
export function isExampleEmail(email: string): boolean {
  return /@(?:[a-z0-9-]+\.)*(?:example\.(?:com|org|net)|example|test|invalid|localhost)$/i.test(email);
}
