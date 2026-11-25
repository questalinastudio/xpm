import { createHash } from 'node:crypto';
import { lstat, mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import { join, relative, sep } from 'node:path';
import { isExampleEmail } from './redact.js';
import { scanSecrets } from './secrets.js';

/**
 * Builds the sanitized source snapshot the dev manager may read.
 *
 * - Never follows symlinks; never copies VCS metadata, dependencies, or build output.
 * - Excludes files that typically hold credentials or data dumps, by name.
 * - Excludes binaries and oversized files.
 * - Replaces high-confidence secrets in text files with a marker.
 * - Holds (excludes and lists) files with ambiguous findings for owner review.
 * - Replaces real-looking email addresses (customer data in seeds, fixtures).
 *
 * Files are written read-only. The manifest records what happened to every
 * file, with rule names and line numbers but never the secret values.
 */

export type FileStatus = 'included' | 'redacted' | 'excluded' | 'held';

export interface ManifestEntry {
  path: string;
  status: FileStatus;
  reason?: string;
  sha256?: string;
  bytes?: number;
  findings?: { rule: string; line: number; confidence: 'high' | 'ambiguous' }[];
}

export interface SourceManifest {
  createdAt: string;
  sourceRef: string;
  files: ManifestEntry[];
  totals: Record<FileStatus, number>;
}

const SKIP_DIRS = new Set([
  '.git', '.hg', '.svn', 'node_modules', '.pnpm-store', '.next', '.nuxt', '.expo', '.expo-shared', '.turbo', '.vercel',
  '.cache', 'dist', 'build', 'out', 'coverage', '.idea', '.vscode', 'Pods', 'DerivedData', '.gradle', '.terraform',
]);

const EXCLUDE_FILE_PATTERNS: [RegExp, string][] = [
  [/^\.env(\..*)?$/i, 'environment file'],
  [/\.(pem|key|p12|pfx|jks|keystore|p8|der|crt|cer|mobileprovision|provisionprofile)$/i, 'key or certificate'],
  [/^id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$/i, 'SSH key'],
  [/^(credentials|secrets?|service[-_]?account.*|client[-_]?secret.*)\.(json|ya?ml|toml|txt)$/i, 'credentials file'],
  [/^(google-services\.json|GoogleService-Info\.plist)$/, 'mobile service credentials'],
  [/^\.(npmrc|yarnrc\.yml|pypirc|netrc|pgpass|git-credentials|dockercfg)$/i, 'package or auth config'],
  [/\.(sqlite3?|db|dump|bak|backup)$/i, 'database or backup file'],
  [/^\.DS_Store$/, 'system file'],
];
const TEMPLATE_ENV = /^\.env\.(example|sample|template|defaults)$/i;
const LOCKFILES = new Set(['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lockb', 'Podfile.lock', 'Gemfile.lock', 'composer.lock', 'Cargo.lock', 'poetry.lock']);
const MAX_BYTES = 512 * 1024;

function lineOf(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

function exclusionReason(name: string): string | null {
  if (TEMPLATE_ENV.test(name)) return null;
  for (const [re, reason] of EXCLUDE_FILE_PATTERNS) if (re.test(name)) return reason;
  return null;
}

export interface SanitizeOptions {
  /** Identifier recorded in the manifest, e.g. the commit SHA. */
  sourceRef: string;
}

export async function sanitizeSourceTree(srcRoot: string, outRoot: string, opts: SanitizeOptions): Promise<SourceManifest> {
  const files: ManifestEntry[] = [];

  async function walk(dir: string): Promise<void> {
    const entries = (await readdir(dir, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const abs = join(dir, entry.name);
      const rel = relative(srcRoot, abs).split(sep).join('/');
      const st = await lstat(abs);
      if (st.isSymbolicLink()) {
        files.push({ path: rel, status: 'excluded', reason: 'symbolic link' });
        continue;
      }
      if (st.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) files.push({ path: `${rel}/`, status: 'excluded', reason: 'dependency, build, or VCS directory' });
        else await walk(abs);
        continue;
      }
      if (!st.isFile()) continue;
      const reason = exclusionReason(entry.name);
      if (reason) {
        files.push({ path: rel, status: 'excluded', reason });
        continue;
      }
      if (st.size > MAX_BYTES) {
        files.push({ path: rel, status: 'excluded', reason: `larger than ${MAX_BYTES / 1024} KB`, bytes: st.size });
        continue;
      }
      const buf = await readFile(abs);
      if (buf.subarray(0, 8192).includes(0)) {
        files.push({ path: rel, status: 'excluded', reason: 'binary file', bytes: st.size });
        continue;
      }
      let text = buf.toString('utf8');
      const isLockfile = LOCKFILES.has(entry.name);
      const findings = scanSecrets(text, { entropyScan: !isLockfile });
      const ambiguous = findings.filter((f) => f.confidence === 'ambiguous');
      const report = findings.map((f) => ({ rule: f.rule, line: lineOf(text, f.start), confidence: f.confidence }));
      if (ambiguous.length > 0) {
        files.push({ path: rel, status: 'held', reason: 'possible secret needs owner review', findings: report });
        continue;
      }
      let redactions = 0;
      for (const f of [...findings].reverse()) {
        text = `${text.slice(0, f.start)}[REDACTED_SECRET:${f.rule}]${text.slice(f.end)}`;
        redactions++;
      }
      text = text.replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, (m) => {
        if (isExampleEmail(m)) return m;
        redactions++;
        return '[REDACTED_EMAIL]';
      });
      const outPath = join(outRoot, rel);
      if (!outPath.startsWith(outRoot + sep)) throw new Error(`Refusing to write outside snapshot: ${rel}`);
      await mkdir(join(outPath, '..'), { recursive: true });
      await writeFile(outPath, text, { mode: 0o444 });
      files.push({
        path: rel,
        status: redactions > 0 ? 'redacted' : 'included',
        sha256: createHash('sha256').update(text).digest('hex'),
        bytes: Buffer.byteLength(text),
        ...(report.length > 0 ? { findings: report } : {}),
      });
    }
  }

  await mkdir(outRoot, { recursive: true });
  await walk(srcRoot);
  const totals: Record<FileStatus, number> = { included: 0, redacted: 0, excluded: 0, held: 0 };
  for (const f of files) totals[f.status]++;
  const manifest: SourceManifest = { createdAt: new Date().toISOString(), sourceRef: opts.sourceRef, files, totals };
  await writeFile(join(outRoot, '.snapshot-manifest.json'), JSON.stringify(manifest, null, 2), { mode: 0o444 });
  return manifest;
}
