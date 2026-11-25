import { readFileSync } from 'node:fs';
import { registerKnownSecret } from '@xpm/privacy';

/**
 * Read a secret from `${name}_FILE` (preferred, e.g. a Docker secret) or `${name}`.
 * Secrets are never logged; callers must not include them in error messages.
 */
export function readSecret(name: string, env: NodeJS.ProcessEnv = process.env): string | undefined {
  const file = env[`${name}_FILE`];
  const value = file ? readFileSync(file, 'utf8').trim() : env[name];
  if (value === undefined || value === '') return undefined;
  // Every loaded secret is scrubbed from logs and stored errors by exact match.
  registerKnownSecret(value);
  return value;
}

export function requireSecret(name: string, env: NodeJS.ProcessEnv = process.env): string {
  const value = readSecret(name, env);
  if (!value) {
    throw new Error(`Missing required secret ${name} (set ${name}_FILE or ${name})`);
  }
  return value;
}
