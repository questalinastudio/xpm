import { readFileSync } from 'node:fs';

/**
 * Read a secret from `${name}_FILE` (preferred, e.g. a Docker secret) or `${name}`.
 * Secrets are never logged; callers must not include them in error messages.
 */
export function readSecret(name: string, env: NodeJS.ProcessEnv = process.env): string | undefined {
  const file = env[`${name}_FILE`];
  if (file) {
    return readFileSync(file, 'utf8').trim();
  }
  const value = env[name];
  return value === undefined || value === '' ? undefined : value;
}

export function requireSecret(name: string, env: NodeJS.ProcessEnv = process.env): string {
  const value = readSecret(name, env);
  if (!value) {
    throw new Error(`Missing required secret ${name} (set ${name}_FILE or ${name})`);
  }
  return value;
}
