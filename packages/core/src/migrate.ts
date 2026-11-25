import { createHash } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import type { Pool } from './db.js';

/** Migrations live beside src/ and dist/, so this resolves in both. */
export const MIGRATIONS_DIR = fileURLToPath(new URL('../migrations/', import.meta.url));

// Arbitrary constant key so concurrent migrators serialize.
const MIGRATION_LOCK_KEY = 7_318_400_211;

export interface MigrationFile {
  version: string;
  name: string;
  sql: string;
  checksum: string;
}

export async function loadMigrations(dir = MIGRATIONS_DIR): Promise<MigrationFile[]> {
  const entries = (await readdir(dir)).filter((f) => /^\d{4}_[a-z0-9_]+\.sql$/.test(f)).sort();
  return Promise.all(
    entries.map(async (file) => {
      const sql = await readFile(`${dir}/${file}`, 'utf8');
      return {
        version: file.slice(0, 4),
        name: file.replace(/\.sql$/, ''),
        sql,
        checksum: createHash('sha256').update(sql).digest('hex'),
      };
    }),
  );
}

export interface MigrateResult {
  applied: string[];
  current: string | null;
}

/**
 * Apply pending migrations, each in its own transaction, under an advisory
 * lock. Refuses to run if an applied migration file was modified.
 */
export async function migrate(pool: Pool, dir = MIGRATIONS_DIR): Promise<MigrateResult> {
  const migrations = await loadMigrations(dir);
  const client = await pool.connect();
  try {
    await client.query('SELECT pg_advisory_lock($1)', [MIGRATION_LOCK_KEY]);
    await client.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version    text PRIMARY KEY,
        name       text NOT NULL,
        checksum   text NOT NULL,
        applied_at timestamptz NOT NULL DEFAULT now()
      )`);
    const { rows } = await client.query<{ version: string; checksum: string }>(
      'SELECT version, checksum FROM schema_migrations',
    );
    const applied = new Map(rows.map((r) => [r.version, r.checksum]));
    const newlyApplied: string[] = [];

    for (const m of migrations) {
      const existing = applied.get(m.version);
      if (existing !== undefined) {
        if (existing !== m.checksum) {
          throw new Error(`Migration ${m.name} was modified after being applied (checksum mismatch)`);
        }
        continue;
      }
      await client.query('BEGIN');
      try {
        await client.query(m.sql);
        await client.query('INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)', [
          m.version,
          m.name,
          m.checksum,
        ]);
        await client.query('COMMIT');
      } catch (err) {
        await client.query('ROLLBACK').catch(() => {});
        throw new Error(`Migration ${m.name} failed: ${(err as Error).message}`);
      }
      newlyApplied.push(m.name);
    }
    const last = migrations.at(-1);
    return { applied: newlyApplied, current: last ? last.name : null };
  } finally {
    await client.query('SELECT pg_advisory_unlock($1)', [MIGRATION_LOCK_KEY]).catch(() => {});
    client.release();
  }
}

export interface ServiceRole {
  name: string;
  password: string;
}

/**
 * Enable login for per-service roles and (re)set their passwords from secret
 * files. Safe to run on every deploy; supports password rotation.
 */
export async function configureServiceRoles(pool: Pool, roles: ServiceRole[]): Promise<void> {
  const client = await pool.connect();
  try {
    for (const role of roles) {
      if (!/^xpm_[a-z_]+$/.test(role.name)) throw new Error(`Invalid role name: ${role.name}`);
      const exists = await client.query('SELECT 1 FROM pg_roles WHERE rolname = $1', [role.name]);
      if (exists.rowCount === 0) throw new Error(`Role ${role.name} does not exist; run migrations first`);
      await client.query(
        `ALTER ROLE ${client.escapeIdentifier(role.name)} WITH LOGIN PASSWORD ${client.escapeLiteral(role.password)}`,
      );
    }
  } finally {
    client.release();
  }
}
