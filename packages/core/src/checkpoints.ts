import type { Queryable } from './db.js';

export interface Checkpoint<T = unknown> {
  key: string;
  value: T;
  version: number;
  updatedAt: Date;
}

export class CheckpointConflictError extends Error {
  constructor(key: string, expected: number | null) {
    super(`Checkpoint ${key} changed concurrently (expected version ${expected ?? 'none'})`);
    this.name = 'CheckpointConflictError';
  }
}

export async function getCheckpoint<T = unknown>(db: Queryable, key: string): Promise<Checkpoint<T> | null> {
  const { rows } = await db.query('SELECT key, value, version, updated_at FROM checkpoints WHERE key = $1', [key]);
  const r = rows[0];
  return r ? { key: r.key, value: r.value as T, version: r.version, updatedAt: r.updated_at } : null;
}

/**
 * Compare-and-set. `expectedVersion` null means "must not exist yet".
 * Run inside the same transaction as the work the checkpoint describes.
 */
export async function setCheckpoint<T>(
  db: Queryable,
  key: string,
  value: T,
  expectedVersion: number | null,
): Promise<Checkpoint<T>> {
  const json = JSON.stringify(value);
  const { rows } =
    expectedVersion === null
      ? await db.query(
          `INSERT INTO checkpoints (key, value) VALUES ($1, $2::jsonb)
           ON CONFLICT (key) DO NOTHING
           RETURNING key, value, version, updated_at`,
          [key, json],
        )
      : await db.query(
          `UPDATE checkpoints SET value = $2::jsonb, version = version + 1, updated_at = now()
           WHERE key = $1 AND version = $3
           RETURNING key, value, version, updated_at`,
          [key, json, expectedVersion],
        );
  const r = rows[0];
  if (!r) throw new CheckpointConflictError(key, expectedVersion);
  return { key: r.key, value: r.value as T, version: r.version, updatedAt: r.updated_at };
}
