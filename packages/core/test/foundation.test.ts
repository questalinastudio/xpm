import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  CheckpointConflictError,
  configureServiceRoles,
  getCheckpoint,
  hashPassword,
  migrate,
  setCheckpoint,
  verifyPassword,
} from '../src/index.js';
import { startTestDb, type TestDb } from './helpers.js';

let db: TestDb;
beforeAll(async () => {
  db = await startTestDb();
});
afterAll(async () => {
  await db?.stop();
});

describe('migrations', () => {
  it('are idempotent on a migrated database', async () => {
    const again = await migrate(db.pool);
    expect(again.applied).toEqual([]);
    expect(again.current).toBe('0001_foundation');
  });

  it('refuse to run if an applied migration was modified', async () => {
    await db.pool.query(`UPDATE schema_migrations SET checksum = 'tampered' WHERE version = '0001'`);
    await expect(migrate(db.pool)).rejects.toThrow(/checksum mismatch/);
    const { rows } = await db.pool.query(`SELECT checksum FROM schema_migrations`);
    // restore for other tests
    const { loadMigrations } = await import('../src/migrate.js');
    const [m] = await loadMigrations();
    await db.pool.query(`UPDATE schema_migrations SET checksum = $1 WHERE version = '0001'`, [m!.checksum]);
    expect(rows[0].checksum).toBe('tampered');
  });
});

describe('per-service database roles', () => {
  beforeAll(async () => {
    await configureServiceRoles(db.pool, [
      { name: 'xpm_web', password: 'web-test-password' },
      { name: 'xpm_worker', password: 'worker-test-password' },
    ]);
  });

  it('worker role cannot read administrator credentials or sessions', async () => {
    const worker = db.newPool('xpm_worker', 'worker-test-password');
    await expect(worker.query('SELECT * FROM admin_users')).rejects.toThrow(/permission denied/);
    await expect(worker.query('SELECT * FROM sessions')).rejects.toThrow(/permission denied/);
    await expect(worker.query('SELECT count(*) FROM jobs')).resolves.toBeDefined();
  });

  it('service roles cannot alter the schema', async () => {
    const web = db.newPool('xpm_web', 'web-test-password');
    await expect(web.query('CREATE TABLE evil (id int)')).rejects.toThrow(/permission denied/);
    await expect(web.query('DROP TABLE jobs')).rejects.toThrow(/must be owner/);
  });

  it('rejects invalid role names', async () => {
    await expect(configureServiceRoles(db.pool, [{ name: 'postgres', password: 'x' }])).rejects.toThrow(/Invalid role/);
  });
});

describe('checkpoints', () => {
  it('compare-and-set prevents lost updates', async () => {
    const created = await setCheckpoint(db.pool, 'gmail:inbox', { historyId: '100' }, null);
    expect(created.version).toBe(1);
    await expect(setCheckpoint(db.pool, 'gmail:inbox', { historyId: 'x' }, null)).rejects.toBeInstanceOf(
      CheckpointConflictError,
    );
    const updated = await setCheckpoint(db.pool, 'gmail:inbox', { historyId: '120' }, 1);
    expect(updated.version).toBe(2);
    await expect(setCheckpoint(db.pool, 'gmail:inbox', { historyId: '110' }, 1)).rejects.toBeInstanceOf(
      CheckpointConflictError,
    );
    expect((await getCheckpoint(db.pool, 'gmail:inbox'))?.value).toEqual({ historyId: '120' });
  });
});

describe('password hashing', () => {
  const fast = { N: 2 ** 12, r: 8, p: 1 };
  it('verifies the right password and rejects others', async () => {
    const hash = await hashPassword('correct horse battery', fast);
    expect(hash).toMatch(/^scrypt\$4096\$8\$1\$/);
    expect(hash).not.toContain('correct horse');
    expect(await verifyPassword('correct horse battery', hash)).toBe(true);
    expect(await verifyPassword('correct horse batterY', hash)).toBe(false);
  });

  it('uses a unique salt per hash and rejects malformed hashes', async () => {
    expect(await hashPassword('same password!', fast)).not.toBe(await hashPassword('same password!', fast));
    expect(await verifyPassword('x', 'not-a-hash')).toBe(false);
    expect(await verifyPassword('x', 'scrypt$0$8$1$AAAA$AAAA')).toBe(false);
  });

  it('default parameters meet OWASP scrypt guidance', async () => {
    const hash = await hashPassword('a strong password');
    expect(hash.startsWith('scrypt$131072$8$1$')).toBe(true);
    expect(await verifyPassword('a strong password', hash)).toBe(true);
  });
});
