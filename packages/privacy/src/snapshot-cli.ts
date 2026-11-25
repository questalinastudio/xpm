/**
 * Sanitized source snapshot tool. Milestone 5 adds the GitHub synchronizer;
 * for now it builds a snapshot from the synthetic repository.
 *
 *   docker compose run --rm reposync synthetic
 *
 * Snapshots are written to a new directory, then the "current" symlink is
 * swapped atomically, so the gateway never sees a half-written snapshot.
 */
import { mkdtemp, rename, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { sanitizeSourceTree } from './source.js';
import { writeSyntheticRepo } from './synthetic.js';

const SNAPSHOT_ROOT = process.env.XPM_SNAPSHOT_ROOT ?? '/snapshots';

async function main(command: string | undefined): Promise<number> {
  if (command !== 'synthetic') {
    console.log('Usage: reposync synthetic');
    return 2;
  }
  if (!['true', '1'].includes(process.env.XPM_SAMPLE_DATA ?? '')) {
    console.error('Refusing: synthetic data is only allowed when XPM_SAMPLE_DATA=true');
    return 1;
  }
  const work = await mkdtemp(join(tmpdir(), 'xpm-repo-'));
  try {
    await writeSyntheticRepo(join(work, 'repo'));
    const name = `snap-${new Date().toISOString().replace(/[:.]/g, '-')}`;
    const manifest = await sanitizeSourceTree(join(work, 'repo'), join(SNAPSHOT_ROOT, name), { sourceRef: 'synthetic' });
    const tmpLink = join(SNAPSHOT_ROOT, `.current-${process.pid}`);
    await symlink(name, tmpLink);
    await rename(tmpLink, join(SNAPSHOT_ROOT, 'current'));
    console.log(`Snapshot ${name}: ${JSON.stringify(manifest.totals)}`);
    for (const f of manifest.files.filter((x) => x.status === 'held')) {
      console.log(`  held for review: ${f.path} (${f.findings?.map((x) => `${x.rule} line ${x.line}`).join(', ')})`);
    }
    return 0;
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}

process.exitCode = await main(process.argv[2]);
