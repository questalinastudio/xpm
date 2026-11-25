/**
 * Workstation administration CLI. Run inside the server container:
 *   docker compose run --rm server node apps/server/dist/cli.js <command>
 *
 *   admin create --username <name> [--password-stdin]
 *   admin reset-password --username <name> [--password-stdin]
 *   admin list
 *   sample seed | sample clear
 */
import { createInterface } from 'node:readline';
import { parseArgs } from 'node:util';
import { createPool, dbOptionsFromEnv } from '@xpm/core';
import { AccountError, createAdmin, listAdmins, resetPassword } from './auth.js';
import { clearSampleData, seedSampleData } from './sample.js';

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString('utf8').replace(/\r?\n$/, '');
}

function promptHidden(question: string): Promise<string> {
  if (!process.stdin.isTTY) {
    throw new AccountError('No terminal for a password prompt; use -it or --password-stdin');
  }
  return new Promise((resolve) => {
    const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    const rlAny = rl as unknown as { _writeToOutput: (s: string) => void; output: NodeJS.WriteStream };
    let prompted = false;
    rlAny._writeToOutput = (s: string) => {
      if (!prompted) {
        rlAny.output.write(s);
        prompted = true;
      }
    };
    rl.question(question, (answer) => {
      rl.close();
      process.stdout.write('\n');
      resolve(answer);
    });
  });
}

async function obtainPassword(fromStdin: boolean): Promise<string> {
  if (fromStdin) return readStdin();
  const first = await promptHidden('New password: ');
  const second = await promptHidden('Repeat password: ');
  if (first !== second) throw new AccountError('Passwords do not match');
  return first;
}

const USAGE = `Usage:
  cli admin create --username <name> [--password-stdin]
  cli admin reset-password --username <name> [--password-stdin]
  cli admin list
  cli sample seed|clear`;

async function main(): Promise<number> {
  const { positionals, values } = parseArgs({
    allowPositionals: true,
    options: { username: { type: 'string' }, 'password-stdin': { type: 'boolean', default: false } },
  });
  const [group, command] = positionals;
  const pool = createPool(dbOptionsFromEnv(process.env, 'xpm-cli'));
  try {
    if (group === 'admin' && (command === 'create' || command === 'reset-password')) {
      if (!values.username) throw new AccountError('--username is required');
      const password = await obtainPassword(values['password-stdin'] ?? false);
      if (command === 'create') {
        await createAdmin(pool, values.username, password);
        console.log(`Created administrator ${values.username.trim().toLowerCase()}`);
      } else {
        const r = await resetPassword(pool, values.username, password);
        console.log(`Password reset; revoked ${r.revokedSessions} active session(s)`);
      }
      return 0;
    }
    if (group === 'admin' && command === 'list') {
      for (const a of await listAdmins(pool)) {
        console.log(`${a.username}\tcreated ${a.createdAt.toISOString()}${a.disabled ? '\tDISABLED' : ''}`);
      }
      return 0;
    }
    if (group === 'sample' && command === 'seed') {
      console.log(`Inserted ${await seedSampleData(pool)} sample case(s)`);
      return 0;
    }
    if (group === 'sample' && command === 'clear') {
      console.log(`Removed ${await clearSampleData(pool)} sample case(s)`);
      return 0;
    }
    console.error(USAGE);
    return 2;
  } catch (err) {
    if (err instanceof AccountError) {
      console.error(`Error: ${err.message}`);
      return 1;
    }
    console.error(`Error: ${(err as Error).message}`);
    return 1;
  } finally {
    await pool.end();
  }
}

process.exitCode = await main();
