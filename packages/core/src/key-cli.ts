/**
 * Master key tool. Runs in an isolated container with no network:
 *   docker compose run --rm keytool <command>
 *
 *   generate   Create the master key and show the paper backup sheet.
 *   verify     Type the paper copy back in to confirm it is correct.
 *   paper      Show the paper backup sheet again.
 *   restore    Recreate the key file from the paper copy (disaster recovery).
 *   status     Show whether a key exists and its fingerprint (never the key).
 *
 * The key is displayed only on an interactive terminal, so it cannot end up
 * in logs, CI output, or a chat transcript.
 */
import { existsSync, writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { fromPaper, generateMasterKey, loadMasterKey, PaperKeyError, toPaperGroups, type MasterKey } from './crypto.js';

const KEY_FILE = process.env.XPM_MASTER_KEY_FILE ?? '/secrets/protected_master_key';

function requireTty(): void {
  if (!process.stdout.isTTY || !process.stdin.isTTY) {
    throw new Error(
      'This command shows or reads the secret key and only runs in an interactive terminal.\n' +
        'Run it yourself in a terminal window: docker compose run --rm keytool <command>',
    );
  }
}

function prompt(question: string): Promise<string> {
  return new Promise((resolve) => {
    const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

function clearScreen(): void {
  process.stdout.write('\x1b[2J\x1b[3J\x1b[H');
}

function writeKeyFile(mk: MasterKey): void {
  writeFileSync(KEY_FILE, `${mk.key.toString('base64')}\n`, { mode: 0o644, flag: 'wx' });
}

function printPaperSheet(mk: MasterKey): void {
  const groups = toPaperGroups(mk);
  const rows = [groups.slice(0, 5), groups.slice(5, 10), groups.slice(10, 14)];
  const line = '─'.repeat(58);
  console.log(`
┌${line}┐
  QUESTALINA DESK: PROTECTED DATA RECOVERY KEY
  Key fingerprint: ${mk.id}        Created: ${new Date().toISOString().slice(0, 10)}
├${line}┤

    ${rows.map((r, i) => `${i + 1}.  ${r.join('  ')}`).join('\n\n    ')}

├${line}┤
  Copy all 14 groups exactly. The last group is a checksum.
  Characters used: 0-9 and A-Z except I, L, O, U.
  Anyone with this key can decrypt stored customer originals.
  Keep it in a safe place, away from the workstation.
  Restore: docker compose run --rm keytool restore
└${line}┘
`);
}

async function verifyInteractively(mk: MasterKey): Promise<boolean> {
  for (let attempt = 1; attempt <= 3; attempt++) {
    const typed = await prompt('Type the key from your paper copy (spaces optional): ');
    try {
      const fromPaperKey = fromPaper(typed);
      if (fromPaperKey.key.equals(mk.key)) {
        console.log('✔ Paper copy verified. It matches the stored key.');
        return true;
      }
      console.log('✘ That is a valid key, but not this installation’s key.');
    } catch (err) {
      console.log(`✘ ${err instanceof PaperKeyError ? err.message : 'Could not read that key'}`);
    }
    if (attempt < 3) console.log('Check your copy and try again.\n');
  }
  return false;
}

async function main(command: string | undefined, flags: string[]): Promise<number> {
  switch (command) {
    case 'status': {
      if (!existsSync(KEY_FILE)) {
        console.log('No master key yet. Run: docker compose run --rm keytool generate');
        return 1;
      }
      console.log(`Master key present. Fingerprint: ${loadMasterKey(KEY_FILE).id}`);
      return 0;
    }

    case 'generate': {
      if (existsSync(KEY_FILE)) {
        console.error(`A master key already exists (fingerprint ${loadMasterKey(KEY_FILE).id}). Refusing to overwrite.`);
        return 1;
      }
      // Disposable test installations only: create a key without a paper copy.
      if (flags.includes('--no-paper-test-only')) {
        const mk = generateMasterKey();
        writeKeyFile(mk);
        console.log(`Test key created without paper backup. Fingerprint: ${mk.id}`);
        return 0;
      }
      requireTty();
      const mk = generateMasterKey();
      clearScreen();
      printPaperSheet(mk);
      await prompt('Copy the key onto paper, then press Enter to continue… ');
      clearScreen();
      console.log('Now confirm your paper copy. The key is no longer on screen.\n');
      if (!(await verifyInteractively(mk))) {
        console.log('\nThe key was NOT saved. Run generate again and copy carefully.');
        return 1;
      }
      writeKeyFile(mk);
      console.log(`\nMaster key saved. Fingerprint: ${mk.id}`);
      console.log('Store the paper copy somewhere safe, away from this workstation.');
      return 0;
    }

    case 'paper': {
      requireTty();
      const mk = loadMasterKey(KEY_FILE);
      clearScreen();
      printPaperSheet(mk);
      await prompt('Press Enter to clear the screen… ');
      clearScreen();
      return 0;
    }

    case 'verify': {
      requireTty();
      return (await verifyInteractively(loadMasterKey(KEY_FILE))) ? 0 : 1;
    }

    case 'restore': {
      requireTty();
      if (existsSync(KEY_FILE)) {
        console.error(`A master key already exists (fingerprint ${loadMasterKey(KEY_FILE).id}). Remove it first if you really mean to replace it.`);
        return 1;
      }
      const typed = await prompt('Type the key from your paper copy: ');
      const mk = fromPaper(typed);
      writeKeyFile(mk);
      clearScreen();
      console.log(`Master key restored. Fingerprint: ${mk.id}`);
      return 0;
    }

    default:
      console.log('Usage: docker compose run --rm keytool generate|verify|paper|restore|status');
      return command === undefined || command === 'help' ? 0 : 2;
  }
}

try {
  process.exitCode = await main(process.argv[2], process.argv.slice(3));
} catch (err) {
  console.error(`Error: ${(err as Error).message}`);
  process.exitCode = 1;
}
