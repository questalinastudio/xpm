import { randomBytes, scrypt as scryptCb, timingSafeEqual, type ScryptOptions } from 'node:crypto';

function scrypt(password: string, salt: Buffer, keylen: number, options: ScryptOptions): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scryptCb(password, salt, keylen, options, (err, key) => (err ? reject(err) : resolve(key)));
  });
}

export interface ScryptParams {
  N: number;
  r: number;
  p: number;
}

/** OWASP-recommended scrypt strength (N=2^17, r=8, p=1). */
export const DEFAULT_SCRYPT: ScryptParams = { N: 2 ** 17, r: 8, p: 1 };
const KEYLEN = 64;
export const MIN_PASSWORD_LENGTH = 12;

function maxmem({ N, r }: ScryptParams): number {
  return 128 * N * r * 2;
}

/** Format: scrypt$N$r$p$<salt b64>$<hash b64> */
export async function hashPassword(password: string, params: ScryptParams = DEFAULT_SCRYPT): Promise<string> {
  const salt = randomBytes(16);
  const key = await scrypt(password.normalize('NFKC'), salt, KEYLEN, { ...params, maxmem: maxmem(params) });
  return ['scrypt', params.N, params.r, params.p, salt.toString('base64'), key.toString('base64')].join('$');
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const [, n, r, p, saltB64, hashB64] = parts as [string, string, string, string, string, string];
  const params = { N: Number(n), r: Number(r), p: Number(p) };
  if (![params.N, params.r, params.p].every((x) => Number.isInteger(x) && x > 0)) return false;
  const expected = Buffer.from(hashB64, 'base64');
  if (expected.length !== KEYLEN) return false;
  const actual = await scrypt(password.normalize('NFKC'), Buffer.from(saltB64, 'base64'), KEYLEN, {
    ...params,
    maxmem: maxmem(params),
  });
  return timingSafeEqual(actual, expected);
}

/** A valid hash of a random password, verified against when the user does not exist to equalize timing. */
let dummyHash: Promise<string> | undefined;
export function getDummyHash(): Promise<string> {
  dummyHash ??= hashPassword(randomBytes(24).toString('base64'));
  return dummyHash;
}

export function validateNewPassword(password: string): string | null {
  if (password.length < MIN_PASSWORD_LENGTH) return `Password must be at least ${MIN_PASSWORD_LENGTH} characters`;
  if (password.length > 1024) return 'Password is too long';
  return null;
}
