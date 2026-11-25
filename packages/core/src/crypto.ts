import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';

/**
 * Envelope encryption for protected originals and identity mappings.
 * AES-256-GCM with a single local master key. Every ciphertext carries the
 * key fingerprint so a wrong or rotated key fails loudly, and an AAD string
 * binds it to its record (a ciphertext copied to another row will not decrypt).
 */

export const MASTER_KEY_BYTES = 32;
const VERSION = 1;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const KEY_ID_BYTES = 4;

export interface MasterKey {
  key: Buffer;
  /** Non-secret fingerprint, e.g. "a1b2c3d4". Safe to log and print. */
  id: string;
}

export function keyFingerprint(key: Buffer): string {
  return createHash('sha256').update('xpm-master-key-id').update(key).digest('hex').slice(0, KEY_ID_BYTES * 2);
}

export function masterKeyFromBytes(key: Buffer): MasterKey {
  if (key.length !== MASTER_KEY_BYTES) throw new Error(`Master key must be ${MASTER_KEY_BYTES} bytes`);
  return { key, id: keyFingerprint(key) };
}

export function generateMasterKey(): MasterKey {
  return masterKeyFromBytes(randomBytes(MASTER_KEY_BYTES));
}

/** Key file format: one line of base64. */
export function loadMasterKey(path: string): MasterKey {
  const raw = readFileSync(path, 'utf8').trim();
  return masterKeyFromBytes(Buffer.from(raw, 'base64'));
}

export class DecryptionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DecryptionError';
  }
}

/** Layout: version(1) | keyId(4) | iv(12) | tag(16) | ciphertext */
export function encrypt(mk: MasterKey, plaintext: Buffer | string, aad: string): Buffer {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', mk.key, iv);
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const ct = Buffer.concat([cipher.update(typeof plaintext === 'string' ? Buffer.from(plaintext, 'utf8') : plaintext), cipher.final()]);
  return Buffer.concat([Buffer.from([VERSION]), Buffer.from(mk.id, 'hex'), iv, cipher.getAuthTag(), ct]);
}

export function decrypt(mk: MasterKey, blob: Buffer, aad: string): Buffer {
  const header = 1 + KEY_ID_BYTES + IV_BYTES + TAG_BYTES;
  if (blob.length < header || blob[0] !== VERSION) throw new DecryptionError('Unsupported ciphertext format');
  const keyId = blob.subarray(1, 1 + KEY_ID_BYTES).toString('hex');
  if (keyId !== mk.id) throw new DecryptionError(`Encrypted with key ${keyId}, but the loaded key is ${mk.id}`);
  const iv = blob.subarray(1 + KEY_ID_BYTES, 1 + KEY_ID_BYTES + IV_BYTES);
  const tag = blob.subarray(1 + KEY_ID_BYTES + IV_BYTES, header);
  const decipher = createDecipheriv('aes-256-gcm', mk.key, iv);
  decipher.setAAD(Buffer.from(aad, 'utf8'));
  decipher.setAuthTag(tag);
  try {
    return Buffer.concat([decipher.update(blob.subarray(header)), decipher.final()]);
  } catch {
    throw new DecryptionError('Ciphertext failed authentication (tampered, or bound to a different record)');
  }
}

export function decryptString(mk: MasterKey, blob: Buffer, aad: string): string {
  return decrypt(mk, blob, aad).toString('utf8');
}

// ---------------------------------------------------------------------------
// Paper backup encoding: Crockford base32, grouped, with a checksum group.
// ---------------------------------------------------------------------------

const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'; // no I, L, O, U

function base32Encode(bytes: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

function base32Decode(text: string, expectedBytes: number): Buffer {
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of text) {
    const idx = ALPHABET.indexOf(ch);
    if (idx < 0) throw new Error(`Invalid character "${ch}"`);
    value = ((value << 5) | idx) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  if (out.length !== expectedBytes) throw new Error(`Expected ${expectedBytes} bytes, got ${out.length}`);
  // The last character carries padding bits that must be zero; otherwise
  // two different spellings would decode to the same key.
  if (bits > 0 && (value & ((1 << bits) - 1)) !== 0) throw new Error('Last key character is not valid');
  return Buffer.from(out);
}

const KEY_CHARS = Math.ceil((MASTER_KEY_BYTES * 8) / 5); // 52
const CHECK_CHARS = 4;

function checksum(key: Buffer): string {
  return base32Encode(createHash('sha256').update('xpm-paper-check').update(key).digest()).slice(0, CHECK_CHARS);
}

/** 14 groups of 4: 13 key groups + 1 checksum group. */
export function toPaperGroups(mk: MasterKey): string[] {
  const text = base32Encode(mk.key) + checksum(mk.key);
  return text.match(/.{4}/g)!;
}

export class PaperKeyError extends Error {}

/** Parse a hand-typed paper key. Tolerates spaces, dashes, lowercase, and O/I/L confusion. */
export function fromPaper(input: string): MasterKey {
  const cleaned = input
    .toUpperCase()
    .replace(/[\s-]/g, '')
    .replace(/O/g, '0')
    .replace(/[IL]/g, '1');
  if (cleaned.length !== KEY_CHARS + CHECK_CHARS) {
    throw new PaperKeyError(`Expected ${KEY_CHARS + CHECK_CHARS} characters, got ${cleaned.length}`);
  }
  let key: Buffer;
  try {
    key = base32Decode(cleaned.slice(0, KEY_CHARS), MASTER_KEY_BYTES);
  } catch (err) {
    throw new PaperKeyError((err as Error).message);
  }
  if (checksum(key) !== cleaned.slice(KEY_CHARS)) {
    throw new PaperKeyError('Checksum does not match: at least one character was copied incorrectly');
  }
  return masterKeyFromBytes(key);
}
