import { describe, expect, it } from 'vitest';
import {
  decrypt,
  DecryptionError,
  encrypt,
  fromPaper,
  generateMasterKey,
  PaperKeyError,
  toPaperGroups,
} from '../src/crypto.js';

describe('envelope encryption', () => {
  const mk = generateMasterKey();

  it('round-trips and never contains the plaintext', () => {
    const blob = encrypt(mk, 'jane.doe@example.com', 'identity:42');
    expect(blob.includes(Buffer.from('jane.doe'))).toBe(false);
    expect(decrypt(mk, blob, 'identity:42').toString()).toBe('jane.doe@example.com');
  });

  it('binds ciphertext to its record via AAD', () => {
    const blob = encrypt(mk, 'secret', 'original:1');
    expect(() => decrypt(mk, blob, 'original:2')).toThrow(DecryptionError);
  });

  it('detects tampering and wrong keys', () => {
    const blob = encrypt(mk, 'secret', 'a');
    const tampered = Buffer.from(blob);
    tampered[tampered.length - 1]! ^= 1;
    expect(() => decrypt(mk, tampered, 'a')).toThrow(DecryptionError);
    expect(() => decrypt(generateMasterKey(), blob, 'a')).toThrow(/Encrypted with key/);
  });
});

describe('paper backup', () => {
  it('is 14 groups of 4 and round-trips exactly', () => {
    const mk = generateMasterKey();
    const groups = toPaperGroups(mk);
    expect(groups).toHaveLength(14);
    expect(groups.every((g) => /^[0-9A-HJKMNP-TV-Z]{4}$/.test(g))).toBe(true);
    expect(fromPaper(groups.join(' ')).key.equals(mk.key)).toBe(true);
  });

  it('tolerates lowercase, dashes, and O/I/L confusion', () => {
    for (let i = 0; i < 50; i++) {
      const mk = generateMasterKey();
      const text = toPaperGroups(mk)
        .join('-')
        .toLowerCase()
        .replace(/0/g, 'o')
        .replace(/1/g, 'l');
      expect(fromPaper(text).key.equals(mk.key)).toBe(true);
    }
  });

  it('catches a single mistyped character with the checksum', () => {
    let caught = 0;
    for (let i = 0; i < 200; i++) {
      const mk = generateMasterKey();
      const chars = toPaperGroups(mk).join('').split('');
      const pos = i % 52; // a key character, not the checksum
      chars[pos] = chars[pos] === 'A' ? 'B' : 'A';
      try {
        fromPaper(chars.join(''));
      } catch (err) {
        if (err instanceof PaperKeyError) caught++;
      }
    }
    // 20-bit checksum: a miss is ~1 in a million per typo.
    expect(caught).toBe(200);
  });

  it('rejects wrong lengths', () => {
    expect(() => fromPaper('ABCD')).toThrow(PaperKeyError);
  });
});
