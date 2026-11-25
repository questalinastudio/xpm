/**
 * Text normalization applied to all untrusted input before storage,
 * redaction, or model calls.
 */

// Zero-width, bidi override, and other invisible formatting characters are a
// common way to hide instructions from human reviewers.
const INVISIBLE = /[­᠎​-‏‪-‮⁠-⁤⁦-⁩﻿]/g;
// C0/C1 controls except tab and newline.
const CONTROL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g;

export function normalizeText(input: string): string {
  // Encoded words would otherwise carry names past redaction in base64.
  return decodeEncodedWords(input)
    .normalize('NFKC')
    .replace(/\r\n?/g, '\n')
    .replace(INVISIBLE, '')
    .replace(CONTROL, '')
    .replace(/[ \t]+\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

const ENTITIES: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };

/** Minimal HTML-to-text for email bodies. Drops scripts, styles, comments, and hidden elements. */
export function htmlToText(html: string): string {
  return html
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/<(script|style|head|template)[\s\S]*?<\/\1>/gi, '')
    .replace(/<([a-z0-9]+)[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|hidden)[^>]*>[\s\S]*?<\/\1>/gi, '')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/(p|div|li|tr|h[1-6]|blockquote)>/gi, '\n')
    .replace(/<li[^>]*>/gi, '- ')
    .replace(/<[^>]+>/g, '')
    .replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e: string) => {
      if (e[0] === '#') {
        const code = e[1]?.toLowerCase() === 'x' ? Number.parseInt(e.slice(2), 16) : Number.parseInt(e.slice(1), 10);
        return Number.isFinite(code) && code > 0 && code < 0x110000 ? String.fromCodePoint(code) : '';
      }
      return ENTITIES[e.toLowerCase()] ?? m;
    });
}

/** Shannon entropy in bits per character. */
export function entropy(s: string): number {
  if (!s) return 0;
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Decode RFC 2047 encoded words (MIME headers), e.g. "=?UTF-8?B?SmFuZQ==?=". */
export function decodeEncodedWords(value: string): string {
  return value
    .replace(/\?=\s+=\?/g, '?==?')
    .replace(/=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g, (_m, charset: string, enc: string, text: string) => {
      try {
        const bytes =
          enc.toUpperCase() === 'B'
            ? Buffer.from(text, 'base64')
            : Buffer.from(text.replace(/_/g, ' ').replace(/=([0-9A-F]{2})/gi, (_x, h: string) => String.fromCharCode(Number.parseInt(h, 16))), 'latin1');
        return new TextDecoder(charset.toLowerCase(), { fatal: false }).decode(bytes);
      } catch {
        return text;
      }
    });
}

