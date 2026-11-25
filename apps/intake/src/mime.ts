import type { GmailMessage, GmailPart } from './google.js';

import { decodeEncodedWords } from '@xpm/privacy';

export { decodeEncodedWords };

export interface Address {
  name?: string;
  address: string;
}

/** Parse an address-list header, respecting quoted display names. */
export function parseAddressList(value: string | undefined): Address[] {
  if (!value) return [];
  const out: Address[] = [];
  let current = '';
  let inQuotes = false;
  let depth = 0;
  const flush = () => {
    const part = current.trim();
    current = '';
    if (!part) return;
    const angle = /^(.*)<([^>]+)>\s*$/.exec(part);
    if (angle) {
      const name = decodeEncodedWords(angle[1]!.trim().replace(/^"|"$/g, '').replace(/\\"/g, '"')).trim();
      out.push({ ...(name ? { name } : {}), address: angle[2]!.trim() });
    } else if (part.includes('@')) {
      out.push({ address: part.replace(/\(.*\)/, '').trim() });
    }
  };
  for (const ch of value) {
    if (ch === '"') inQuotes = !inQuotes;
    if (!inQuotes && ch === '<') depth++;
    if (!inQuotes && ch === '>') depth--;
    if (ch === ',' && !inQuotes && depth === 0) flush();
    else current += ch;
  }
  flush();
  return out;
}

export function header(part: GmailPart, name: string): string | undefined {
  return part.headers?.find((h) => h.name.toLowerCase() === name.toLowerCase())?.value;
}

function charsetOf(part: GmailPart): string {
  const ct = header(part, 'Content-Type') ?? '';
  return /charset="?([^";\s]+)"?/i.exec(ct)?.[1]?.toLowerCase() ?? 'utf-8';
}

function decodeBody(part: GmailPart): string {
  if (!part.body?.data) return '';
  const bytes = Buffer.from(part.body.data, 'base64url');
  try {
    return new TextDecoder(charsetOf(part), { fatal: false }).decode(bytes);
  } catch {
    return bytes.toString('utf8');
  }
}

export interface ExtractedBody {
  text?: string;
  html?: string;
  attachments: { mimeType: string; size: number }[];
}

/** Collect the first text/plain and text/html bodies; record attachments by type and size only. */
export function extractBody(root: GmailPart): ExtractedBody {
  const result: ExtractedBody = { attachments: [] };
  const walk = (p: GmailPart) => {
    const disposition = header(p, 'Content-Disposition') ?? '';
    const isAttachment = Boolean(p.filename) || /attachment/i.test(disposition) || Boolean(p.body?.attachmentId);
    if (isAttachment && !p.mimeType.startsWith('multipart/')) {
      result.attachments.push({ mimeType: p.mimeType, size: p.body?.size ?? 0 });
      return;
    }
    if (p.mimeType === 'text/plain' && result.text === undefined) result.text = decodeBody(p);
    else if (p.mimeType === 'text/html' && result.html === undefined) result.html = decodeBody(p);
    for (const child of p.parts ?? []) walk(child);
  };
  walk(root);
  return result;
}

export type SkipReason = 'outgoing' | 'draft' | 'spam' | 'trash' | 'chat';

/** Which messages are "incoming correspondence". Sent mail, drafts, spam, trash and chats are not. */
export function skipReason(msg: GmailMessage): SkipReason | null {
  const labels = new Set(msg.labelIds ?? []);
  if (labels.has('DRAFT')) return 'draft';
  if (labels.has('SPAM')) return 'spam';
  if (labels.has('TRASH')) return 'trash';
  if (labels.has('CHAT')) return 'chat';
  if (labels.has('SENT') && !labels.has('INBOX')) return 'outgoing';
  return null;
}
