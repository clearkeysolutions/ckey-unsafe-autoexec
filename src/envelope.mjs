// Parsing and verification of CKey Safe Action envelopes
// (spec/CKey-Safe-Actions.md in github.com/clearkeysolutions/ckey), with the
// platform's own Ed25519 (WebCrypto). Same verdicts as the official core:
// ok, integrity, expired, invalid; tested against the official vectors.
//
// Verification here says an envelope is genuine. It says nothing about whether
// running it is a good idea; that decision is yours in this package.

export const PREFIX = 'ckey-action:1:';
export const SAME_DEVICE = 'same-device';
export const CROSS_DEVICE = 'cross-device';
export const CLOCK_TOLERANCE_SECONDS = 120;
export const MAX_LIFETIME_CAP = 3600;

const CONTEXT = new TextEncoder().encode('CKey Safe Action v1\0');
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const B64_INDEX = new Map([...B64].map((c, i) => [c, i]));
const L = (1n << 252n) + 27742317777372353535851937790883648493n;

const FIELD_RULES = {
  issuer: [/^(?=.*\.)[a-z0-9.-]{1,253}$/, 'issuer must be a lower-case DNS name with a dot'],
  app: [/^[A-Za-z0-9._-]{1,255}$/, 'app is 1 to 255 of A-Z a-z 0-9 . _ -'],
  action: [/^[a-z0-9._-]{1,64}$/, 'action is 1 to 64 of a-z 0-9 . _ -'],
  key_id: [/^[A-Za-z0-9._-]{1,32}$/, 'key_id is 1 to 32 of A-Z a-z 0-9 . _ -'],
  request_id: [/^[A-Za-z0-9_-]{8,64}$/, 'request_id is 8 to 64 of A-Z a-z 0-9 _ -']
};

export class SafeActionError extends Error {
  /** @param {'invalid'|'integrity'|'expired'} verdict */
  constructor(verdict, message, fields = null) {
    super(message);
    this.name = 'SafeActionError';
    this.verdict = verdict;
    this.fields = fields;
  }
}

function base64urlDecode(text) {
  if (!text.length || text.length % 4 === 1) throw new SafeActionError('invalid', 'not base64url');
  const out = new Uint8Array(Math.floor((text.length * 6) / 8));
  let bits = 0, value = 0, o = 0;
  for (const c of text) {
    const v = B64_INDEX.get(c);
    if (v === undefined) throw new SafeActionError('invalid', 'not base64url');
    value = (value << 6) | v;
    bits += 6;
    if (bits >= 8) { bits -= 8; out[o++] = (value >> bits) & 0xff; }
  }
  if (bits && (value & ((1 << bits) - 1))) throw new SafeActionError('invalid', 'non-canonical base64url');
  return out;
}

/** True when text is a Safe Action payload (says nothing about whether it is valid). */
export function isSafeAction(text) {
  return typeof text === 'string' && text.startsWith(PREFIX) && text.length > PREFIX.length;
}

/**
 * Parses an envelope without checking the signature. Throws SafeActionError
 * ('invalid'). The result is NOT verified; never act on it.
 */
export function parseEnvelope(text) {
  if (!isSafeAction(text)) throw new SafeActionError('invalid', 'not a Safe Action');
  const bytes = base64urlDecode(text.slice(PREFIX.length));
  let i = 0;
  const need = (n) => { if (i + n > bytes.length) throw new SafeActionError('invalid', 'truncated'); };
  const u8 = () => { need(1); return bytes[i++]; };
  const str = (name) => {
    const n = u8(); need(n);
    let s = '';
    for (let k = 0; k < n; k++) s += String.fromCharCode(bytes[i + k]);
    i += n;
    const [rule, why] = FIELD_RULES[name];
    if (!rule.test(s) || /[^\x21-\x7e]/.test(s)) throw new SafeActionError('invalid', why);
    return s;
  };
  const u64 = () => { need(8); let v = 0n; for (let k = 0; k < 8; k++) v = (v << 8n) | BigInt(bytes[i++]); return v; };
  if (u8() !== 1) throw new SafeActionError('invalid', 'unsupported envelope version');
  const scopeByte = u8();
  if (scopeByte > 1) throw new SafeActionError('invalid', 'unknown scope');
  const fields = { scope: scopeByte === 1 ? CROSS_DEVICE : SAME_DEVICE };
  for (const name of ['issuer', 'app', 'action', 'key_id', 'request_id']) fields[name] = str(name);
  const issued = u64(), expires = u64();
  if (issued > BigInt(Number.MAX_SAFE_INTEGER) || expires > BigInt(Number.MAX_SAFE_INTEGER)) throw new SafeActionError('invalid', 'time out of range');
  fields.issued_at = Number(issued);
  fields.expires_at = Number(expires);
  need(2);
  const plen = (bytes[i] << 8) | bytes[i + 1];
  i += 2;
  if (plen > 1024) throw new SafeActionError('invalid', 'params longer than 1024 bytes');
  need(plen);
  fields.params = bytes.slice(i, i + plen);
  i += plen;
  const signedLength = i;
  need(64);
  const signature = bytes.slice(i, i + 64);
  i += 64;
  if (i !== bytes.length) throw new SafeActionError('invalid', 'bytes after the signature');
  return { fields, signed: bytes.subarray(0, signedLength), signature };
}

const keyCache = new WeakMap();
async function importKey(publicKey) {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== 32) throw new TypeError('a public key is 32 bytes');
  if (keyCache.has(publicKey)) return keyCache.get(publicKey);
  const key = await globalThis.crypto.subtle.importKey('raw', publicKey, { name: 'Ed25519' }, false, ['verify']);
  keyCache.set(publicKey, key);
  return key;
}

/** 64 hexadecimal digits to 32 bytes. */
export function hexKey(hex) {
  if (typeof hex !== 'string' || !/^[0-9a-fA-F]{64}$/.test(hex)) throw new TypeError('a public key is 64 hexadecimal digits');
  return Uint8Array.from(hex.match(/../g), (b) => parseInt(b, 16));
}

/**
 * Verifies an envelope: signature (with the canonical-S rule), lifetime and time.
 * Resolves to the verified fields, or throws SafeActionError with verdict
 * 'invalid', 'integrity' or 'expired'.
 */
export async function verifyEnvelope(text, publicKey, { now = Math.floor(Date.now() / 1000), maxLifetime = 600 } = {}) {
  if (!Number.isInteger(maxLifetime) || maxLifetime < 1 || maxLifetime > MAX_LIFETIME_CAP) throw new RangeError('maxLifetime is 1 to 3600 seconds');
  const { fields, signed, signature } = parseEnvelope(text);
  let s = 0n;
  for (let k = 63; k >= 32; k--) s = (s << 8n) | BigInt(signature[k]);
  if (s >= L) throw new SafeActionError('integrity', 'the signature does not match this key');
  const message = new Uint8Array(CONTEXT.length + signed.length);
  message.set(CONTEXT);
  message.set(signed, CONTEXT.length);
  const ok = await globalThis.crypto.subtle.verify({ name: 'Ed25519' }, await importKey(publicKey), signature, message);
  if (!ok) throw new SafeActionError('integrity', 'the signature does not match this key');
  const { issued_at: issued, expires_at: expires } = fields;
  const why = expires <= issued ? 'expires before it is issued'
    : expires - issued > maxLifetime ? 'valid for longer than this app allows'
    : now + CLOCK_TOLERANCE_SECONDS < issued ? 'issued in the future'
    : now >= expires ? 'expired' : null;
  if (why) throw new SafeActionError('expired', 'Safe Action ' + why, fields);
  return fields;
}
