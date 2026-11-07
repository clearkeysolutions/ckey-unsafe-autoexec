// Developer-controlled execution of verified CKey Safe Action envelopes.
//
// This module verifies exactly what the official CKey SDK verifies (signature,
// app, registered action and issuer, lifetime, time, single use). It then hands
// the verified action to YOU and lets you decide whether, when and after which
// prompt it runs. That is the difference from the official SDK, which shows its
// own confirmation for cross-device actions and offers no way around it.
//
// Nothing here is unsafe by itself. What changes is who is responsible: with
// this module, you are. Codes it runs are not Safe Actions, and products built
// on it may not claim CKey Safe Actions, certification, or that an action was
// brokered by CKey (https://openckey.org/trademark).

import { CROSS_DEVICE, MAX_LIFETIME_CAP, SAME_DEVICE, SafeActionError, hexKey, isSafeAction, parseEnvelope, verifyEnvelope } from './envelope.mjs';

const UNSAFE_NOTICE = 'ckey-unsafe-autoexec: you decide when verified actions run and what the person sees first. ' +
  'Follow spec/CKey-Safe-Actions.md: never run a cross-device action without a confirmation that shows who is asking. ' +
  'Codes run this way are not CKey Safe Actions. Pass { acknowledgeUnsafe: true } to silence this notice.';
let noticeShown = false;

const shortText = (v, max = 120) => (typeof v === 'string' && v.length && v.length <= max ? v : null);

/** Request information must come over HTTPS from the issuer's own domain. */
export function requestInfoUrl(template, issuer, requestId) {
  if (typeof template !== 'string') return null;
  let url;
  try { url = new URL(template.replace('{request_id}', encodeURIComponent(requestId))); } catch { return null; }
  if (url.protocol !== 'https:' || url.username || url.password) return null;
  if (!(url.hostname === issuer || url.hostname.endsWith('.' + issuer))) return null;
  return url.href;
}

export class UnsafeAutoExec {
  #appId; #maxLifetime; #fetch; #now;
  #keys = new Map();
  #actions = new Map();
  #seen = new Map();

  /**
   * @param {string} appId this app's ID, for example 'com.viadere'
   * @param {{ maxLifetime?: number, fetch?: typeof fetch, now?: () => number, acknowledgeUnsafe?: boolean }} [options]
   */
  constructor(appId, { maxLifetime = 600, fetch = globalThis.fetch?.bind(globalThis), now = () => Date.now(), acknowledgeUnsafe = false } = {}) {
    if (typeof appId !== 'string' || !/^[A-Za-z0-9._-]{1,255}$/.test(appId)) throw new TypeError('appId must be an app ID such as com.example.app');
    if (!Number.isInteger(maxLifetime) || maxLifetime < 1 || maxLifetime > MAX_LIFETIME_CAP) throw new RangeError('maxLifetime is 1 to 3600 seconds');
    this.#appId = appId;
    this.#maxLifetime = maxLifetime;
    this.#fetch = fetch;
    this.#now = now;
    if (!acknowledgeUnsafe && !noticeShown) { noticeShown = true; console.warn(UNSAFE_NOTICE); }
  }

  /** Pins an issuer's Ed25519 public key (64 hex digits or 32 bytes). requestInfo is its request_info URL template. */
  trust(issuer, keyId, publicKey, { requestInfo } = {}) {
    if (typeof issuer !== 'string' || !/^[a-z0-9.-]+\.[a-z0-9-]+$/.test(issuer)) throw new TypeError('issuer is a lower-case domain name');
    if (typeof keyId !== 'string' || !/^[A-Za-z0-9._-]{1,32}$/.test(keyId)) throw new TypeError('keyId is 1 to 32 letters, digits, . _ or -');
    const key = publicKey instanceof Uint8Array ? publicKey : hexKey(publicKey);
    if (key.length !== 32) throw new TypeError('a public key is 32 bytes');
    this.#keys.set(issuer + ' ' + keyId, { key, requestInfo: requestInfo ?? null });
    return this;
  }

  /** Registers an action and the issuers allowed to request it. */
  register(action, { issuers, issuer, scope = SAME_DEVICE } = {}, handler) {
    if (typeof action !== 'string' || !/^[a-z0-9._-]{1,64}$/.test(action)) throw new TypeError('action is 1 to 64 of a-z 0-9 . _ -');
    if (scope !== SAME_DEVICE && scope !== CROSS_DEVICE) throw new TypeError('scope is SAME_DEVICE or CROSS_DEVICE');
    if (typeof handler !== 'function') throw new TypeError('a handler function is required');
    const list = issuers ?? (issuer ? [issuer] : []);
    if (!list.length) throw new TypeError('name the issuer or issuers allowed to request this action');
    this.#actions.set(action, { issuers: new Set(list), scope, handler });
    return this;
  }

  /**
   * Verifies a decoded payload. Resolves to one of:
   *   { kind: 'not-safe-action' }                      follow the ordinary payload rules
   *   { kind: 'rejected', verdict, reason }            did not verify; run nothing
   *   { kind: 'verified', action, scope, run, requestInfo }
   * `scope` is the stricter of the envelope's and your registration's.
   * `run()` runs the handler once. `requestInfo()` fetches the issuer's account
   * of who is asking (device, place, time), for your confirmation.
   */
  async inspect(text) {
    if (!isSafeAction(text)) return { kind: 'not-safe-action' };
    let claimed;
    try { claimed = parseEnvelope(text).fields; }
    catch (error) { return { kind: 'rejected', verdict: 'invalid', reason: error.message }; }
    const reject = (verdict, reason) => ({ kind: 'rejected', verdict, reason });
    if (claimed.app !== this.#appId) return reject('policy', 'this code is for another app (' + claimed.app + ')');
    const registered = this.#actions.get(claimed.action);
    if (!registered) return reject('policy', 'this app does not accept the action ' + claimed.action);
    if (!registered.issuers.has(claimed.issuer)) return reject('policy', claimed.issuer + ' may not request ' + claimed.action);
    const trusted = this.#keys.get(claimed.issuer + ' ' + claimed.key_id);
    if (!trusted) return reject('policy', 'no trusted key ' + claimed.key_id + ' for ' + claimed.issuer);
    const nowMs = this.#now();
    let fields;
    try { fields = await verifyEnvelope(text, trusted.key, { now: Math.floor(nowMs / 1000), maxLifetime: this.#maxLifetime }); }
    catch (error) { return error instanceof SafeActionError ? reject(error.verdict, error.message) : reject('invalid', String(error.message || error)); }
    for (const [id, until] of this.#seen) if (until < nowMs) this.#seen.delete(id);
    if (this.#seen.has(fields.request_id)) return reject('policy', 'this code has already been used');
    this.#seen.set(fields.request_id, fields.expires_at * 1000 + 120000);
    let paramsText = null, paramsJSON = null;
    try { paramsText = new TextDecoder('utf-8', { fatal: true }).decode(fields.params); paramsJSON = paramsText ? JSON.parse(paramsText) : null; } catch {}
    const action = Object.freeze({
      issuer: fields.issuer, app: fields.app, action: fields.action, keyId: fields.key_id, requestId: fields.request_id,
      scope: fields.scope, issuedAt: fields.issued_at, expiresAt: fields.expires_at, params: fields.params, paramsText, paramsJSON
    });
    const scope = fields.scope === CROSS_DEVICE || registered.scope === CROSS_DEVICE ? CROSS_DEVICE : SAME_DEVICE;
    let ran = false;
    return {
      kind: 'verified', action, scope,
      run: async () => { if (ran) throw new Error('this action has already run'); ran = true; return registered.handler(action); },
      requestInfo: () => this.#requestInfo(trusted.requestInfo, fields.issuer, fields.request_id)
    };
  }

  /**
   * Verifies, then asks `decide(verified)` whether to run. Return true (or a
   * promise of true) to run the handler. Resolves to inspect()'s result plus
   * { ran, result }.
   */
  async handle(text, decide) {
    if (typeof decide !== 'function') throw new TypeError('decide(verified) is required: you choose whether each action runs');
    const verified = await this.inspect(text);
    if (verified.kind !== 'verified') return verified;
    if (!(await decide(verified))) return { ...verified, ran: false };
    return { ...verified, ran: true, result: await verified.run() };
  }

  async #requestInfo(template, issuer, requestId) {
    const url = requestInfoUrl(template, issuer, requestId);
    if (!url || !this.#fetch) return null;
    try {
      const response = await this.#fetch(url, { headers: { Accept: 'application/json' }, redirect: 'error' });
      if (!response.ok) return null;
      const info = await response.json();
      if (!info || info.request_id !== requestId || info.status !== 'pending') return null;
      return { device: shortText(info.device), location: shortText(info.location), requestedAt: shortText(info.requested_at, 40) };
    } catch {
      return null;
    }
  }
}
