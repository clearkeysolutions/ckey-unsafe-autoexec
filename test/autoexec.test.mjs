import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { CROSS_DEVICE, SAME_DEVICE, SafeActionError, hexKey, parseEnvelope, verifyEnvelope } from '../src/envelope.mjs';
import { UnsafeAutoExec, requestInfoUrl } from '../src/autoexec.mjs';

// The official vectors (tests/vectors/safe-actions-v1.json in the CKey repository).
const { vectors } = JSON.parse(readFileSync(new URL('./fixtures/safe-actions-v1.json', import.meta.url), 'utf8'));
const KEY = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
const NOW_MS = 1794000000 * 1000;
const payload = (name) => vectors.find((v) => v.name === name).payload;

test('reaches every official verdict', async () => {
  assert.ok(vectors.length >= 20);
  for (const v of vectors) {
    let verdict = 'ok', fields = null;
    try { fields = await verifyEnvelope(v.payload, hexKey(v.public_key), { now: v.now, maxLifetime: v.max_lifetime }); }
    catch (error) { assert.ok(error instanceof SafeActionError, v.name + ': ' + error); verdict = error.verdict; }
    const ok = v.expect === 'invalid_or_integrity' ? ['invalid', 'integrity'].includes(verdict) : verdict === v.expect;
    assert.ok(ok, `${v.name}: expected ${v.expect}, got ${verdict}`);
    if (v.expect === 'ok') {
      assert.equal(fields.issuer, v.fields.issuer);
      assert.equal(fields.request_id, v.fields.request_id);
      assert.equal(fields.scope, v.fields.scope === 1 ? CROSS_DEVICE : SAME_DEVICE);
      assert.equal(new TextDecoder().decode(fields.params), v.fields.params);
    }
  }
});

const actions = (opts = {}) => new UnsafeAutoExec('com.viadere', { now: () => NOW_MS, acknowledgeUnsafe: true, ...opts });

test('the developer decides; nothing runs unless decide() says so; single use', async () => {
  let ran = 0;
  const a = actions().trust('citeory.com', '2026-11', KEY).register('open.library', { issuer: 'citeory.com' }, () => ++ran);
  const declined = await a.handle(payload('valid same-device action'), () => false);
  assert.equal(declined.kind, 'verified');
  assert.equal(declined.ran, false);
  assert.equal(ran, 0);
  const again = await a.handle(payload('valid same-device action'), () => true);
  assert.equal(again.kind, 'rejected', 'the request ID was used by the first inspection');
  assert.equal(ran, 0);
  const b = actions().trust('citeory.com', '2026-11', KEY).register('open.library', { issuer: 'citeory.com' }, () => ++ran);
  const done = await b.handle(payload('valid same-device action'), (v) => v.scope === SAME_DEVICE);
  assert.equal(done.ran, true);
  assert.equal(done.action.paramsJSON.item, 'apa-7');
  assert.equal(ran, 1);
  await assert.rejects(() => done.run(), /already run/);
  await assert.rejects(() => b.handle('x'), /decide/);
});

test('policy checks match the official SDK', async () => {
  const run = () => assert.fail('must not run');
  const text = payload('valid same-device action');
  assert.equal((await actions().inspect('https://citeory.com')).kind, 'not-safe-action');
  assert.match((await new UnsafeAutoExec('com.other', { acknowledgeUnsafe: true, now: () => NOW_MS }).trust('citeory.com', '2026-11', KEY).register('open.library', { issuer: 'citeory.com' }, run).inspect(text)).reason, /another app/);
  assert.match((await actions().trust('citeory.com', '2026-11', KEY).inspect(text)).reason, /does not accept/);
  assert.match((await actions().register('open.library', { issuer: 'example.org' }, run).inspect(text)).reason, /may not request/);
  assert.match((await actions().register('open.library', { issuer: 'citeory.com' }, run).inspect(text)).reason, /no trusted key/);
  const late = await actions({ now: () => NOW_MS + 3600e3 }).trust('citeory.com', '2026-11', KEY).register('open.library', { issuer: 'citeory.com' }, run).inspect(text);
  assert.equal(late.verdict, 'expired');
});

test('cross-device scope is reported, and request information comes only from the issuer over HTTPS', async () => {
  const urls = [];
  const fetch = async (url) => { urls.push(url); return Response.json({ request_id: 'sess-41fd0a9be2c74', device: 'Chrome on Windows', location: 'near Lagos, Nigeria', requested_at: '2026-11-07T20:14:03Z', status: 'pending' }); };
  const a = actions({ fetch }).trust('citeory.com', '2026-11', KEY, { requestInfo: 'https://citeory.com/api/ckey/requests/{request_id}' })
    .register('signin.request', { issuer: 'citeory.com' }, () => 'signed in');
  const v = await a.inspect(payload('valid cross-device sign-in, no params'));
  assert.equal(v.scope, CROSS_DEVICE);
  assert.deepEqual(await v.requestInfo(), { device: 'Chrome on Windows', location: 'near Lagos, Nigeria', requestedAt: '2026-11-07T20:14:03Z' });
  assert.deepEqual(urls, ['https://citeory.com/api/ckey/requests/sess-41fd0a9be2c74']);
  assert.equal(requestInfoUrl('http://citeory.com/{request_id}', 'citeory.com', 'x'), null);
  assert.equal(requestInfoUrl('https://evilciteory.com/{request_id}', 'citeory.com', 'x'), null);
  assert.equal(requestInfoUrl('https://citeory.com@evil.example/{request_id}', 'citeory.com', 'x'), null);
});

test('parseEnvelope is not verification', () => {
  const { fields } = parseEnvelope(payload('signed by a different key'));
  assert.equal(fields.issuer, 'citeory.com', 'parses a forged envelope; only verifyEnvelope may be trusted');
});

test('a notice is printed once unless acknowledged', async () => {
  const saved = console.warn;
  const lines = [];
  console.warn = (m) => lines.push(m);
  try {
    const { UnsafeAutoExec: Fresh } = await import('../src/autoexec.mjs?fresh=' + Date.now());
    new Fresh('com.viadere');
    new Fresh('com.viadere');
  } finally { console.warn = saved; }
  assert.equal(lines.length, 1);
  assert.match(lines[0], /not CKey Safe Actions/);
});
