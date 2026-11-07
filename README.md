# ckey-unsafe-autoexec

Not endorsed, brokered or certified by CKey or ClearKey Solutions. Codes executed by this module are not Safe Actions.

---

`ckey-unsafe-autoexec` is the CKey web SDK ([`openckey`](https://www.npmjs.com/package/openckey)) plus one addition: it verifies [CKey Safe Action](https://github.com/clearkeysolutions/ckey/blob/Stable-Release/spec/CKey-Safe-Actions.md) envelopes and then lets **you** decide whether, when and after which prompt each one runs.

## Read this before you choose it

The official CKey SDKs control when a Safe Action runs. A same-device action runs at once; a cross-device action (for example signing in a browser on another computer) runs only after a confirmation that the SDK itself shows, naming the verified issuer and who is asking. The app has no way to skip, replace or pre-approve that confirmation. That is what lets CKey say an action was a Safe Action.

This package does the same verification and then steps aside:

- **CKey itself is not doing anything unsafe here.** Every check the official SDK makes is made here too: the Ed25519 signature (with the canonical-S rule), the receiving app, the registered action and its issuers, the lifetime, the time, and single use. This package reaches every verdict in the official conformance vectors.
- **You are taking on the responsibility the official SDK keeps.** You choose the prompt, or no prompt. If you run a cross-device action without showing who is asking, someone can relay a genuine code from their own session to a person who scans it, and nothing in the code can reveal that. That is the risk this package's name is about.
- **Most developers who use it do so in good faith**, usually to put the confirmation in their own design, and still follow every rule in the specification. Built that way, what they ship is safe. But CKey can't check that from the outside, so it can't vouch for it.

That is why codes run by this module are not Safe Actions, and why, under the [CKey trademark policy](https://openckey.org/trademark):

- a product that uses this package may say it **reads CKey codes**;
- it may **never** claim to be CKey Certified, to support CKey Safe Actions, or that an action was brokered by CKey;
- it must not describe the codes it runs as Safe Actions.

If you don't need your own prompt, use the official SDK instead: `ckey.safeActions()` in `openckey`, or `CKeySafeActions` in the Swift, Android and .NET SDKs.

## Install

```sh
npm install ckey-unsafe-autoexec
```

Everything `openckey` exports is exported here too, so this can replace it.

## Use

```js
import { UnsafeAutoExec, CROSS_DEVICE } from 'ckey-unsafe-autoexec';

const actions = new UnsafeAutoExec('com.viadere', { acknowledgeUnsafe: true })
  .trust('citeory.com', '2026-11', '<64 hex digits>', { requestInfo: 'https://citeory.com/api/ckey/requests/{request_id}' })
  .register('open.library', { issuer: 'citeory.com' }, (action) => openItem(action.paramsJSON))
  .register('signin.request', { issuer: 'citeory.com', scope: CROSS_DEVICE }, (action) => approveSignIn(action));

const outcome = await actions.handle(text, async (verified) => {
  if (verified.scope !== CROSS_DEVICE) return true;     // same-device: run at once, as the spec allows
  const info = await verified.requestInfo();             // who is asking, from the issuer's own domain
  if (!info) return false;                               // no pending request: never run
  return myConfirmation({ issuer: verified.action.issuer, ...info }); // your prompt; must show device and place
});

if (outcome.kind === 'not-safe-action') showPayload(text);        // the ordinary CKey payload rules
if (outcome.kind === 'rejected') showUnverified(outcome.reason);  // claims to be one but did not verify
```

- `inspect(text)` verifies and returns `{ kind: 'verified', action, scope, run, requestInfo }` without running anything; `run()` runs the handler once.
- `scope` is the stricter of the envelope's and your registration's.
- A request ID is spent when it is verified, even if you decide not to run it.
- `verifyEnvelope(text, publicKey, { now, maxLifetime })` and `parseEnvelope(text)` are the low-level pieces. `parseEnvelope` does not check the signature; never act on its result.
- Without `{ acknowledgeUnsafe: true }`, the first instance prints a one-line notice.

## Best practices to keep

Following these keeps what you build safe, even though it can't be called a Safe Action:

1. Verify everything, every time. Never act on `parseEnvelope` alone.
2. Never run a cross-device action without a confirmation that names the verified issuer and shows the issuer's request information (device, place, time). If it can't be fetched, or isn't `pending`, don't run it.
3. Pin issuer keys for sign-in and payments.
4. Keep the default lifetime (10 minutes) or shorter.
5. Treat `params` as untrusted input to your handler, even when the signature is good.

## Tests

```sh
npm test
```

The tests include every vector in `tests/vectors/safe-actions-v1.json` from the CKey repository.

## Licence

[BSD 3-Clause](LICENSE), with a clause that forbids using the names CKey, Open CKey or ClearKey Solutions to endorse or promote products built with it.
