// ckey-unsafe-autoexec: the CKey web SDK (openckey), plus developer-controlled
// execution of verified Safe Action envelopes. Not endorsed, brokered or
// certified by CKey or ClearKey Solutions. Codes executed by this module are
// not Safe Actions.
export * from 'openckey';
export { PREFIX, SAME_DEVICE, CROSS_DEVICE, SafeActionError, isSafeAction, parseEnvelope, verifyEnvelope, hexKey } from './envelope.mjs';
export { UnsafeAutoExec, requestInfoUrl } from './autoexec.mjs';
