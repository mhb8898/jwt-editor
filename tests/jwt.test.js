// Node built-in test runner
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  toBase64Url, fromBase64Url, signJwt, verifyJwt,
  generateKeyPair, exportKeyPEM
} from '../lib/jwt.js';

test('base64url roundtrip', () => {
  const msg = new TextEncoder().encode('hello');
  const b64u = toBase64Url(msg);
  const back = fromBase64Url(b64u);
  assert.equal(new TextDecoder().decode(back), 'hello');
});

test('HS256 sign/verify', async () => {
  const header = { alg:'HS256', typ:'JWT' };
  const payload = { sub:'123', name:'Alice', iat: 1516239022 };
  const secret = 'secret';
  const tok = await signJwt({ alg:'HS256', header, payload, key: secret });
  const { ok } = await verifyJwt(tok, { key: secret });
  assert.equal(ok, true);
  const { ok: bad } = await verifyJwt(tok, { key: 'wrong' });
  assert.equal(bad, false);
});

test('RS256 sign/verify with generated keys', async () => {
  const kp = await generateKeyPair('RS256');
  const pubPem = await exportKeyPEM('spki', kp.publicKey, 'PUBLIC KEY');
  const pk8Pem = await exportKeyPEM('pkcs8', kp.privateKey, 'PRIVATE KEY');
  const header = { alg:'RS256', typ:'JWT' };
  const payload = { sub:'u1', role:'admin' };
  const tok = await signJwt({ alg:'RS256', header, payload, key: pk8Pem });
  const { ok } = await verifyJwt(tok, { key: pubPem });
  assert.equal(ok, true);
});

test('PS256 sign/verify with generated keys', async () => {
  const kp = await generateKeyPair('PS256');
  const pubPem = await exportKeyPEM('spki', kp.publicKey, 'PUBLIC KEY');
  const pk8Pem = await exportKeyPEM('pkcs8', kp.privateKey, 'PRIVATE KEY');
  const header = { alg:'PS256', typ:'JWT' };
  const payload = { sub:'u2', feature:'ps' };
  const tok = await signJwt({ alg:'PS256', header, payload, key: pk8Pem });
  const { ok } = await verifyJwt(tok, { key: pubPem });
  assert.equal(ok, true);
});

test('none alg', async () => {
  const header = { alg:'none', typ:'JWT' };
  const payload = { ok:true };
  const tok = await signJwt({ alg:'none', header, payload, key: null });
  const { ok } = await verifyJwt(tok);
  assert.equal(ok, true);
});

