// Reusable, dependency-free JWT crypto utilities (ESM)
// Works in browser (Web Crypto) and Node (node:crypto webcrypto).

const isNode = typeof process !== 'undefined' && !!process.versions?.node;

let subtle = (typeof crypto !== 'undefined' && crypto.subtle) ? crypto.subtle : undefined;
let TextEncoderCtor = typeof TextEncoder !== 'undefined' ? TextEncoder : undefined;
let TextDecoderCtor = typeof TextDecoder !== 'undefined' ? TextDecoder : undefined;

if (!subtle && isNode) {
  const { webcrypto } = await import('node:crypto');
  subtle = webcrypto.subtle;
}
if (!TextEncoderCtor && isNode) {
  const util = await import('node:util');
  TextEncoderCtor = util.TextEncoder;
  TextDecoderCtor = util.TextDecoder;
}

const enc = new TextEncoderCtor();
const dec = new TextDecoderCtor();

export function u8(arr){
  if (arr instanceof Uint8Array) return arr;
  if (arr instanceof ArrayBuffer) return new Uint8Array(arr);
  return enc.encode(String(arr));
}

export function b64encode(bytes){
  const u = u8(bytes);
  if (typeof btoa !== 'undefined') {
    let bin = '';
    for (let i=0;i<u.length;i++) bin += String.fromCharCode(u[i]);
    return btoa(bin);
  }
  // Node
  return Buffer.from(u).toString('base64');
}
export function b64decode(str){
  if (typeof atob !== 'undefined'){
    const bin = atob(str);
    const out = new Uint8Array(bin.length);
    for (let i=0;i<bin.length;i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  return new Uint8Array(Buffer.from(str, 'base64'));
}
export function toBase64Url(bytes){
  return b64encode(bytes).replace(/=+$/,'').replace(/\+/g,'-').replace(/\//g,'_');
}
export function fromBase64Url(s){
  const b64 = s.replace(/-/g,'+').replace(/_/g,'/');
  const pad = b64.length % 4 === 2 ? '==' : b64.length % 4 === 3 ? '=' : b64.length % 4 === 1 ? '===' : '';
  return b64decode(b64 + pad);
}

export function getHashForAlg(alg){
  switch(alg){
    case 'HS256': case 'RS256': case 'PS256': return 'SHA-256';
    case 'HS384': case 'RS384': case 'PS384': return 'SHA-384';
    case 'HS512': case 'RS512': case 'PS512': return 'SHA-512';
    case 'EdDSA': return null;
    case 'none': return null;
    default: return null;
  }
}

export function timingSafeEqual(a, b){
  const ua = u8(a), ub = u8(b);
  if (ua.length !== ub.length) return false;
  let res = 0;
  for (let i=0;i<ua.length;i++) res |= ua[i] ^ ub[i];
  return res === 0;
}

// PEM helpers
export function ab2b64(arr){ return b64encode(u8(arr)); }
export function b64ToPem(b64, label){
  const lines = b64.match(/.{1,64}/g)?.join('\n') || b64;
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----`;
}
export async function exportKeyPEM(format, key, label){
  const buf = await subtle.exportKey(format, key);
  return b64ToPem(ab2b64(new Uint8Array(buf)), label);
}
export function pemToArrayBuffer(pem){
  const b64 = pem.replace(/-----[^-]+-----/g,'').replace(/\s+/g,'');
  return b64decode(b64);
}

export function composeSigningInput(headerObj, payloadObj){
  const hB64 = toBase64Url(u8(JSON.stringify(headerObj)));
  const pB64 = toBase64Url(u8(JSON.stringify(payloadObj)));
  return { signingInput: `${hB64}.${pB64}`, hB64, pB64 };
}

export async function hmacSign(alg, secretBytes, dataBytes){
  const hash = getHashForAlg(alg);
  const key = await subtle.importKey('raw', u8(secretBytes), {name:'HMAC', hash}, false, ['sign']);
  const sig = await subtle.sign('HMAC', key, u8(dataBytes));
  return new Uint8Array(sig);
}
export async function hmacVerify(alg, secretBytes, dataBytes, sigBytes){
  const expected = await hmacSign(alg, secretBytes, dataBytes);
  return timingSafeEqual(expected, sigBytes);
}

export function algCategory(alg){
  if (['HS256','HS384','HS512'].includes(alg)) return 'HS';
  if (['RS256','RS384','RS512'].includes(alg)) return 'RS';
  if (['PS256','PS384','PS512'].includes(alg)) return 'PS';
  if (alg === 'EdDSA') return 'ED';
  if (alg === 'none') return 'none';
  return null;
}

export async function importPublicKey(alg, keyText){
  const cat = algCategory(alg);
  const hash = getHashForAlg(alg) || undefined;
  const text = (keyText || '').trim();
  if (!text) throw new Error('Public key required');
  if (text.startsWith('{')){
    const jwk = JSON.parse(text);
    if (cat === 'ED') return subtle.importKey('jwk', jwk, {name:'Ed25519'}, false, ['verify']);
    const algo = cat === 'RS' ? 'RSASSA-PKCS1-v1_5' : 'RSA-PSS';
    return subtle.importKey('jwk', jwk, {name: algo, hash}, false, ['verify']);
  }
  if (/BEGIN PUBLIC KEY/.test(text)){
    const spki = pemToArrayBuffer(text);
    if (cat === 'ED') return subtle.importKey('spki', spki, {name:'Ed25519'}, false, ['verify']);
    const algo = cat === 'RS' ? 'RSASSA-PKCS1-v1_5' : 'RSA-PSS';
    return subtle.importKey('spki', spki, {name: algo, hash}, false, ['verify']);
  }
  throw new Error('Unsupported public key format');
}

export async function importPrivateKey(alg, keyText){
  const cat = algCategory(alg);
  const hash = getHashForAlg(alg) || undefined;
  const text = (keyText || '').trim();
  if (!text) throw new Error('Private key required');
  if (text.startsWith('{')){
    const jwk = JSON.parse(text);
    if (cat === 'ED') return subtle.importKey('jwk', jwk, {name:'Ed25519'}, false, ['sign']);
    const algo = cat === 'RS' ? 'RSASSA-PKCS1-v1_5' : 'RSA-PSS';
    return subtle.importKey('jwk', jwk, {name: algo, hash}, false, ['sign']);
  }
  if (/BEGIN PRIVATE KEY/.test(text)){
    const pkcs8 = pemToArrayBuffer(text);
    if (cat === 'ED') return subtle.importKey('pkcs8', pkcs8, {name:'Ed25519'}, false, ['sign']);
    const algo = cat === 'RS' ? 'RSASSA-PKCS1-v1_5' : 'RSA-PSS';
    return subtle.importKey('pkcs8', pkcs8, {name: algo, hash}, false, ['sign']);
  }
  if (/BEGIN RSA PRIVATE KEY/.test(text)){
    throw new Error('PKCS#1 private key not supported by Web Crypto; convert to PKCS#8');
  }
  throw new Error('Unsupported private key format');
}

function saltLengthForAlg(alg){
  switch(alg){ case 'PS256': return 32; case 'PS384': return 48; case 'PS512': return 64; default: return 0; }
}

export async function signAsymmetric(alg, signingInput){
  const cat = algCategory(alg);
  throw new Error('signAsymmetric requires a private CryptoKey; use signJwt or pass key to signAsymWithKey');
}

export async function signAsymWithKey(alg, privateKey, signingInput){
  const cat = algCategory(alg);
  const data = u8(signingInput);
  if (cat === 'RS'){
    const sig = await subtle.sign({name:'RSASSA-PKCS1-v1_5'}, privateKey, data); return new Uint8Array(sig);
  } else if (cat === 'PS'){
    const sig = await subtle.sign({name:'RSA-PSS', saltLength: saltLengthForAlg(alg)}, privateKey, data); return new Uint8Array(sig);
  } else if (cat === 'ED'){
    try{ const sig = await subtle.sign({name:'Ed25519'}, privateKey, data); return new Uint8Array(sig); }catch{ throw new Error('Ed25519 signing unsupported'); }
  }
  throw new Error('Unsupported asymmetric alg');
}

export async function verifyAsymWithKey(alg, key, signingInput, sigBytes){
  const cat = algCategory(alg);
  const data = u8(signingInput);
  if (cat === 'RS') return subtle.verify({name:'RSASSA-PKCS1-v1_5'}, key, sigBytes, data);
  if (cat === 'PS') return subtle.verify({name:'RSA-PSS', saltLength: saltLengthForAlg(alg)}, key, sigBytes, data);
  if (cat === 'ED') { try{ return subtle.verify({name:'Ed25519'}, key, sigBytes, data); }catch{ throw new Error('Ed25519 verification unsupported'); } }
  throw new Error('Unsupported asymmetric alg');
}

export function parseJwt(token){
  const parts = String(token).trim().split('.');
  if (parts.length < 2) throw new Error('Invalid token');
  const [hb, pb, sb] = parts;
  const header = JSON.parse(dec.decode(fromBase64Url(hb)));
  const payload = JSON.parse(dec.decode(fromBase64Url(pb)));
  return { header, payload, signatureB64: sb || '', headerB64: hb, payloadB64: pb };
}

export function serializeJwt({header, payload, signatureBytes}){
  const hB64 = toBase64Url(u8(JSON.stringify(header)));
  const pB64 = toBase64Url(u8(JSON.stringify(payload)));
  if (!signatureBytes) return `${hB64}.${pB64}`;
  const sB64 = toBase64Url(signatureBytes);
  return `${hB64}.${pB64}.${sB64}`;
}

export async function signJwt({alg, header, payload, key}){
  if (alg === 'none') return serializeJwt({header:{...header, alg:'none'}, payload});
  const cat = algCategory(alg);
  const { signingInput } = composeSigningInput({...header, alg}, payload);
  if (cat === 'HS'){
    const secretBytes = typeof key === 'string' ? u8(key) : u8('');
    const sig = await hmacSign(alg, secretBytes, u8(signingInput));
    return serializeJwt({header:{...header, alg}, payload, signatureBytes: sig});
  } else {
    const privKey = await importPrivateKey(alg, key);
    const sig = await signAsymWithKey(alg, privKey, signingInput);
    return serializeJwt({header:{...header, alg}, payload, signatureBytes: sig});
  }
}

export async function verifyJwt(token, {key}={}){
  const { header, payload, signatureB64, headerB64, payloadB64 } = parseJwt(token);
  const alg = header.alg || 'none';
  if (alg === 'none') return { ok: !signatureB64, header, payload };
  if (!signatureB64) return { ok:false, header, payload };
  const signingInput = `${headerB64}.${payloadB64}`;
  if (algCategory(alg) === 'HS'){
    const secretBytes = typeof key === 'string' ? u8(key) : u8('');
    const ok = await hmacVerify(alg, secretBytes, u8(signingInput), fromBase64Url(signatureB64));
    return { ok, header, payload };
  } else {
    // try public then private
    let cryptoKey = null;
    try{ cryptoKey = await importPublicKey(alg, key); }
    catch{ cryptoKey = await importPrivateKey(alg, key); }
    const ok = await verifyAsymWithKey(alg, cryptoKey, signingInput, fromBase64Url(signatureB64));
    return { ok, header, payload };
  }
}

export async function generateKeyPair(alg){
  const cat = algCategory(alg);
  const hash = getHashForAlg(alg) || 'SHA-256';
  if (cat === 'RS'){
    return subtle.generateKey({ name:'RSASSA-PKCS1-v1_5', modulusLength:2048, publicExponent:new Uint8Array([1,0,1]), hash }, true, ['sign','verify']);
  }
  if (cat === 'PS'){
    return subtle.generateKey({ name:'RSA-PSS', modulusLength:2048, publicExponent:new Uint8Array([1,0,1]), hash }, true, ['sign','verify']);
  }
  if (cat === 'ED'){
    return subtle.generateKey({ name:'Ed25519' }, true, ['sign','verify']);
  }
  throw new Error('Key generation only for RS/PS/ED');
}

