// Minimal in-browser JWT editor with HS256/384/512 sign/verify using Web Crypto

(function(){
  'use strict';

  // DOM elements
  const $ = sel => document.querySelector(sel);
  const tokenInput = $('#token-input');
  const tokenStatus = $('#token-status');
  const headerText = $('#header-json');
  const payloadText = $('#payload-json');
  const claimsHuman = $('#claims-human');
  const partHeader = $('#part-header');
  const partPayload = $('#part-payload');
  const partSignature = $('#part-signature');
  const algSelect = $('#alg');
  const btnUseHeaderAlg = $('#btn-use-header-alg');
  const secretInput = $('#secret');
  const secretIsB64 = $('#secret-b64');
  const btnVerify = $('#btn-verify');
  const btnSign = $('#btn-sign');
  const verifyResult = $('#verify-result');
  const btnPrettyHeader = $('#btn-pretty-header');
  const btnPrettyPayload = $('#btn-pretty-payload');
  const btnCopyToken = $('#btn-copy-token');
  const btnClear = $('#btn-clear');
  const exampleSelect = document.getElementById('example-select');
  const btnLoadExample = document.getElementById('btn-load-example');
  const btnGenKeys = document.getElementById('btn-gen-keys');
  // HS separate verify secret toggle
  const hsSeparate = document.getElementById('hs-separate');
  const secretVerifyInput = document.getElementById('secret-verify');
  // Asymmetric key inputs
  const hsKeys = document.getElementById('hs-keys');
  const asymKeys = document.getElementById('asym-keys');
  const pubkeyText = document.getElementById('pubkey');
  const privkeyText = document.getElementById('privkey');

  // Utilities
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  function u8(arr){
    if (arr instanceof Uint8Array) return arr;
    if (arr instanceof ArrayBuffer) return new Uint8Array(arr);
    return enc.encode(String(arr));
  }

  function b64encode(bytes){
    let bin = '';
    const u = u8(bytes);
    for (let i=0; i<u.length; i++) bin += String.fromCharCode(u[i]);
    return btoa(bin);
  }
  function b64decode(str){
    const bin = atob(str);
    const out = new Uint8Array(bin.length);
    for (let i=0; i<bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function toBase64Url(bytes){
    return b64encode(bytes).replace(/=+$/,'').replace(/\+/g,'-').replace(/\//g,'_');
  }
  function fromBase64Url(str){
    const s = str.replace(/-/g,'+').replace(/_/g,'/');
    const pad = s.length % 4 === 2 ? '==' : s.length % 4 === 3 ? '=' : s.length % 4 === 1 ? '===' : '';
    return b64decode(s + pad);
  }

  function parseJSONSafe(text){
    try{ return [JSON.parse(text), null]; }catch(err){ return [null, err]; }
  }
  function pretty(obj){ return JSON.stringify(obj, null, 2); }
  function safePretty(text){
    const [obj, err] = parseJSONSafe(text);
    if (err) return null;
    return pretty(obj);
  }

  // Algorithm category + key import/sign/verify helpers
  const ALG_CATS = {
    HS: ['HS256','HS384','HS512'],
    RS: ['RS256','RS384','RS512'],
    PS: ['PS256','PS384','PS512'],
    ED: ['EdDSA']
  };
  function algCategory(alg){
    if (ALG_CATS.HS.includes(alg)) return 'HS';
    if (ALG_CATS.RS.includes(alg)) return 'RS';
    if (ALG_CATS.PS.includes(alg)) return 'PS';
    if (ALG_CATS.ED.includes(alg)) return 'ED';
    if (alg === 'none') return 'none';
    return null;
  }
  function setKeyInputsVisibility(){
    const cat = algCategory(algSelect.value);
    if (cat === 'HS'){
      hsKeys && hsKeys.classList.remove('hidden');
      asymKeys && asymKeys.classList.add('hidden');
      // HS verify secret row visibility
      if (hsSeparate) {
        const row = document.getElementById('hs-keys-verify');
        if (row) row.classList.toggle('hidden', !hsSeparate.checked);
      }
    } else if (cat === 'RS' || cat === 'PS' || cat === 'ED'){
      hsKeys && hsKeys.classList.add('hidden');
      asymKeys && asymKeys.classList.remove('hidden');
      const row = document.getElementById('hs-keys-verify');
      if (row) row.classList.add('hidden');
    } else {
      hsKeys && hsKeys.classList.add('hidden');
      asymKeys && asymKeys.classList.add('hidden');
      const row = document.getElementById('hs-keys-verify');
      if (row) row.classList.add('hidden');
    }
  }
  function ab2b64(arr){ return b64encode(u8(arr)); }
  function b64ToPem(b64, label){
    const lines = b64.match(/.{1,64}/g).join('\n');
    return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----`;
  }
  function pemToArrayBuffer(pem){
    const b64 = pem.replace(/-----[^-]+-----/g,'').replace(/\s+/g,'');
    return b64decode(b64);
  }
  async function exportKeyPEM(format, key, label){
    const buf = await crypto.subtle.exportKey(format, key);
    return b64ToPem(ab2b64(new Uint8Array(buf)), label);
  }
  async function importPublicKey(alg, keyText){
    const cat = algCategory(alg);
    if (!cat || cat === 'HS' || alg === 'none') throw new Error('No public key for alg');
    const hash = getHashForAlg(alg) || undefined;
    const text = (keyText || '').trim();
    if (!text) throw new Error('Public key required');
    if (text.startsWith('{')){
      const jwk = JSON.parse(text);
      if (cat === 'ED') return crypto.subtle.importKey('jwk', jwk, {name:'Ed25519'}, false, ['verify']);
      const algo = cat === 'RS' ? 'RSASSA-PKCS1-v1_5' : 'RSA-PSS';
      return crypto.subtle.importKey('jwk', jwk, {name: algo, hash}, false, ['verify']);
    }
    if (/BEGIN PUBLIC KEY/.test(text)){
      const spki = pemToArrayBuffer(text);
      if (cat === 'ED') return crypto.subtle.importKey('spki', spki, {name:'Ed25519'}, false, ['verify']);
      const algo = cat === 'RS' ? 'RSASSA-PKCS1-v1_5' : 'RSA-PSS';
      return crypto.subtle.importKey('spki', spki, {name: algo, hash}, false, ['verify']);
    }
    throw new Error('Unsupported public key format');
  }
  async function importPrivateKey(alg, keyText){
    const cat = algCategory(alg);
    if (!cat || cat === 'HS' || alg === 'none') throw new Error('No private key for alg');
    const hash = getHashForAlg(alg) || undefined;
    const text = (keyText || '').trim();
    if (!text) throw new Error('Private key required');
    if (text.startsWith('{')){
      const jwk = JSON.parse(text);
      if (cat === 'ED') return crypto.subtle.importKey('jwk', jwk, {name:'Ed25519'}, false, ['sign']);
      const algo = cat === 'RS' ? 'RSASSA-PKCS1-v1_5' : 'RSA-PSS';
      return crypto.subtle.importKey('jwk', jwk, {name: algo, hash}, false, ['sign']);
    }
    if (/BEGIN PRIVATE KEY/.test(text)){
      const pkcs8 = pemToArrayBuffer(text);
      if (cat === 'ED') return crypto.subtle.importKey('pkcs8', pkcs8, {name:'Ed25519'}, false, ['sign']);
      const algo = cat === 'RS' ? 'RSASSA-PKCS1-v1_5' : 'RSA-PSS';
      return crypto.subtle.importKey('pkcs8', pkcs8, {name: algo, hash}, false, ['sign']);
    }
    if (/BEGIN RSA PRIVATE KEY/.test(text)){
      throw new Error('PKCS#1 private key not supported by Web Crypto; convert to PKCS#8');
    }
    throw new Error('Unsupported private key format');
  }
  function saltLengthForAlg(alg){
    switch(alg){ case 'PS256': return 32; case 'PS384': return 48; case 'PS512': return 64; default: return 0; }
  }
  async function signAsymmetric(alg, signingInput){
    const cat = algCategory(alg);
    const privText = privkeyText?.value?.trim();
    if (!privText) return null;
    const key = await importPrivateKey(alg, privText);
    const data = u8(signingInput);
    if (cat === 'RS'){
      const sig = await crypto.subtle.sign({name:'RSASSA-PKCS1-v1_5'}, key, data); return toBase64Url(new Uint8Array(sig));
    } else if (cat === 'PS'){
      const sig = await crypto.subtle.sign({name:'RSA-PSS', saltLength: saltLengthForAlg(alg)}, key, data); return toBase64Url(new Uint8Array(sig));
    } else if (cat === 'ED'){
      try{ const sig = await crypto.subtle.sign({name:'Ed25519'}, key, data); return toBase64Url(new Uint8Array(sig)); }catch{ throw new Error('Ed25519 signing unsupported in this browser'); }
    }
    return null;
  }
  async function verifyAsymmetric(alg, signingInput, sigB64){
    const cat = algCategory(alg);
    const pubText = pubkeyText?.value?.trim();
    const privText = privkeyText?.value?.trim();
    if (!pubText && !privText) return null;
    let key;
    try{ key = await importPublicKey(alg, pubText || privText); }
    catch{
      if (privText){ try{ key = await importPrivateKey(alg, privText); }catch(e){ throw e; } }
      if (!key) throw new Error('Invalid key for verification');
    }
    const data = u8(signingInput);
    const sig = fromBase64Url(sigB64);
    if (cat === 'RS') return crypto.subtle.verify({name:'RSASSA-PKCS1-v1_5'}, key, sig, data);
    if (cat === 'PS') return crypto.subtle.verify({name:'RSA-PSS', saltLength: saltLengthForAlg(alg)}, key, sig, data);
    if (cat === 'ED') { try{ return crypto.subtle.verify({name:'Ed25519'}, key, sig, data); }catch{ throw new Error('Ed25519 verification unsupported in this browser'); } }
    return null;
  }

  async function generateKeysForAlg(alg){
    const cat = algCategory(alg);
    if (cat === 'RS'){
      const kp = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' }, true, ['sign','verify']);
      const pubPem = await exportKeyPEM('spki', kp.publicKey, 'PUBLIC KEY');
      const pk8Pem = await exportKeyPEM('pkcs8', kp.privateKey, 'PRIVATE KEY');
      return {pubPem, pk8Pem};
    }
    if (cat === 'PS'){
      const kp = await crypto.subtle.generateKey({ name: 'RSA-PSS', modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' }, true, ['sign','verify']);
      const pubPem = await exportKeyPEM('spki', kp.publicKey, 'PUBLIC KEY');
      const pk8Pem = await exportKeyPEM('pkcs8', kp.privateKey, 'PRIVATE KEY');
      return {pubPem, pk8Pem};
    }
    if (cat === 'ED'){
      try{
        const kp = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign','verify']);
        const pubPem = await exportKeyPEM('spki', kp.publicKey, 'PUBLIC KEY');
        const pk8Pem = await exportKeyPEM('pkcs8', kp.privateKey, 'PRIVATE KEY');
        return {pubPem, pk8Pem};
      }catch{ throw new Error('Ed25519 keygen unsupported in this browser'); }
    }
    throw new Error('Key generation not required for this algorithm');
  }

  // (Removed duplicate helper block)

  function timingSafeEqual(a, b){
    const ua = u8(a), ub = u8(b);
    if (ua.length !== ub.length) return false;
    let res = 0;
    for (let i=0; i<ua.length; i++) res |= ua[i] ^ ub[i];
    return res === 0;
  }

  function getHashForAlg(alg){
    switch(alg){
      case 'HS256': return 'SHA-256';
      case 'HS384': return 'SHA-384';
      case 'HS512': return 'SHA-512';
      default: return null;
    }
  }

  async function hmacSign(alg, keyBytes, dataBytes){
    const hash = getHashForAlg(alg);
    if (!hash) throw new Error('Unsupported HMAC alg');
    const key = await crypto.subtle.importKey(
      'raw', u8(keyBytes), { name: 'HMAC', hash }, false, ['sign']
    );
    const sig = await crypto.subtle.sign('HMAC', key, u8(dataBytes));
    return new Uint8Array(sig);
  }

  async function hmacVerify(alg, keyBytes, dataBytes, sigBytes){
    const expected = await hmacSign(alg, keyBytes, dataBytes);
    return timingSafeEqual(expected, sigBytes);
  }

  function splitToken(tok){
    const parts = String(tok).trim().split('.');
    if (parts.length < 2) return null;
    return { headerB64: parts[0] || '', payloadB64: parts[1] || '', signatureB64: parts[2] || '' };
  }

  function decodePart(b64){
    try{ return dec.decode(fromBase64Url(b64)); } catch(e){ return null; }
  }

  function updatePartsDisplay(hB64, pB64, sB64){
    partHeader.value = hB64 || '';
    partPayload.value = pB64 || '';
    partSignature.value = sB64 || '';
  }

  function setStatus(msg){ tokenStatus.textContent = msg || ''; }

  function showVerifyBadge(state, text){
    verifyResult.textContent = text || '';
    verifyResult.className = 'badge' + (state ? ' ok' : ' bad');
  }

  function showWarnBadge(text){
    verifyResult.textContent = text || '';
    verifyResult.className = 'badge warn';
  }

  function clearBadge(){
    verifyResult.textContent = '';
    verifyResult.className = 'badge';
  }

  function humanTime(ts){
    if (typeof ts !== 'number') return '';
    try{
      const ms = ts * 1000;
      const d = new Date(ms);
      return d.toISOString();
    }catch{ return ''; }
  }

  function updateClaimsHuman(payloadObj){
    const claims = [];
    if (!payloadObj || typeof payloadObj !== 'object'){
      claimsHuman.textContent = '';
      return;
    }
    if (typeof payloadObj.iat === 'number') claims.push(`iat: ${humanTime(payloadObj.iat)}`);
    if (typeof payloadObj.nbf === 'number') claims.push(`nbf: ${humanTime(payloadObj.nbf)}`);
    if (typeof payloadObj.exp === 'number') claims.push(`exp: ${humanTime(payloadObj.exp)}`);
    claimsHuman.innerHTML = claims.length ? 'Standard claims — ' + claims.map(c => `<code>${c}</code>`).join(' · ') : '';
  }

  function loadFromLocation(){
    try{
      const url = new URL(window.location.href);
      const t = url.searchParams.get('token') || (url.hash.startsWith('#token=') ? decodeURIComponent(url.hash.slice(7)) : null);
      if (t) tokenInput.value = t;
    }catch{}
  }

  function saveState(){
    try{
      const state = {
        token: tokenInput.value,
        header: headerText.value,
        payload: payloadText.value,
        alg: algSelect.value,
        secretIsB64: !!secretIsB64.checked
      };
      localStorage.setItem('jwt-editor-state', JSON.stringify(state));
    }catch{}
  }
  function loadState(){
    try{
      const raw = localStorage.getItem('jwt-editor-state');
      if (!raw) return;
      const s = JSON.parse(raw);
      if (s.token) tokenInput.value = s.token;
      if (s.header) headerText.value = s.header;
      if (s.payload) payloadText.value = s.payload;
      if (s.alg) algSelect.value = s.alg;
      if (typeof s.secretIsB64 === 'boolean') secretIsB64.checked = s.secretIsB64;
    }catch{}
  }

  function updateTokenFromEditors(signatureB64){
    let headerObj, payloadObj;
    try{ headerObj = JSON.parse(headerText.value || '{}'); }catch{}
    try{ payloadObj = JSON.parse(payloadText.value || '{}'); }catch{}
    const hB64 = toBase64Url(enc.encode(JSON.stringify(headerObj || {})));
    const pB64 = toBase64Url(enc.encode(JSON.stringify(payloadObj || {})));
    const sB64 = signatureB64 || '';
    const t = sB64 ? `${hB64}.${pB64}.${sB64}` : `${hB64}.${pB64}`;
    tokenInput.value = t;
    updatePartsDisplay(hB64, pB64, sB64);
    setStatus('');
    saveState();
  }

  async function computeSignatureIfHmac(){
    const alg = algSelect.value;
    if (alg === 'none') return '';
    const secret = secretInput.value;
    if (!secret){ return null; }
    let keyBytes;
    try{
      keyBytes = secretIsB64.checked ? fromBase64Url(secret) : enc.encode(secret);
    }catch{
      return null;
    }
    let headerObj, payloadObj;
    const [h, he] = parseJSONSafe(headerText.value || '{}');
    const [p, pe] = parseJSONSafe(payloadText.value || '{}');
    if (he || pe) return null;
    const hB64 = toBase64Url(enc.encode(JSON.stringify(h)));
    const pB64 = toBase64Url(enc.encode(JSON.stringify(p)));
    const signingInput = enc.encode(`${hB64}.${pB64}`);
    const sigBytes = await hmacSign(alg, keyBytes, signingInput);
    return toBase64Url(sigBytes);
  }

  async function verifyCurrentToken(){
    clearBadge();
    const tok = tokenInput.value.trim();
    if (!tok){ setStatus(''); return; }
    const parts = splitToken(tok);
    if (!parts){ setStatus('Token must contain header and payload'); return; }
    updatePartsDisplay(parts.headerB64, parts.payloadB64, parts.signatureB64);
    const headerStr = decodePart(parts.headerB64);
    const payloadStr = decodePart(parts.payloadB64);
    if (!headerStr || !payloadStr){ setStatus('Invalid base64url in header or payload'); return; }
    headerText.value = headerStr;
    payloadText.value = payloadStr;
    saveState();
    const [headerObj] = parseJSONSafe(headerStr);
    const [payloadObj] = parseJSONSafe(payloadStr);
    updateClaimsHuman(payloadObj);

    const alg = (headerObj && headerObj.alg) || algSelect.value;
    if (alg === 'none'){
      if (parts.signatureB64){ showWarnBadge('alg "none", signature ignored'); }
      else showWarnBadge('alg "none"');
      return;
    }

    if (!parts.signatureB64){ showWarnBadge('Missing signature'); return; }
    const cat = algCategory(alg);
    try{
      const signingInputStr = `${parts.headerB64}.${parts.payloadB64}`;
      let ok = false;
      if (cat === 'HS'){
        const secret = hsSeparate && hsSeparate.checked ? (secretVerifyInput?.value || '') : secretInput.value;
        if (!secret){ showWarnBadge('Enter secret to verify'); return; }
        let keyBytes;
        try{ keyBytes = secretIsB64.checked ? fromBase64Url(secret) : enc.encode(secret); }
        catch{ showWarnBadge('Invalid secret encoding'); return; }
        const hash = getHashForAlg(alg);
        if (!hash){ showWarnBadge(`Unsupported alg ${alg}`); return; }
        ok = await hmacVerify(alg, keyBytes, enc.encode(signingInputStr), fromBase64Url(parts.signatureB64));
      } else if (cat === 'RS' || cat === 'PS' || cat === 'ED'){
        ok = await verifyAsymmetric(alg, signingInputStr, parts.signatureB64);
      } else {
        showWarnBadge(`Unsupported alg ${alg}`); return;
      }
      showVerifyBadge(ok, ok ? 'Signature valid' : 'Signature invalid');
      if (ok) tokenInput.classList.add('highlight-ok'); else tokenInput.classList.add('highlight-bad');
      setTimeout(()=>{ tokenInput.classList.remove('highlight-ok','highlight-bad'); }, 900);
    }catch(err){
      showWarnBadge(err.message || 'Verify error');
      console.error(err);
    }
  }

  // Event bindings
  tokenInput.addEventListener('input', () => {
    clearBadge();
    const tok = tokenInput.value.trim();
    if (!tok){ setStatus(''); updatePartsDisplay('','',''); return; }
    const parts = splitToken(tok);
    if (!parts){ setStatus('Token must contain header and payload'); return; }
    setStatus('Decoded header and payload below');
    const headerStr = decodePart(parts.headerB64);
    const payloadStr = decodePart(parts.payloadB64);
    if (headerStr) headerText.value = headerStr;
    if (payloadStr) payloadText.value = payloadStr;
    updatePartsDisplay(parts.headerB64, parts.payloadB64, parts.signatureB64);
    // Prefer header alg if available
    try{
      const h = JSON.parse(headerStr);
      if (h && typeof h.alg === 'string' && ['HS256','HS384','HS512','RS256','RS384','RS512','PS256','PS384','PS512','EdDSA','none'].includes(h.alg)){
        algSelect.value = h.alg;
      }
    }catch{}
    // claims human
    try{ updateClaimsHuman(JSON.parse(payloadStr)); }catch{ updateClaimsHuman(null); }
    saveState();
    debounceVerify();
  });

  let signDebounce;
  function debounceSign(){
    clearTimeout(signDebounce);
    signDebounce = setTimeout(async ()=>{
      const alg = algSelect.value;
      const cat = algCategory(alg);
      let sig = '';
      if (alg === 'none') sig = '';
      else if (cat === 'HS') sig = await computeSignatureIfHmac();
      else if (cat === 'RS' || cat === 'PS' || cat === 'ED') sig = await computeSignatureIfAsym();
      updateTokenFromEditors(sig || '');
    }, 180);
  }

  let verifyDebounce;
  function debounceVerify(){
    clearTimeout(verifyDebounce);
    verifyDebounce = setTimeout(()=>{ verifyCurrentToken(); }, 220);
  }

  headerText.addEventListener('input', () => { clearBadge(); debounceSign(); });
  payloadText.addEventListener('input', () => { clearBadge(); debounceSign(); });
  algSelect.addEventListener('change', () => { clearBadge(); setKeyInputsVisibility(); debounceSign(); saveState(); debounceVerify(); });
  secretInput.addEventListener('input', () => { clearBadge(); debounceSign(); debounceVerify(); });
  secretIsB64.addEventListener('change', () => { clearBadge(); debounceSign(); saveState(); debounceVerify(); });
  pubkeyText && pubkeyText.addEventListener('input', () => { clearBadge(); debounceSign(); debounceVerify(); });
  privkeyText && privkeyText.addEventListener('input', () => { clearBadge(); debounceSign(); debounceVerify(); });
  hsSeparate && hsSeparate.addEventListener('change', () => { setKeyInputsVisibility(); debounceVerify(); });
  secretVerifyInput && secretVerifyInput.addEventListener('input', () => { clearBadge(); debounceVerify(); });

  btnSign.addEventListener('click', async () => {
    try{
      const alg = algSelect.value;
      if (alg === 'none'){ updateTokenFromEditors(''); setStatus('Signed with alg "none"'); return; }
      const cat = algCategory(alg);
      let sig = null;
      if (cat === 'HS'){
        sig = await computeSignatureIfHmac();
        if (sig === null){ setStatus('Provide valid JSON and secret to sign'); return; }
      } else if (cat === 'RS' || cat === 'PS' || cat === 'ED'){
        sig = await computeSignatureIfAsym();
        if (!sig){ setStatus('Provide valid JSON and private key to sign'); return; }
      } else { setStatus('Unsupported algorithm'); return; }
      updateTokenFromEditors(sig);
      setStatus('Signed');
      clearBadge();
    }catch(err){ setStatus('Sign error'); console.error(err); }
  });

  btnVerify.addEventListener('click', () => { verifyCurrentToken(); });

  btnUseHeaderAlg.addEventListener('click', () => {
    const [h] = parseJSONSafe(headerText.value || '{}');
    if (h && h.alg && ['HS256','HS384','HS512','RS256','RS384','RS512','PS256','PS384','PS512','EdDSA','none'].includes(h.alg)){
      algSelect.value = h.alg; saveState(); setKeyInputsVisibility(); debounceSign();
    } else {
      setStatus('No valid header.alg found');
    }
  });

  btnPrettyHeader.addEventListener('click', () => {
    const p = safePretty(headerText.value);
    if (p){ headerText.value = p; debounceSign(); }
  });
  btnPrettyPayload.addEventListener('click', () => {
    const p = safePretty(payloadText.value);
    if (p){ payloadText.value = p; debounceSign(); }
  });

  btnCopyToken.addEventListener('click', async () => {
    try{
      await navigator.clipboard.writeText(tokenInput.value.trim());
      tokenInput.classList.add('highlight-ok');
      setTimeout(()=> tokenInput.classList.remove('highlight-ok'), 800);
    }catch{}
  });

  btnClear.addEventListener('click', () => {
    tokenInput.value = '';
    headerText.value = '';
    payloadText.value = '';
    updatePartsDisplay('','','');
    claimsHuman.textContent = '';
    setStatus('');
    clearBadge();
    saveState();
  });

  // Examples UI
  btnLoadExample.addEventListener('click', async () => {
    const ex = exampleSelect.value;
    if (ex === 'HS256'){
      headerText.value = pretty({alg:'HS256',typ:'JWT'});
      payloadText.value = pretty({sub:'123',name:'Alice',iat:1516239022});
      algSelect.value = 'HS256';
      secretInput.value = 'secret';
      secretIsB64.checked = false;
      setKeyInputsVisibility();
      debounceSign();
      setStatus('Loaded HS256 example');
      return;
    }
    if (ex === 'RS256'){
      headerText.value = pretty({alg:'RS256',typ:'JWT'});
      payloadText.value = pretty({sub:'123',name:'Alice'});
      algSelect.value = 'RS256';
      setKeyInputsVisibility();
      updateTokenFromEditors('');
      setStatus('Loaded RS256 example — generate or paste keys to sign/verify');
      return;
    }
    if (ex === 'PS256'){
      headerText.value = pretty({alg:'PS256',typ:'JWT'});
      payloadText.value = pretty({sub:'123',name:'Alice'});
      algSelect.value = 'PS256';
      setKeyInputsVisibility();
      updateTokenFromEditors('');
      setStatus('Loaded PS256 example — generate or paste keys to sign/verify');
      return;
    }
    if (ex === 'EdDSA'){
      headerText.value = pretty({alg:'EdDSA',typ:'JWT'});
      payloadText.value = pretty({sub:'123',name:'Alice'});
      algSelect.value = 'EdDSA';
      setKeyInputsVisibility();
      updateTokenFromEditors('');
      setStatus('Loaded EdDSA example — generate or paste keys to sign/verify');
      return;
    }
  });

  btnGenKeys.addEventListener('click', async () => {
    const alg = exampleSelect.value;
    try{
      const {pubPem, pk8Pem} = await generateKeysForAlg(alg);
      pubkeyText.value = pubPem;
      privkeyText.value = pk8Pem;
      setStatus('Generated keys and filled fields');
    }catch(e){ setStatus(e.message || 'Key generation error'); }
  });

  // Init
  loadState();
  loadFromLocation();
  setKeyInputsVisibility();
  if (tokenInput.value) {
    tokenInput.dispatchEvent(new Event('input'));
  } else if (headerText.value || payloadText.value) {
    debounceSign();
  } else {
    // sensible defaults
    headerText.value = '{"alg":"HS256","typ":"JWT"}';
    payloadText.value = '{"sub":"1234567890","name":"John Doe","iat":1516239022}';
    debounceSign();
  }
})();
