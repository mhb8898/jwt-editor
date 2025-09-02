// Frontend app wired to the shared JWT library (lib/jwt.js)
// Uses ESM in the browser; index.html loads this with type="module".

import {
  parseJwt,
  signJwt,
  verifyJwt,
  algCategory,
  composeSigningInput,
  toBase64Url,
  fromBase64Url,
  generateKeyPair,
  exportKeyPEM
} from './lib/jwt.js';

const $ = sel => document.querySelector(sel);

// DOM refs
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
const hsSeparate = $('#hs-separate');
const secretVerifyInput = $('#secret-verify');
const btnVerify = $('#btn-verify');
const btnSign = $('#btn-sign');
const verifyResult = $('#verify-result');
const btnPrettyHeader = $('#btn-pretty-header');
const btnPrettyPayload = $('#btn-pretty-payload');
const btnCopyToken = $('#btn-copy-token');
const btnClear = $('#btn-clear');
const hsKeys = $('#hs-keys');
const asymKeys = $('#asym-keys');
const pubkeyText = $('#pubkey');
const privkeyText = $('#privkey');
const exampleSelect = $('#example-select');
const btnLoadExample = $('#btn-load-example');
const btnGenKeys = $('#btn-gen-keys');

// Helpers
function parseJSONSafe(text){ try{ return [JSON.parse(text), null]; }catch(e){ return [null, e]; } }
function pretty(obj){ return JSON.stringify(obj, null, 2); }
function safePretty(text){ const [o,e]=parseJSONSafe(text); return e?null:pretty(o); }
function setStatus(msg){ tokenStatus.textContent = msg || ''; }
function showVerifyBadge(state, text){ verifyResult.textContent = text || ''; verifyResult.className = 'badge' + (state ? ' ok' : ' bad'); }
function showWarnBadge(text){ verifyResult.textContent = text || ''; verifyResult.className = 'badge warn'; }
function clearBadge(){ verifyResult.textContent = ''; verifyResult.className = 'badge'; }
function humanTime(ts){ if (typeof ts !== 'number') return ''; try{ return new Date(ts*1000).toISOString(); }catch{ return ''; } }
function updateClaimsHuman(payloadObj){
  const claims=[]; if(!payloadObj||typeof payloadObj!=='object'){claimsHuman.textContent='';return;}
  if (typeof payloadObj.iat==='number') claims.push(`iat: ${humanTime(payloadObj.iat)}`);
  if (typeof payloadObj.nbf==='number') claims.push(`nbf: ${humanTime(payloadObj.nbf)}`);
  if (typeof payloadObj.exp==='number') claims.push(`exp: ${humanTime(payloadObj.exp)}`);
  claimsHuman.innerHTML = claims.length ? 'Standard claims — ' + claims.map(c=>`<code>${c}</code>`).join(' · ') : '';
}
function updatePartsDisplay(hB64,pB64,sB64){ partHeader.value=hB64||''; partPayload.value=pB64||''; partSignature.value=sB64||''; }
function setKeyInputsVisibility(){
  const cat = algCategory(algSelect.value);
  const hsVerifyRow = document.getElementById('hs-keys-verify');
  if (cat==='HS'){
    hsKeys?.classList.remove('hidden'); asymKeys?.classList.add('hidden');
    hsVerifyRow?.classList.toggle('hidden', !(hsSeparate && hsSeparate.checked));
  } else if (cat==='RS'||cat==='PS'||cat==='ED'){
    hsKeys?.classList.add('hidden'); asymKeys?.classList.remove('hidden'); hsVerifyRow?.classList.add('hidden');
  } else { hsKeys?.classList.add('hidden'); asymKeys?.classList.add('hidden'); hsVerifyRow?.classList.add('hidden'); }
}
function syncHeaderAlgToSelection(){
  const [h,e]=parseJSONSafe(headerText.value||'{}'); if(e) return;
  if (!h || typeof h!=='object') return; h.alg = algSelect.value; headerText.value = pretty(h);
}
function buildPreviewFromEditors(){
  const [h,he]=parseJSONSafe(headerText.value||'{}'); const [p,pe]=parseJSONSafe(payloadText.value||'{}');
  if (he||pe) return null; const {hB64,pB64}=composeSigningInput(h,p); return `${hB64}.${pB64}`;
}
function loadFromLocation(){ try{ const url=new URL(window.location.href); const t=url.searchParams.get('token')||(url.hash.startsWith('#token=')?decodeURIComponent(url.hash.slice(7)):null); if(t) tokenInput.value=t; }catch{}
}
function saveState(){ try{ localStorage.setItem('jwt-editor-state', JSON.stringify({ token:tokenInput.value, header:headerText.value, payload:payloadText.value, alg:algSelect.value, secretIsB64: !!secretIsB64.checked })); }catch{} }
function loadState(){ try{ const raw=localStorage.getItem('jwt-editor-state'); if(!raw) return; const s=JSON.parse(raw); if(s.token) tokenInput.value=s.token; if(s.header) headerText.value=s.header; if(s.payload) payloadText.value=s.payload; if(s.alg) algSelect.value=s.alg; if(typeof s.secretIsB64==='boolean') secretIsB64.checked=s.secretIsB64; }catch{} }

// Signing/Verification
async function signCurrent(){
  clearBadge();
  const alg = algSelect.value;
  const [h,he]=parseJSONSafe(headerText.value||'{}'); const [p,pe]=parseJSONSafe(payloadText.value||'{}');
  if (he||pe){ setStatus('Provide valid JSON in header/payload'); return; }
  h.alg = alg; // ensure match
  try{
    let key;
    const cat = algCategory(alg);
    if (alg==='none'){ key=null; }
    else if (cat==='HS'){
      key = secretIsB64.checked ? atob((secretInput.value||'').replace(/-/g,'+').replace(/_/g,'/')) : (secretInput.value||'');
      if (!key){ setStatus('Provide secret to sign'); updatePreviewOnly(); return; }
    } else {
      key = (privkeyText?.value||'').trim();
      if (!key){ setStatus('Provide private key to sign'); updatePreviewOnly(); return; }
    }
    const tok = await signJwt({ alg, header:h, payload:p, key });
    tokenInput.value = tok;
    const { header:hh, payload:pp, signatureB64, headerB64, payloadB64 } = parseJwt(tok);
    updatePartsDisplay(headerB64, payloadB64, signatureB64);
    updateClaimsHuman(pp);
    setStatus('Signed');
    // Auto-verify the freshly signed token
    await verifyCurrent();
    saveState();
  }catch(e){ setStatus(e?.message || 'Sign error'); updatePreviewOnly(); }
}

async function verifyCurrent(){
  clearBadge(); const tok = tokenInput.value.trim(); if(!tok){ setStatus(''); return; }
  try{
    const { header, payload, signatureB64, headerB64, payloadB64 } = parseJwt(tok);
    updatePartsDisplay(headerB64,payloadB64,signatureB64);
    headerText.value = pretty(header); payloadText.value = pretty(payload);
    updateClaimsHuman(payload);
    const alg = header.alg || algSelect.value; algSelect.value = alg; setKeyInputsVisibility();
    if (alg==='none'){ showWarnBadge(signatureB64? 'alg "none", signature ignored':'alg "none"'); return; }
    let key;
    const cat = algCategory(alg);
    if (cat==='HS'){
      key = (hsSeparate && hsSeparate.checked) ? (secretVerifyInput?.value||'') : (secretInput.value||'');
      if (secretIsB64.checked && key){ key = atob(key.replace(/-/g,'+').replace(/_/g,'/')); }
      if (!key){ showWarnBadge('Enter secret to verify'); return; }
    } else {
      key = (pubkeyText?.value||privkeyText?.value||'').trim();
      if (!key){ showWarnBadge('Provide public or private key to verify'); return; }
    }
    const res = await verifyJwt(tok, { key });
    showVerifyBadge(res.ok, res.ok ? 'Signature valid' : 'Signature invalid');
    tokenInput.classList.add(res.ok?'highlight-ok':'highlight-bad');
    setTimeout(()=> tokenInput.classList.remove('highlight-ok','highlight-bad'), 900);
  }catch(e){ showWarnBadge(e?.message || 'Verify error'); }
}

function updatePreviewOnly(){
  const preview = buildPreviewFromEditors();
  if (preview){ tokenInput.value = preview; const [h]=parseJSONSafe(headerText.value||'{}'); const [p]=parseJSONSafe(payloadText.value||'{}'); const {hB64,pB64}=composeSigningInput(h||{},p||{}); updatePartsDisplay(hB64,pB64,''); }
}

// Event bindings
tokenInput.addEventListener('input', () => {
  clearBadge(); const tok = tokenInput.value.trim(); if(!tok){ setStatus(''); updatePartsDisplay('','',''); return; }
  try{
    const { header, payload, signatureB64, headerB64, payloadB64 } = parseJwt(tok);
    headerText.value = pretty(header); payloadText.value = pretty(payload);
    updatePartsDisplay(headerB64,payloadB64,signatureB64); updateClaimsHuman(payload); saveState();
    if (header && typeof header.alg==='string'){ algSelect.value = header.alg; setKeyInputsVisibility(); }
    debounceVerify();
  }catch{ setStatus('Invalid token'); }
});

let signDebounce, verifyDebounce;
function debounceSign(){ clearTimeout(signDebounce); signDebounce = setTimeout(signCurrent, 180); }
function debounceVerify(){ clearTimeout(verifyDebounce); verifyDebounce = setTimeout(verifyCurrent, 220); }

headerText.addEventListener('input', () => { clearBadge(); debounceSign(); });
payloadText.addEventListener('input', () => { clearBadge(); debounceSign(); });
algSelect.addEventListener('change', () => { clearBadge(); syncHeaderAlgToSelection(); setKeyInputsVisibility(); debounceSign(); saveState(); debounceVerify(); });
secretInput.addEventListener('input', () => { clearBadge(); debounceSign(); debounceVerify(); });
secretIsB64.addEventListener('change', () => { clearBadge(); debounceSign(); saveState(); debounceVerify(); });
hsSeparate && hsSeparate.addEventListener('change', () => { setKeyInputsVisibility(); debounceVerify(); });
secretVerifyInput && secretVerifyInput.addEventListener('input', () => { clearBadge(); debounceVerify(); });
pubkeyText && pubkeyText.addEventListener('input', () => { clearBadge(); debounceSign(); debounceVerify(); });
privkeyText && privkeyText.addEventListener('input', () => { clearBadge(); debounceSign(); debounceVerify(); });

btnSign.addEventListener('click', () => { signCurrent(); });
btnVerify.addEventListener('click', () => { verifyCurrent(); });

btnUseHeaderAlg.addEventListener('click', () => {
  const [h] = parseJSONSafe(headerText.value||'{}'); if (h && h.alg){ algSelect.value = h.alg; setKeyInputsVisibility(); debounceSign(); }
  else setStatus('No valid header.alg found');
});

btnPrettyHeader.addEventListener('click', () => { const p = safePretty(headerText.value); if(p){ headerText.value=p; debounceSign(); } });
btnPrettyPayload.addEventListener('click', () => { const p = safePretty(payloadText.value); if(p){ payloadText.value=p; debounceSign(); } });
btnCopyToken.addEventListener('click', async () => { try{ await navigator.clipboard.writeText(tokenInput.value.trim()); tokenInput.classList.add('highlight-ok'); setTimeout(()=> tokenInput.classList.remove('highlight-ok'), 800);}catch{} });
btnClear.addEventListener('click', () => { tokenInput.value=''; headerText.value=''; payloadText.value=''; updatePartsDisplay('','',''); claimsHuman.textContent=''; setStatus(''); clearBadge(); saveState(); });

// Examples panel
btnLoadExample && btnLoadExample.addEventListener('click', () => {
  const ex = exampleSelect.value;
  if (ex==='HS256'){
    headerText.value = pretty({alg:'HS256',typ:'JWT'});
    payloadText.value = pretty({sub:'123',name:'Alice',iat:1516239022});
    algSelect.value = 'HS256'; secretInput.value='secret'; secretIsB64.checked=false; setKeyInputsVisibility(); debounceSign(); setStatus('Loaded HS256 example'); return;
  }
  if (ex==='RS256'){
    headerText.value = pretty({alg:'RS256',typ:'JWT'}); payloadText.value=pretty({sub:'123',name:'Alice'}); algSelect.value='RS256'; setKeyInputsVisibility(); updatePreviewOnly(); setStatus('Loaded RS256 example — generate or paste keys'); return;
  }
  if (ex==='PS256'){
    headerText.value = pretty({alg:'PS256',typ:'JWT'}); payloadText.value=pretty({sub:'123',name:'Alice'}); algSelect.value='PS256'; setKeyInputsVisibility(); updatePreviewOnly(); setStatus('Loaded PS256 example — generate or paste keys'); return;
  }
  if (ex==='EdDSA'){
    headerText.value = pretty({alg:'EdDSA',typ:'JWT'}); payloadText.value=pretty({sub:'123',name:'Alice'}); algSelect.value='EdDSA'; setKeyInputsVisibility(); updatePreviewOnly(); setStatus('Loaded EdDSA example — generate or paste keys'); return;
  }
});

btnGenKeys && btnGenKeys.addEventListener('click', async () => {
  const alg = algSelect.value;
  try{ const kp = await generateKeyPair(alg); const pubPem = await exportKeyPEM('spki', kp.publicKey, 'PUBLIC KEY'); const pk8Pem = await exportKeyPEM('pkcs8', kp.privateKey, 'PRIVATE KEY'); pubkeyText.value=pubPem; privkeyText.value=pk8Pem; setStatus('Generated keys and filled fields'); }
  catch(e){ setStatus(e?.message || 'Key generation error'); }
});

// Init
loadState();
loadFromLocation();
setKeyInputsVisibility();
if (tokenInput.value){ tokenInput.dispatchEvent(new Event('input')); }
else if (headerText.value || payloadText.value){ debounceSign(); }
else { headerText.value='{"alg":"HS256","typ":"JWT"}'; payloadText.value='{"sub":"1234567890","name":"John Doe","iat":1516239022}'; debounceSign(); }
