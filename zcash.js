import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { blake2b } from '@noble/hashes/blake2b';
import { bytesToHex, hexToBytes, concatBytes } from '@noble/hashes/utils';

// ---- SOZLAMALAR (ishga tushirishdan oldin tekshiring) ----
export const API = 'https://zec1.trezor.io'; // Blockbook API
export const BRANCH_ID = 0x4dec4df0; // joriy konsensus branch ID (NU6.1). Tarmoq yangilansa o'zgartiring!

const A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const enc = new TextEncoder();

function b58dec(s) {
  let n = 0n;
  for (const c of s) {
    const i = A.indexOf(c);
    if (i < 0) throw new Error('Noto‘g‘ri belgi');
    n = n * 58n + BigInt(i);
  }
  let hex = n.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  const body = n === 0n ? new Uint8Array(0) : hexToBytes(hex);
  let z = 0;
  while (z < s.length && s[z] === '1') z++;
  return concatBytes(new Uint8Array(z), body);
}
function b58enc(b) {
  let n = 0n;
  for (const x of b) n = n * 256n + BigInt(x);
  let s = '';
  while (n > 0n) { s = A[Number(n % 58n)] + s; n /= 58n; }
  for (const x of b) { if (x === 0) s = '1' + s; else break; }
  return s;
}
const chk = (d) => sha256(sha256(d)).slice(0, 4);
function b58cDec(s) {
  const r = b58dec(s.trim());
  const d = r.slice(0, -4);
  if (bytesToHex(r.slice(-4)) !== bytesToHex(chk(d))) throw new Error('Checksum xato');
  return d;
}
const b58cEnc = (d) => b58enc(concatBytes(d, chk(d)));

export function parseWif(wif) {
  const d = b58cDec(wif);
  if (d[0] !== 0x80) throw new Error('Bu Zcash mainnet WIF emas');
  let compressed = false;
  if (d.length === 34 && d[33] === 1) compressed = true;
  else if (d.length !== 33) throw new Error('WIF uzunligi noto‘g‘ri');
  const priv = d.slice(1, 33);
  const pub = secp256k1.getPublicKey(priv, compressed);
  const pkh = ripemd160(sha256(pub));
  const address = b58cEnc(concatBytes(Uint8Array.of(0x1c, 0xb8), pkh));
  return { priv, pub, pkh, address };
}

const p2pkh = (h) => concatBytes(Uint8Array.of(0x76, 0xa9, 0x14), h, Uint8Array.of(0x88, 0xac));
function addrToScript(addr) {
  const d = b58cDec(addr);
  if (d.length !== 22) throw new Error('Manzil noto‘g‘ri');
  const h = d.slice(2);
  if (d[0] === 0x1c && d[1] === 0xb8) return p2pkh(h);
  if (d[0] === 0x1c && d[1] === 0xbd) return concatBytes(Uint8Array.of(0xa9, 0x14), h, Uint8Array.of(0x87));
  throw new Error('Faqat transparent (t1/t3) manzillar qo‘llanadi');
}

const u32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n, true); return b; };
const u64 = (n) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n), true); return b; };
const vi = (n) => (n < 253 ? Uint8Array.of(n) : Uint8Array.of(253, n & 255, n >> 8));
const rev = (h) => hexToBytes(h).reverse();
const h256 = (p, d) => blake2b(d, { dkLen: 32, personalization: enc.encode(p) });

// ZIP-317 an'anaviy komissiya (faqat transparent, <=2 chiqish)
export const feeFor = (nIn) => 5000n * BigInt(Math.max(2, nIn));

export function buildSignedTx({ wif, utxos, to, amount }) {
  const { priv, pub, pkh } = parseWif(wif);
  const myScript = p2pkh(pkh);
  const amt = BigInt(amount);
  if (amt <= 0n) throw new Error('Miqdor noto‘g‘ri');

  const sorted = [...utxos].sort((a, b) => Number(BigInt(b.value) - BigInt(a.value)));
  const ins = [];
  let total = 0n;
  for (const u of sorted) {
    ins.push(u);
    total += BigInt(u.value);
    if (total >= amt + feeFor(ins.length)) break;
  }
  const fee = feeFor(ins.length);
  const change = total - amt - fee;
  if (change < 0n) throw new Error('Mablag‘ yetarli emas (komissiya: ' + fee + ' zat)');

  const outs = [{ value: amt, script: addrToScript(to) }];
  if (change > 1000n) outs.push({ value: change, script: myScript });

  const outBytes = outs.map((o) => concatBytes(u64(o.value), vi(o.script.length), o.script));
  const hP = h256('ZcashPrevoutHash', concatBytes(...ins.map((i) => concatBytes(rev(i.txid), u32(i.vout)))));
  const hS = h256('ZcashSequencHash', concatBytes(...ins.map(() => u32(0xffffffff))));
  const hO = h256('ZcashOutputsHash', concatBytes(...outBytes));
  const zero = new Uint8Array(32);
  const header = concatBytes(u32(0x80000004), u32(0x892f2085));
  const persona = concatBytes(enc.encode('ZcashSigHash'), u32(BRANCH_ID));

  const signedIns = ins.map((i) => {
    const preimage = concatBytes(
      header, hP, hS, hO, zero, zero, zero,
      u32(0), u32(0), u64(0), u32(1), // locktime, expiry, valueBalance, SIGHASH_ALL
      rev(i.txid), u32(i.vout),
      vi(myScript.length), myScript,
      u64(i.value), u32(0xffffffff)
    );
    const sh = blake2b(preimage, { dkLen: 32, personalization: persona });
    const der = secp256k1.sign(sh, priv).toDERRawBytes();
    const sig = concatBytes(der, Uint8Array.of(1));
    const scriptSig = concatBytes(vi(sig.length), sig, vi(pub.length), pub);
    return concatBytes(rev(i.txid), u32(i.vout), vi(scriptSig.length), scriptSig, u32(0xffffffff));
  });

  const tx = concatBytes(
    header, vi(ins.length), ...signedIns, vi(outs.length), ...outBytes,
    u32(0), u32(0), u64(0), vi(0), vi(0), vi(0)
  );
  return { hex: bytesToHex(tx), fee, change };
}

const HEADERS = { Accept: 'application/json', 'User-Agent': 'Mozilla/5.0 (Android) ZecHamyon/1.0' };
const BLOCKBOOKS = ['https://zec1.trezor.io', 'https://zec2.trezor.io'];
const BLOCKCHAIR = 'https://api.blockchair.com/zcash';
// Ixtiyoriy: blockchair.com/api/plans dan bepul kalit olsangiz, shu yerga qo'ying
const BLOCKCHAIR_KEY = '';
const bk = (u) => (BLOCKCHAIR_KEY ? u + (u.includes('?') ? '&' : '?') + 'key=' + BLOCKCHAIR_KEY : u);

export async function getUtxos(address) {
  const errs = [];
  // 1) Blockchair
  try {
    const r = await fetch(bk(`${BLOCKCHAIR}/dashboards/address/${address}?limit=0,100`), { headers: HEADERS });
    if (!r.ok) throw new Error('Blockchair ' + r.status);
    const j = await r.json();
    const d = j && j.data && j.data[address];
    if (!d) throw new Error('Blockchair: ma’lumot yo‘q');
    return (d.utxo || []).map((u) => ({ txid: u.transaction_hash, vout: u.index, value: String(u.value) }));
  } catch (e) { errs.push(e.message); }
  // 2) Blockbook
  for (const base of BLOCKBOOKS) {
    try {
      const r = await fetch(`${base}/api/v2/utxo/${address}`, { headers: HEADERS });
      if (!r.ok) throw new Error(base + ' ' + r.status);
      return (await r.json()).map((u) => ({ txid: u.txid, vout: u.vout, value: String(u.value) }));
    } catch (e) { errs.push(e.message); }
  }
  throw new Error('UTXO olinmadi: ' + errs.join(' | '));
}

export async function broadcast(hex) {
  const errs = [];
  try {
    const r = await fetch(bk(`${BLOCKCHAIR}/push/transaction`), {
      method: 'POST',
      headers: { ...HEADERS, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'data=' + hex,
    });
    const j = await r.json();
    const id = j && j.data && j.data.transaction_hash;
    if (id) return id;
    errs.push('Blockchair: ' + ((j && j.context && j.context.error) || r.status));
  } catch (e) { errs.push(e.message); }
  for (const base of BLOCKBOOKS) {
    try {
      const r = await fetch(`${base}/api/v2/sendtx/`, { method: 'POST', headers: HEADERS, body: hex });
      const j = await r.json();
      if (j.result) return j.result;
      errs.push(j.error || base + ' ' + r.status);
    } catch (e) { errs.push(e.message); }
  }
  throw new Error('Yuborilmadi: ' + errs.join(' | '));
}

export const zecToZat = (s) => {
  const m = /^(\d+)(?:[.,](\d{1,8}))?$/.exec(s.trim());
  if (!m) throw new Error('Miqdor formati noto‘g‘ri');
  return BigInt(m[1]) * 100000000n + BigInt((m[2] || '').padEnd(8, '0'));
};
export const zatToZec = (z) => {
  const n = BigInt(z);
  return `${n / 100000000n}.${(n % 100000000n).toString().padStart(8, '0')}`;
};
