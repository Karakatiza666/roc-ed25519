// Test vectors of roc-ed25519, made with node:crypto and BigInt only (not with the code under test).
// Usage (repo root): node scripts/vectors.mjs
//   Checks each vector against node:crypto, then prints the Roc constants of tests/sha512.roc, tests/rfc8032.roc and tests/ed25519.roc.
// Sources:
//   SHA-512: FIPS 180-4 examples (NIST CSRC "SHA512.pdf"): "abc" (one block), the 896-bit message (two blocks), and the empty message. The other lengths are from node:crypto.
//   Ed25519: RFC 8032 section 7.1 (rfc8032-7.1.txt next to this file, copied from https://www.rfc-editor.org/rfc/rfc8032.txt on 2026-11-23).
//   The rejection rules are those of Go crypto/ed25519 (Go 1.17 and later, filippo.io/edwards25519):
//     len(sig) != 64 or sig[63] & 0xE0 != 0: false. A that does not decode (SetBytes): false. S not canonical (SetCanonicalBytes, S >= L): false.
//     R is not decoded: Go compares the encoding of [S]B - [k]A with sig[0..32], so an R that is not a point never matches.
//     Go does NOT reject a small-order A or R (cofactorless, no check), so there is no small-order rejection vector.
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const hex = (b) => Buffer.from(b).toString("hex");
const sha512 = (b) => createHash("sha512").update(Buffer.from(b)).digest();
const fail = (m) => { console.error("FAIL: " + m); process.exit(1); };
const eq = (a, b, m) => { if (a !== b) fail(`${m}: ${a} != ${b}`); };

// --- SHA-512 ---
const FIPS = {
  empty: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
  abc: "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
  two: "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
};
const TWO = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
eq(hex(sha512(Buffer.alloc(0))), FIPS.empty, "sha512 empty");
eq(hex(sha512(Buffer.from("abc"))), FIPS.abc, "sha512 abc");
eq(hex(sha512(Buffer.from(TWO))), FIPS.two, "sha512 896-bit");
// pattern(n): byte i is (i * 31 + 7) mod 256. The Roc test makes the same bytes.
const pattern = (n) => Buffer.from(Array.from({ length: n }, (_, i) => (i * 31 + 7) % 256));
const LENGTHS = [1, 111, 112, 113, 127, 128, 129, 239, 240, 255, 256, 1000, 8192];
const lengthVectors = LENGTHS.map((n) => [n, hex(sha512(pattern(n)))]);

// --- Ed25519: RFC 8032 7.1 ---
const rfc = readFileSync(join(HERE, "rfc8032-7.1.txt"), "utf8").split("\n").filter((l) => !/^(Josefsson|RFC 8032|\f)/.test(l));
// The hex lines after the label, up to the next label (a line that starts with an upper-case word) or the end. Blank lines (also at a page break) are skipped.
function field(lines, name) {
  const i = lines.findIndex((l) => l.trim().startsWith(name));
  let out = "";
  for (let j = i + 1; j < lines.length; j++) {
    const t = lines[j].trim();
    if (t === "") continue;
    if (/^[0-9a-f]+$/.test(t)) out += t;
    else break;
  }
  return out;
}
const tests = [];
const starts = rfc.map((l, i) => [l, i]).filter(([l]) => l.trim().startsWith("-----TEST"));
for (let k = 0; k < starts.length; k++) {
  const [l, i] = starts[k];
  const end = k + 1 < starts.length ? starts[k + 1][1] : rfc.length;
  const block = rfc.slice(i, end);
  tests.push({ name: l.trim().replace("-----TEST ", ""), sk: field(block, "SECRET KEY:"), pk: field(block, "PUBLIC KEY:"), msg: field(block, "MESSAGE"), sig: field(block, "SIGNATURE:") });
}
const PKCS8 = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI = Buffer.from("302a300506032b6570032100", "hex");
const pub = (pk) => createPublicKey({ key: Buffer.concat([SPKI, Buffer.from(pk, "hex")]), format: "der", type: "spki" });
const okSig = (pk, msg, sig) => { try { return verify(null, Buffer.from(msg, "hex"), pub(pk), Buffer.from(sig, "hex")); } catch { return false; } };
for (const t of tests) {
  const priv = createPrivateKey({ key: Buffer.concat([PKCS8, Buffer.from(t.sk, "hex")]), format: "der", type: "pkcs8" });
  eq(Buffer.from(createPublicKey(priv).export({ format: "jwk" }).x, "base64url").toString("hex"), t.pk, `${t.name} public key`);
  eq(hex(sign(null, Buffer.from(t.msg, "hex"), priv)), t.sig, `${t.name} signature`);
  if (!okSig(t.pk, t.msg, t.sig)) fail(`${t.name} verify`);
}
eq(tests.length, 5, "RFC 8032 7.1 has 5 tests");
eq(tests.find((t) => t.name === "1024").msg.length, 2046, "TEST 1024 message is 1023 bytes");
eq(tests.find((t) => t.name === "SHA(abc)").msg, FIPS.abc, "TEST SHA(abc) message");

// --- Rejection vectors (Go rules) ---
const p = (1n << 255n) - 19n;
const L = (1n << 252n) + 27742317777372353535851937790883648493n;
const mod = (a) => ((a % p) + p) % p;
const pow = (b, e) => { let r = 1n; b = mod(b); while (e > 0n) { if (e & 1n) r = mod(r * b); b = mod(b * b); e >>= 1n; } return r; };
const d = mod(-121665n * pow(121666n, p - 2n));
const le = (n, len = 32) => { const b = Buffer.alloc(len); for (let i = 0; i < len; i++) { b[i] = Number(n & 255n); n >>= 8n; } return b; };
const fromLe = (b) => b.reduceRight((acc, x) => (acc << 8n) + BigInt(x), 0n);
// The smallest y >= 2 for which (y^2 - 1) / (d y^2 + 1) is not a square mod p: no x, so the encoding does not decode.
let badY = 2n;
for (;; badY++) {
  const u = mod(badY * badY - 1n), v = mod(d * badY * badY + 1n);
  const x2 = mod(u * pow(v, p - 2n));
  if (x2 !== 0n && pow(x2, (p - 1n) / 2n) !== 1n) break;
}
const badPoint = hex(le(badY));
if (okSig(badPoint, "", tests[0].sig)) fail("bad A accepted by node");
const t1 = tests[0], t2 = tests[1];
const s1 = fromLe(Buffer.from(t1.sig.slice(64), "hex"));
if (s1 >= L) fail("S of TEST 1 is canonical");
const sigWithS = (s) => t1.sig.slice(0, 64) + hex(le(s));
const sPlusL = sigWithS(s1 + L);           // S + L < 2^253: the high 3 bits are 0, so only the S < L check rejects it
if (Buffer.from(sPlusL, "hex")[63] & 0xe0) fail("S + L has a high bit");
const sEqL = sigWithS(L);
const sHigh = (() => { const b = Buffer.from(t1.sig, "hex"); b[63] |= 0x80; return hex(b); })();
const flip = (h, byte) => { const b = Buffer.from(h, "hex"); b[byte] ^= 0x01; return hex(b); };
const rFlip = flip(t1.sig, 0), sFlip = flip(t1.sig, 32);
const rBad = badPoint + t1.sig.slice(64);
const msgFlip = flip(t2.msg, 0);
for (const [m, pk, msg, sig] of [["S+L", t1.pk, t1.msg, sPlusL], ["S=L", t1.pk, t1.msg, sEqL], ["S high", t1.pk, t1.msg, sHigh], ["R flip", t1.pk, t1.msg, rFlip], ["S flip", t1.pk, t1.msg, sFlip], ["R bad", t1.pk, t1.msg, rBad], ["msg flip", t2.pk, msgFlip, t2.sig], ["other key", t2.pk, t1.msg, t1.sig]]) {
  if (okSig(pk, msg, sig)) fail(`node accepts ${m}`);
}

// --- Print the Roc constants ---
const out = [];
out.push("# --- tests/sha512.roc ---");
out.push(`vec_two_block : Str\nvec_two_block = "${TWO}"`);
out.push(`fips_empty : Str\nfips_empty = "${FIPS.empty}"\n\nfips_abc : Str\nfips_abc = "${FIPS.abc}"\n\nfips_two : Str\nfips_two = "${FIPS.two}"`);
out.push("vec_lengths : List((U64, Str))\nvec_lengths = [\n" + lengthVectors.map(([n, h]) => `\t(${n}, "${h}"),`).join("\n") + "\n]");
out.push("# --- tests/rfc8032.roc and tests/ed25519.roc ---");
out.push("rfc8032 : List({ name : Str, pk : Str, msg : Str, sig : Str })\nrfc8032 = [\n" + tests.map((t) => `\t{ name: "${t.name}", pk: "${t.pk}", msg: "${t.msg}", sig: "${t.sig}" },`).join("\n") + "\n]");
out.push(`bad_point : Str\nbad_point = "${badPoint}" # y = ${badY}: no x`);
out.push(`sig_s_plus_l : Str\nsig_s_plus_l = "${sPlusL}"\n\nsig_s_eq_l : Str\nsig_s_eq_l = "${sEqL}"\n\nsig_s_high : Str\nsig_s_high = "${sHigh}"`);
console.log(out.join("\n\n"));
console.error(`ok: ${LENGTHS.length + 3} SHA-512 vectors, ${tests.length} RFC 8032 vectors, rejection vectors (bad y = ${badY})`);
