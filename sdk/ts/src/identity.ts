// Ed25519 and P-256 identities (did:key / did:web), DSSE envelopes. node:crypto only.

import { createPrivateKey, createPublicKey, generateKeyPairSync, sign as edSign, verify as edVerify, createHash, type KeyObject } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function base58(bytes: Uint8Array): string {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let s = "";
  while (n > 0n) {
    s = B58[Number(n % 58n)] + s;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b !== 0) break;
    s = "1" + s;
  }
  return s;
}

export function unbase58(s: string): Uint8Array {
  let n = 0n;
  for (const c of s) {
    const i = B58.indexOf(c);
    if (i < 0) throw new Error("invalid base58");
    n = n * 58n + BigInt(i);
  }
  const out: number[] = [];
  while (n > 0n) {
    out.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  for (const c of s) {
    if (c !== "1") break;
    out.unshift(0);
  }
  return Uint8Array.from(out);
}

export function didKey(pk: Uint8Array): string {
  return "did:key:z" + base58(Uint8Array.from([0xed, 0x01, ...pk]));
}

/** Raw public key: 32 bytes (Ed25519) or 33 bytes (P-256, compressed). */
export function publicKeyFromDidKey(id: string): Uint8Array | null {
  const base = id.split("#")[0];
  if (!base.startsWith("did:key:z")) return null;
  const b = unbase58(base.slice(9));
  if (b.length === 34 && b[0] === 0xed && b[1] === 0x01) return b.slice(2);
  if (b.length === 35 && b[0] === 0x80 && b[1] === 0x24 && (b[2] === 2 || b[2] === 3)) return b.slice(2);
  return null;
}

/** Verify a signature by an Ed25519 (32-byte) or P-256 (33-byte) key. */
export function verifySignature(pk: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean {
  if (pk.length === 32) return verifyEd25519(pk, msg, sig);
  try {
    // SPKI with a compressed EC point (id-ecPublicKey, prime256v1).
    const der = Buffer.concat([Buffer.from("3039301306072a8648ce3d020106082a8648ce3d030107032200", "hex"), Buffer.from(pk)]);
    return edVerify("sha256", msg, { key: createPublicKey({ key: der, format: "der", type: "spki" }), dsaEncoding: "ieee-p1363" }, sig);
  } catch {
    return false;
  }
}

const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

function pubKeyObject(pk: Uint8Array): KeyObject {
  return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, Buffer.from(pk)]), format: "der", type: "spki" });
}

export function verifyEd25519(pk: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean {
  try {
    return edVerify(null, msg, pubKeyObject(pk), sig);
  } catch {
    return false;
  }
}

export function sha256Hex(b: Uint8Array | string): string {
  return createHash("sha256").update(b).digest("hex");
}

/** A signing identity: an id plus an Ed25519 or P-256 key (same file format as `remit keygen`). */
export class Identity {
  readonly alg: "Ed25519" | "ES256";
  readonly id: string;
  readonly keyId: string;
  readonly publicKey: Uint8Array;
  #key: KeyObject;

  private constructor(key: KeyObject, id?: string) {
    this.#key = key;
    const jwk = createPublicKey(key).export({ format: "jwk" }) as { crv: string; x: string; y?: string };
    const x = Buffer.from(jwk.x, "base64url");
    this.alg = jwk.crv === "P-256" ? "ES256" : "Ed25519";
    this.publicKey = this.alg === "ES256" ? Uint8Array.from([2 + (Buffer.from(jwk.y!, "base64url")[31] & 1), ...x]) : new Uint8Array(x);
    const dk = this.didKey;
    this.id = id ?? dk;
    this.keyId = this.id.startsWith("did:key:") ? this.id : `${this.id}#${dk.slice("did:key:".length)}`;
  }

  static generateP256(id?: string): Identity {
    return new Identity(generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey, id);
  }

  /** P-256 identity from a 32-byte private scalar. */
  static fromP256(d: Uint8Array, id?: string): Identity {
    // SEC1 ECPrivateKey without the public key: OpenSSL derives it.
    const sec1 = Buffer.concat([Buffer.from("30310201010420", "hex"), Buffer.from(d), Buffer.from("a00a06082a8648ce3d030107", "hex")]);
    return new Identity(createPrivateKey({ key: sec1, format: "der", type: "sec1" }), id);
  }

  static generate(id?: string): Identity {
    return new Identity(generateKeyPairSync("ed25519").privateKey, id);
  }

  static fromSeed(seed: Uint8Array, id?: string): Identity {
    return new Identity(createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, Buffer.from(seed)]), format: "der", type: "pkcs8" }), id);
  }

  static fromJSON(f: { id: string; secret_key: string; key_id?: string; alg?: string }): Identity {
    if (f.alg === "ES256") return Identity.fromP256(Buffer.from(f.secret_key, "base64"), f.id);
    return Identity.fromSeed(Buffer.from(f.secret_key, "base64"), f.id);
  }

  static load(path: string): Identity {
    return Identity.fromJSON(JSON.parse(readFileSync(path, "utf8")));
  }

  /** `REMIT_IDENTITY` (path to an identity file) or `REMIT_SECRET_KEY` + `REMIT_ID`. */
  static async fromEnv(): Promise<Identity> {
    const p = process.env.REMIT_IDENTITY;
    if (p) return Identity.load(p);
    const sk = process.env.REMIT_SECRET_KEY;
    if (sk) return Identity.fromSeed(Buffer.from(sk, "base64"), process.env.REMIT_ID);
    throw new Error("set REMIT_IDENTITY (path to `remit keygen` output) or REMIT_SECRET_KEY");
  }

  get didKey(): string {
    return this.alg === "ES256" ? "did:key:z" + base58(Uint8Array.from([0x80, 0x24, ...this.publicKey])) : didKey(this.publicKey);
  }

  sign(msg: Uint8Array): Uint8Array {
    if (this.alg === "ES256") return new Uint8Array(edSign("sha256", msg, { key: this.#key, dsaEncoding: "ieee-p1363" }));
    return new Uint8Array(edSign(null, msg, this.#key));
  }

  toJSON() {
    if (this.alg === "ES256") {
      const { d } = this.#key.export({ format: "jwk" }) as { d: string };
      return { id: this.id, key_id: this.keyId, alg: "ES256", secret_key: Buffer.from(d, "base64url").toString("base64"), public_key: this.didKey };
    }
    const pkcs8 = this.#key.export({ format: "der", type: "pkcs8" }) as Buffer;
    return { id: this.id, key_id: this.keyId, secret_key: pkcs8.subarray(pkcs8.length - 32).toString("base64"), public_key: this.didKey };
  }

  save(path: string) {
    writeFileSync(path, JSON.stringify(this.toJSON(), null, 2));
  }
}

export interface Envelope {
  payloadType: string;
  payload: string;
  signatures: { keyid: string; sig: string }[];
}

export const MANIFEST_TYPE = "application/vnd.remit.manifest+json";
export const RECEIPT_TYPE = "application/vnd.remit.receipt+json";
export const CATALOG_TYPE = "application/vnd.remit.catalog+json";

export function pae(type: string, body: Uint8Array): Uint8Array {
  const t = Buffer.from(type);
  return Buffer.concat([Buffer.from(`DSSEv1 ${t.length} `), t, Buffer.from(` ${body.length} `), Buffer.from(body)]);
}

export function signEnvelope(type: string, body: Uint8Array, id: Identity): Envelope {
  return { payloadType: type, payload: Buffer.from(body).toString("base64"), signatures: [{ keyid: id.keyId, sig: Buffer.from(id.sign(pae(type, body))).toString("base64") }] };
}

export function openEnvelope(env: Envelope, type: string, key: Uint8Array): Uint8Array {
  if (env.payloadType !== type) throw new Error(`payloadType must be ${type}`);
  const body = Buffer.from(env.payload, "base64");
  const ok = env.signatures.some((s) => verifySignature(key, pae(type, body), Buffer.from(s.sig, "base64")));
  if (!ok) throw new Error("envelope signature does not verify");
  return body;
}
