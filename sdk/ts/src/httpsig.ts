// RFC 9421 HTTP message signatures + RFC 9530 Content-Digest for requests to a
// Holder (binds the envelope to one request; required by strict Holders).

import { createHash, randomBytes } from "node:crypto";
import type { Identity } from "./identity.ts";

export function contentDigest(body: Uint8Array | string): string {
  return `sha-256=:${createHash("sha256").update(body).digest("base64")}:`;
}

/** Headers to add to a request signed by `id`. */
export function signRequest(id: Identity, method: string, url: string, body: string, o: { ttlSeconds?: number; tag?: string; now?: number } = {}): Record<string, string> {
  const u = new URL(url);
  const created = o.now ?? Math.floor(Date.now() / 1000);
  const digest = contentDigest(body);
  const comps: [string, string][] = [
    ["@method", method.toUpperCase()],
    ["@authority", u.host.toLowerCase()],
    ["@path", u.pathname],
    ["content-digest", digest],
  ];
  if (u.search) comps.push(["@query", u.search]);
  const params = `(${comps.map(([n]) => `"${n}"`).join(" ")});created=${created};expires=${created + (o.ttlSeconds ?? 60)};nonce="${randomBytes(12).toString("hex")}";alg="${id.alg === "ES256" ? "ecdsa-p256-sha256" : "ed25519"}";keyid="${id.keyId}";tag="${o.tag ?? "remit"}"`;
  const base = [...comps.map(([n, v]) => `"${n}": ${v}`), `"@signature-params": ${params}`].join("\n");
  return {
    "content-digest": digest,
    "signature-input": `sig1=${params}`,
    signature: `sig1=:${Buffer.from(id.sign(Buffer.from(base))).toString("base64")}:`,
  };
}
