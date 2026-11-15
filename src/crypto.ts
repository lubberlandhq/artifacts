const enc = new TextEncoder();
const dec = new TextDecoder();

export function b64url(bytes: ArrayBuffer | Uint8Array): string {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = "";
  for (const b of u8) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function unb64url(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

export async function sha256Hex(data: ArrayBuffer | Uint8Array | string): Promise<string> {
  const buf = typeof data === "string" ? enc.encode(data) : data;
  const h = await crypto.subtle.digest("SHA-256", buf);
  return [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Lowercase only: an artifact id is also a DNS label on the content domain, and DNS is
// case-insensitive (Claude keeps a separate UUID for the same reason).
const ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789";
// A UUID whose first 48 bits are the time in milliseconds (version 7), so ids sort by creation.
export function timeOrderedUuid(now = Date.now()): string {
  const b = crypto.getRandomValues(new Uint8Array(16));
  for (let i = 5, t = now; i >= 0; i--, t = Math.floor(t / 256)) b[i] = t % 256;
  b[6] = (b[6] & 0x0f) | 0x70;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

export function randomId(len = 20): string {
  const out: string[] = [];
  // Rejection sampling keeps the distribution uniform (256 % 36 != 0).
  while (out.length < len) {
    for (const b of crypto.getRandomValues(new Uint8Array(len * 2))) {
      if (b < 252 && out.length < len) out.push(ALPHABET[b % 36]);
    }
  }
  return out.join("");
}

export function randomToken(bytes = 32): string {
  return b64url(crypto.getRandomValues(new Uint8Array(bytes)));
}

async function hmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
    "verify",
  ]);
}

// Reversible encryption for a value the service must hand back later (a share link's capability).
// AES-GCM under a key derived from the secret and the purpose; output is base64url(iv || ciphertext).
async function aesKey(secret: string, purpose: string): Promise<CryptoKey> {
  const raw = await crypto.subtle.digest("SHA-256", enc.encode(`${purpose}\n${secret}`));
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

export async function encryptText(secret: string, purpose: string, text: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await aesKey(secret, purpose), enc.encode(text)));
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv);
  out.set(ct, iv.length);
  return b64url(out);
}

export async function decryptText(secret: string, purpose: string, sealed: string): Promise<string | null> {
  try {
    const raw = unb64url(sealed);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: raw.slice(0, 12) }, await aesKey(secret, purpose), raw.slice(12));
    return dec.decode(pt);
  } catch {
    return null;
  }
}

// A signed, expiring JSON envelope: base64url(payload).base64url(hmac). `purpose` is mixed into
// the MAC so a token minted for one use (a content-frame grant) is never accepted for another
// (a session).
export async function seal(secret: string, purpose: string, payload: Record<string, unknown>, ttlSeconds: number) {
  const body = b64url(enc.encode(JSON.stringify({ ...payload, p: purpose, exp: Math.floor(Date.now() / 1000) + ttlSeconds })));
  const mac = await crypto.subtle.sign("HMAC", await hmacKey(secret), enc.encode(`${purpose}.${body}`));
  return `${body}.${b64url(mac)}`;
}

export async function unseal<T = Record<string, unknown>>(secret: string, purpose: string, token: string): Promise<T | null> {
  const [body, mac, extra] = token.split(".");
  if (!body || !mac || extra !== undefined) return null;
  let ok = false;
  try {
    ok = await crypto.subtle.verify("HMAC", await hmacKey(secret), unb64url(mac), enc.encode(`${purpose}.${body}`));
  } catch {
    return null;
  }
  if (!ok) return null;
  let payload: { p?: string; exp?: number };
  try {
    payload = JSON.parse(dec.decode(unb64url(body)));
  } catch {
    return null;
  }
  if (payload.p !== purpose || typeof payload.exp !== "number" || payload.exp < Date.now() / 1000) return null;
  return payload as T;
}
