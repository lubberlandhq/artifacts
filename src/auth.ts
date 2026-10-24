// Identity. Humans sign in through Cloudflare Access on the login host (GitHub, Google or an
// emailed one-time PIN — the IdPs live/cloudflare already has), which hands a single-use token
// back to the app host; the app host then keeps its own session cookie. That split exists because
// Access only attaches its token on hostnames it protects, and the app host must stay reachable
// without a login for public links (the same reason Kingpin has two hostnames).
// Agents and the CLI use bearer tokens minted from the dashboard.
import { randomToken, seal, sha256Hex, unb64url, unseal } from "./crypto";
import type { Env, User } from "./env";

const SESSION_COOKIE = "ls_session";
const SESSION_TTL = 7 * 24 * 3600;
const HANDOFF_TTL = 60;

function cookie(req: Request, name: string): string | null {
  for (const part of (req.headers.get("Cookie") ?? "").split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return v.join("=");
  }
  return null;
}

export async function currentUser(req: Request, env: Env): Promise<User | null> {
  const authz = req.headers.get("Authorization");
  if (authz?.startsWith("Bearer ")) {
    const hash = await sha256Hex(authz.slice(7).trim());
    const row = await env.DB.prepare("SELECT owner FROM tokens WHERE hash = ?").bind(hash).first<{ owner: string }>();
    if (!row) return null;
    await env.DB.prepare("UPDATE tokens SET last_used = ? WHERE hash = ?").bind(new Date().toISOString(), hash).run();
    return { email: row.owner, via: "token" };
  }
  const c = cookie(req, SESSION_COOKIE);
  if (!c) return null;
  const s = await unseal<{ email: string }>(env.SESSION_SECRET, "session", c);
  return s ? { email: s.email, via: "session" } : null;
}

export async function sessionCookie(env: Env, email: string): Promise<string> {
  const v = await seal(env.SESSION_SECRET, "session", { email: email.toLowerCase() }, SESSION_TTL);
  const secure = env.APP_ORIGIN.startsWith("https:") ? "; Secure" : "";
  return `${SESSION_COOKIE}=${v}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_TTL}${secure}`;
}

export function clearSessionCookie(): string {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`;
}

// Only same-site relative paths survive a round trip through the login host.
export function safeNext(next: string | null): string {
  return next && next.startsWith("/") && !next.startsWith("//") && !next.includes("\\") ? next : "/";
}

export async function mintHandoff(env: Env, email: string): Promise<string> {
  return seal(env.SESSION_SECRET, "handoff", { email: email.toLowerCase(), n: randomToken(12) }, HANDOFF_TTL);
}

export async function redeemHandoff(env: Env, token: string): Promise<string | null> {
  const h = await unseal<{ email: string; n: string; exp: number }>(env.SESSION_SECRET, "handoff", token);
  if (!h) return null;
  const now = Math.floor(Date.now() / 1000);
  await env.DB.prepare("DELETE FROM handoffs WHERE expires < ?").bind(now).run();
  const ins = await env.DB.prepare("INSERT OR IGNORE INTO handoffs (nonce, expires) VALUES (?, ?)").bind(h.n, h.exp).run();
  return ins.meta.changes === 1 ? h.email : null; // a replayed handoff inserts nothing
}

// ---- Cloudflare Access JWT (RS256), verified against the team's published keys -------------

interface Jwk extends JsonWebKey {
  kid: string;
}
let certCache: { keys: Jwk[]; at: number } | null = null;

async function accessKeys(team: string): Promise<Jwk[]> {
  if (certCache && Date.now() - certCache.at < 3600_000) return certCache.keys;
  const r = await fetch(`https://${team}/cdn-cgi/access/certs`);
  if (!r.ok) throw new Error(`Access certs: HTTP ${r.status}`);
  const { keys } = (await r.json()) as { keys: Jwk[] };
  certCache = { keys, at: Date.now() };
  return keys;
}

export async function verifyAccessJwt(env: Env, jwt: string): Promise<string | null> {
  const [h, p, s] = jwt.split(".");
  if (!h || !p || !s) return null;
  const dec = new TextDecoder();
  const header = JSON.parse(dec.decode(unb64url(h))) as { kid?: string; alg?: string };
  if (header.alg !== "RS256") return null;
  const jwk = (await accessKeys(env.ACCESS_TEAM_DOMAIN)).find((k) => k.kid === header.kid);
  if (!jwk) return null;
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, unb64url(s), new TextEncoder().encode(`${h}.${p}`));
  if (!ok) return null;
  const claims = JSON.parse(dec.decode(unb64url(p))) as { aud?: string | string[]; exp?: number; iss?: string; email?: string };
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!aud.includes(env.ACCESS_AUD)) return null;
  if (claims.iss !== `https://${env.ACCESS_TEAM_DOMAIN}`) return null;
  if (!claims.exp || claims.exp < Date.now() / 1000) return null;
  return claims.email?.toLowerCase() ?? null; // service tokens carry no email and get no session
}

export async function createApiToken(env: Env, owner: string, label: string, createdBy: string): Promise<string> {
  const token = `lsh_${randomToken(30)}`;
  await env.DB.prepare("INSERT INTO tokens (hash, owner, label, created_at, created_by) VALUES (?, ?, ?, ?, ?)")
    .bind(await sha256Hex(token), owner, label, new Date().toISOString(), createdBy)
    .run();
  return token;
}
