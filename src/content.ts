// The content origin: https://<id>.<CONTENT_DOMAIN>/t/<grant>/<path>
// Every artifact gets its own browser origin (its storage, cookies and service workers are its
// own and can't reach the app or another artifact) on a registrable domain apart from the app.
// The grant sits in the path, not a cookie, so it works in a third-party iframe on every browser,
// and relative references inside the page (the way Claude's contract says to write them) carry it
// along for free. Without a valid grant the origin answers 404, as Claude's frame origin does.
import { contentCsp, SECURITY_HEADERS } from "./csp";
import { seal, unseal } from "./crypto";
import type { Env } from "./env";
import { getManifest } from "./store";

const GRANT_TTL = 12 * 3600;

export function contentOrigin(env: Env, id: string): string {
  return `${env.CONTENT_SCHEME}://${id}.${env.CONTENT_DOMAIN}`;
}

export async function contentUrl(env: Env, id: string, ver: number): Promise<string> {
  const grant = await seal(env.SESSION_SECRET, "content", { a: id, v: ver }, GRANT_TTL);
  return `${contentOrigin(env, id)}/t/${grant}/`;
}

export function contentIdFromHost(env: Env, host: string): string | null {
  const suffix = `.${env.CONTENT_DOMAIN}`;
  if (!host.endsWith(suffix)) return null;
  const label = host.slice(0, -suffix.length);
  return /^[a-z0-9]{20}$/.test(label) ? label : null;
}

const notFound = () => new Response("Not found", { status: 404, headers: SECURITY_HEADERS });

export async function serveContent(req: Request, env: Env, id: string): Promise<Response> {
  if (req.method !== "GET" && req.method !== "HEAD") return new Response("Method not allowed", { status: 405 });
  const url = new URL(req.url);
  const m = url.pathname.match(/^\/t\/([^/]+)\/(.*)$/);
  if (!m) return notFound();
  const grant = await unseal<{ a: string; v: number }>(env.SESSION_SECRET, "content", m[1]);
  if (!grant || grant.a !== id) return notFound();

  let path: string;
  try {
    path = decodeURIComponent(m[2]);
  } catch {
    return notFound();
  }
  if (path === "" || path.endsWith("/")) path += "index.html";

  const manifest = await getManifest(env, id, grant.v);
  const entry = manifest?.[path];
  if (!entry) return notFound();

  const etag = `"${entry.sha256}"`;
  const headers = new Headers({
    ...SECURITY_HEADERS,
    "Content-Type": entry.type,
    "Content-Security-Policy": contentCsp(env.APP_ORIGIN),
    // A version's bytes never change, but the grant in the URL expires: cache privately only.
    "Cache-Control": "private, max-age=3600",
    ETag: etag,
    "Cross-Origin-Resource-Policy": "same-site",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), usb=(), payment=()",
  });
  if (req.headers.get("If-None-Match") === etag) return new Response(null, { status: 304, headers });

  const obj = await env.BLOBS.get(`blob/${entry.sha256}`);
  if (!obj) return notFound();
  headers.set("Content-Length", String(entry.size));
  return new Response(req.method === "HEAD" ? null : obj.body, { headers });
}
