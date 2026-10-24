// One Worker, three kinds of host:
//   APP_ORIGIN      share.example.com            viewer shell, gallery, API (public; the Worker authorizes)
//   LOGIN_ORIGIN    share-login.example.com      behind Cloudflare Access; turns an Access login into a session
//   CONTENT_DOMAIN  <id>.<content domain>        each artifact's own origin, served only with a grant
import { handleApi } from "./api";
import { clearSessionCookie, currentUser, mintHandoff, redeemHandoff, safeNext, sessionCookie, verifyAccessJwt } from "./auth";
import { canRead, orgPolicy, visibleVersion } from "./authz";
import { contentIdFromHost, contentUrl, serveContent } from "./content";
import type { Env } from "./env";
import { devLoginPage, galleryPage, messagePage, viewerPage } from "./pages";
import { getArtifact } from "./store";

const redirect = (location: string, cookie?: string) =>
  new Response(null, { status: 302, headers: { Location: location, "Cache-Control": "no-store", ...(cookie ? { "Set-Cookie": cookie } : {}) } });

const devMode = (env: Env) => env.DEV_LOGIN === "1" && !env.APP_ORIGIN.startsWith("https:");

function loginUrl(env: Env, next: string) {
  return devMode(env) ? `/login?next=${encodeURIComponent(next)}` : `${env.LOGIN_ORIGIN}/login?next=${encodeURIComponent(next)}`;
}

async function loginHost(req: Request, env: Env, url: URL): Promise<Response> {
  if (url.pathname !== "/login") return redirect(`${env.APP_ORIGIN}/`);
  // Access has already authenticated the browser to reach this hostname; verify its token anyway,
  // because a misconfigured or missing Access app must never mean "anyone is whoever they say".
  const jwt = req.headers.get("Cf-Access-Jwt-Assertion");
  const email = jwt ? await verifyAccessJwt(env, jwt).catch(() => null) : null;
  if (!email) return messagePage(env, "Sign-in failed", "Cloudflare Access did not vouch for this request.");
  const h = await mintHandoff(env, email);
  return redirect(`${env.APP_ORIGIN}/auth/callback?h=${encodeURIComponent(h)}&next=${encodeURIComponent(safeNext(url.searchParams.get("next")))}`);
}

async function appHost(req: Request, env: Env, url: URL): Promise<Response> {
  const path = url.pathname;
  if (path.startsWith("/api/") || path === "/api") return handleApi(req, env, url);

  if (path === "/login") {
    const next = safeNext(url.searchParams.get("next"));
    return devMode(env) ? devLoginPage(env, next) : redirect(loginUrl(env, next));
  }
  if (path === "/login/dev" && req.method === "POST" && devMode(env)) {
    const form = await req.formData();
    const email = String(form.get("email") ?? "").trim().toLowerCase();
    if (!email.includes("@")) return messagePage(env, "Sign-in failed", "Enter an email.");
    return redirect(safeNext(String(form.get("next") ?? "/")), await sessionCookie(env, email));
  }
  if (path === "/auth/callback") {
    const email = await redeemHandoff(env, url.searchParams.get("h") ?? "");
    if (!email) return messagePage(env, "Sign-in expired", "That sign-in link was used or is too old.", { href: "/login", label: "Sign in again" });
    return redirect(safeNext(url.searchParams.get("next")), await sessionCookie(env, email));
  }
  if (path === "/logout") {
    return new Response(null, { status: 302, headers: { Location: devMode(env) ? "/login" : `${env.LOGIN_ORIGIN}/cdn-cgi/access/logout`, "Set-Cookie": clearSessionCookie() } });
  }

  const user = await currentUser(req, env);
  const email = user?.email ?? null;

  if (path === "/") return email ? galleryPage(env, email) : redirect(loginUrl(env, "/"));

  const m = path.match(/^\/a\/([a-z0-9]{20})\/?$/);
  if (m) {
    const a = await getArtifact(env, m[1]);
    const policy = orgPolicy(env);
    if (a && canRead(policy, a, email)) {
      const v = visibleVersion(policy, a, email, Number(url.searchParams.get("v")) || undefined);
      return viewerPage(env, a, email, v, await contentUrl(env, a.id, v));
    }
    if (!email) return redirect(loginUrl(env, path));
    return messagePage(env, "Not shared with you", `${email} can't open this artifact. Ask its owner to share it with you, or sign in as someone else.`, {
      href: "/logout",
      label: "Switch account",
    });
  }
  return messagePage(env, "Not found", "Nothing lives at this address.");
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    const id = contentIdFromHost(env, url.host);
    if (id) return serveContent(req, env, id);
    if (env.LOGIN_ORIGIN && url.origin === env.LOGIN_ORIGIN) return loginHost(req, env, url);
    return appHost(req, env, url);
  },
} satisfies ExportedHandler<Env>;
