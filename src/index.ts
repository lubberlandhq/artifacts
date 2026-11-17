// One Worker, three kinds of host:
//   APP_ORIGIN      share.example.com            viewer shell, gallery, API (public; the Worker authorizes)
//   LOGIN_ORIGIN    share-login.example.com      behind Cloudflare Access; turns an Access login into a session
//   CONTENT_DOMAIN  <id>.<content domain>        each artifact's own origin, served only with a grant
//                   (any other name on the content domain answers 404, whatever the method or path)
import { handleApi } from "./api";
import { clearSessionCookie, currentUser, mintHandoff, redeemHandoff, safeNext, sessionCookie, verifyAccessJwt } from "./auth";
import { canRead, orgPolicy, visibleVersion } from "./authz";
import { contentIdFromHost, contentOrigin, contentUrl, notFound, onContentDomain, serveContent } from "./content";
import type { Env } from "./env";
import { devicePage, devLoginPage, galleryPage, messagePage, sharedBoardPage, viewerPage } from "./pages";
import { getArtifact } from "./store";
import { approveDevice, devicePending, handleWhiteboardApi, isWhiteboardApi, normalizeUserCode, resolveShared, sharedFrame } from "./whiteboard";

const redirect = (location: string, cookie?: string) =>
  new Response(null, { status: 302, headers: { Location: location, "Cache-Control": "no-store", ...(cookie ? { "Set-Cookie": cookie } : {}) } });

const hostOf = (origin: string) => (origin ? new URL(origin).host : "");

const withStatus = (r: Response, status: number) => new Response(r.body, { status, headers: r.headers });

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
  if (isWhiteboardApi(path)) return handleWhiteboardApi(req, env, url);
  if (path.startsWith("/api/") || path === "/api") return handleApi(req, env, url);

  // A shared Whiteboard board. No sign-in: the capability in the link is the access control.
  const shared = path.match(/^\/s\/([^/]+)$/);
  if (shared) {
    const s = await resolveShared(env, shared[1], url.searchParams.get("rev"));
    if (!s) return withStatus(messagePage(env, "Not found", "This share link is wrong or was revoked."), 404);
    // Desktop takes the link apart again: dev-fast-review://share/<capability>?origin=&rev=.
    // A board that quotes uncommitted changes is view only, so it gets no button.
    const scheme = url.searchParams.get("app") === "preview" ? "dev-fast-review-preview" : "dev-fast-review";
    const openHref = s.revision.frozen
      ? null
      : `${scheme}://share/${shared[1]}?origin=${encodeURIComponent(env.APP_ORIGIN)}&rev=${s.revision.id}`;
    return sharedBoardPage(env, {
      title: s.share.title,
      sender: s.revision.sender,
      sharedAt: s.revision.created_at,
      version: s.revision.version,
      frameSrc: await sharedFrame(env, s),
      frameOrigin: contentOrigin(env, s.share.content_id),
      openHref,
    });
  }

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

  // Whiteboard's device login: the person signed in here approves the code their computer shows.
  if (path === "/device") {
    // A browser session only: a token must never approve a code, or it could mint itself another token.
    if (user?.via !== "session") return redirect(loginUrl(env, path + url.search));
    const email = user.email;
    if (req.method === "POST") {
      if (req.headers.get("Origin") !== env.APP_ORIGIN) return withStatus(messagePage(env, "Not approved", "That request came from another site."), 403);
      const form = await req.formData().catch(() => null);
      const code = normalizeUserCode(String(form?.get("user_code") ?? ""));
      return code && (await approveDevice(env, code, email))
        ? messagePage(env, "Whiteboard is signed in", `It is signed in as ${email}. Go back to Whiteboard; this tab can be closed.`)
        : messagePage(env, "Code not accepted", "That code is wrong, already used, or more than ten minutes old. Start the sign-in again from Whiteboard.");
    }
    const raw = url.searchParams.get("user_code");
    if (raw === null) return devicePage(env, email, null);
    const code = normalizeUserCode(raw);
    return code && (await devicePending(env, code))
      ? devicePage(env, email, code)
      : messagePage(env, "Code not accepted", "That code is wrong, already used, or more than ten minutes old. Start the sign-in again from Whiteboard.");
  }

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
  return withStatus(messagePage(env, "Not found", "Nothing lives at this address.", { href: "/", label: "Back to Tack" }), 404);
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    const id = contentIdFromHost(env, url.host);
    if (id) return serveContent(req, env, id);
    // The rest of the content domain is no one's origin: 404 for every method and path, so the
    // app's API and pages never answer on a hostname meant to keep pages away from them.
    if (onContentDomain(env, url.host) && url.host !== hostOf(env.APP_ORIGIN) && url.host !== hostOf(env.LOGIN_ORIGIN)) return notFound();
    if (env.LOGIN_ORIGIN && url.origin === env.LOGIN_ORIGIN) return loginHost(req, env, url);
    return appHost(req, env, url);
  },
} satisfies ExportedHandler<Env>;
