// End-to-end against `bun run dev` (wrangler dev -c wrangler.dev.jsonc on :8787). Exercises what a person does:
// sign in, mint a CLI token, publish with tack, view through the shell and the content origin,
// share each way, pin, comment, and check the refusals. Exit 1 on the first failed check.
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const APP = process.env.SMOKE_URL ?? "http://localhost:8787";
const port = new URL(APP).port;
let failed = 0;
const check = (name: string, ok: boolean, detail = "") => {
  console.log(`${ok ? "ok  " : "FAIL"} ${name}${!ok && detail ? ` — ${detail}` : ""}`);
  if (!ok) failed++;
};

async function login(email: string): Promise<string> {
  const r = await fetch(`${APP}/login/dev`, {
    method: "POST",
    body: new URLSearchParams({ email, next: "/" }),
    redirect: "manual",
  });
  return (r.headers.get("set-cookie") ?? "").split(";")[0];
}
const api = (cookie: string, path: string, init: RequestInit = {}) =>
  fetch(`${APP}/api${path}`, {
    ...init,
    headers: { Cookie: cookie, Origin: APP, ...(init.body && typeof init.body === "string" ? { "Content-Type": "application/json" } : {}), ...(init.headers ?? {}) },
  });
// The content origin is <id>.localhost:<port>; send the Host header instead of relying on resolution.
const content = (src: string) => {
  const u = new URL(src);
  return fetch(`http://127.0.0.1:${port}${u.pathname}`, { headers: { Host: u.host } });
};
const TACK_BIN = process.env.TACK_BIN ?? join(import.meta.dir, "../cli/tack");
const tack = (token: string, ...args: string[]) => {
  const r = spawnSync("bun", [TACK_BIN, ...args], {
    env: { ...process.env, TACK_URL: APP, TACK_TOKEN: token },
    encoding: "utf8",
  });
  return { code: r.status, json: r.stdout.trim() ? JSON.parse(r.stdout) : null };
};

const nate = await login("nate@dev.test");
const jj = await login("jj@dev.test");
const client = await login("client@acme.example");
check("dev sign-in sets a session", nate.startsWith("ls_session="));

// Token for the CLI
const tok = await (await api(nate, "/tokens", { method: "POST", body: JSON.stringify({ label: "smoke" }) })).json();
check("token minted", typeof tok.token === "string" && tok.token.startsWith("tck_"));
check("non-publisher can't mint", (await api(client, "/tokens", { method: "POST", body: "{}" })).status === 403);

// Publish a two-file page with the CLI
const dir = mkdtempSync(join(tmpdir(), "tack-"));
mkdirSync(join(dir, "assets"));
writeFileSync(join(dir, "index.html"), `<!doctype html><title>Smoke</title><link rel="stylesheet" href="assets/s.css"><h1>v1</h1>`);
writeFileSync(join(dir, "assets/s.css"), "h1{color:teal}");
const pub = tack(tok.token, "publish", dir, "--title", "Smoke test", "--label", "first");
check("tack publish exits 0", pub.code === 0, JSON.stringify(pub.json));
const id: string = pub.json.id;
check("artifact id is a DNS label", /^[a-z0-9]{20}$/.test(id));
check("starts private", pub.json.sharing?.mode === "owner");

// Shell + content origin
const shell = await fetch(`${APP}/a/${id}`, { headers: { Cookie: nate } });
const html = await shell.text();
check("owner sees the viewer shell", shell.status === 200 && html.includes("Smoke test"));
check("shell frames only this artifact's origin", (shell.headers.get("content-security-policy") ?? "").includes(`frame-src http://${id}.localhost:${port}`));
const frame = await (await api(nate, `/artifacts/${id}/frame`)).json();
const page = await content(frame.src);
check("content origin serves index.html", page.status === 200 && (await page.text()).includes("<h1>v1</h1>"));
check("content CSP set", (page.headers.get("content-security-policy") ?? "").includes(`frame-ancestors ${APP}`));
check("relative asset resolves under the grant", (await (await content(frame.src + "assets/s.css")).text()) === "h1{color:teal}");
check("no grant: 404", (await content(`http://${id}.localhost:${port}/index.html`)).status === 404);
const forged = frame.src.replace(/\/t\/([^/]+)\//, (_: string, g: string) => `/t/${g.slice(0, -3)}xyz/`);
check("forged grant: 404", (await content(forged)).status === 404);
const otherOrigin = frame.src.replace(`${id}.`, `${"b".repeat(20)}.`);
check("grant for one artifact fails on another's origin", (await content(otherOrigin)).status === 404);

// Private: strangers and anonymous are refused, and can't tell it exists
check("anonymous viewer redirected to sign-in", (await fetch(`${APP}/a/${id}`, { redirect: "manual" })).status === 302);
check("signed-in stranger refused", !(await (await fetch(`${APP}/a/${id}`, { headers: { Cookie: client } })).text()).includes("Smoke test"));
check("stranger API sees 404", (await api(client, `/artifacts/${id}`)).status === 404);

// Share with specific people
let s = tack(tok.token, "share", id, "--mode", "people", "--users", "client@acme.example");
check("share with people", s.code === 0 && s.json.sharing.mode === "users");
check("named person can view", (await fetch(`${APP}/a/${id}`, { headers: { Cookie: client } })).status === 200);
check("viewer gets no sharing details", (await (await api(client, `/artifacts/${id}`)).json()).sharing === undefined);
check("viewer can't publish", (await api(client, `/artifacts/${id}/versions`, { method: "POST", body: new FormData() })).status === 403);
check("viewer can't change sharing", (await api(client, `/artifacts/${id}/sharing`, { method: "PUT", body: JSON.stringify({ mode: "public" }) })).status === 403);
check("JJ (org, not named) refused", (await api(jj, `/artifacts/${id}`)).status === 404);

// Org
tack(tok.token, "share", id, "--mode", "org");
check("org mode admits JJ", (await api(jj, `/artifacts/${id}`)).status === 200);
check("org mode drops the client", (await api(client, `/artifacts/${id}`)).status === 404);

// Public + pin
s = tack(tok.token, "share", id, "--mode", "public", "--pin", "current");
check("public, pinned to v1", s.json.sharing.mode === "public" && s.json.sharing.pinned_version === 1);
writeFileSync(join(dir, "index.html"), `<!doctype html><title>Smoke</title><link rel="stylesheet" href="assets/s.css"><h1>v2</h1>`);
const v2 = tack(tok.token, "publish", join(dir, "index.html"), "--id", id, "--label", "second");
check("publish v2 keeps files left out", v2.code === 0 && v2.json.live_version === 2);
const anonFrame = await (await fetch(`${APP}/api/artifacts/${id}/frame?v=2`)).json();
check("anonymous sees pinned v1 even when asking for v2", anonFrame.version === 1);
check("anonymous v1 content", (await (await content(anonFrame.src)).text()).includes("<h1>v1</h1>"));
const ownerFrame = await (await api(nate, `/artifacts/${id}/frame`)).json();
check("owner sees live v2", ownerFrame.version === 2 && (await (await content(ownerFrame.src)).text()).includes("<h1>v2</h1>"));
check("v2 still has the css (copied forward)", (await content(ownerFrame.src + "assets/s.css")).status === 200);
tack(tok.token, "share", id, "--pin", "live");
check("unpinned: anonymous follows live", (await (await fetch(`${APP}/api/artifacts/${id}/head`)).json()).version === 2);

// Concurrency guard
const stale = tack(tok.token, "publish", join(dir, "index.html"), "--id", id, "--base", "1");
check("publish built on a stale version is refused", stale.code === 5 && /newer/.test(stale.json?.error ?? ""));

// Comments
check("anonymous can't comment", (await fetch(`${APP}/api/artifacts/${id}/comments`, { method: "POST", body: "{}" })).status === 401);
check("JJ comments", (await api(jj, `/artifacts/${id}/comments`, { method: "POST", body: JSON.stringify({ body: "Looks right" }) })).status === 201);
const cl = tack(tok.token, "comments", id);
check("tack reads comments", cl.json.length === 1 && cl.json[0].author === "jj@dev.test");

// Editors
tack(tok.token, "share", id, "--mode", "private", "--editors", "jj@dev.test");
const fdj = new FormData();
fdj.append("file", new Blob(["<h1>by jj</h1>"]), "index.html");
check("editor can publish while private", (await api(jj, `/artifacts/${id}/versions`, { method: "POST", body: fdj })).status === 201);
check("editor can't change sharing", (await api(jj, `/artifacts/${id}/sharing`, { method: "PUT", body: JSON.stringify({ mode: "public" }) })).status === 403);

// CSRF + bad input
check("cookie write from another origin refused",
  (await fetch(`${APP}/api/artifacts/${id}/sharing`, { method: "PUT", headers: { Cookie: nate, Origin: "https://evil.example" }, body: JSON.stringify({ mode: "public" }) })).status === 403);
const bad = new FormData();
bad.append("file", new Blob(["x"]), "../escape.html");
bad.append("title", "bad");
check("path traversal refused", (await api(nate, "/artifacts", { method: "POST", body: bad })).status === 400);
const noIndex = new FormData();
noIndex.append("file", new Blob(["x"]), "page.html");
noIndex.append("title", "x");
check("artifact without index.html refused", (await api(nate, "/artifacts", { method: "POST", body: noIndex })).status === 400);
check("login next can't leave the site", (await fetch(`${APP}/login/dev`, { method: "POST", body: new URLSearchParams({ email: "nate@dev.test", next: "//evil.example" }), redirect: "manual" })).headers.get("location") === "/");
check("unknown CLI flag exits 2", tack(tok.token, "list", "--bogus").code === 2);
check("bad token exits 4", tack("tck_nope", "list").code === 4);

// A tenant's agents: an admin mints their token; they see only what they publish
const tenantTok = await (await api(nate, "/tokens", { method: "POST", body: JSON.stringify({ label: "tenant", as: "agents@dev.test" }) })).json();
check("admin mints a token for another publisher", tenantTok.owner === "agents@dev.test" && tenantTok.token?.startsWith("tck_"));
check("non-admin can't mint for someone else", (await api(jj, "/tokens", { method: "POST", body: JSON.stringify({ as: "agents@dev.test" }) })).status === 403);
check("admin can't mint for a non-publisher", (await api(nate, "/tokens", { method: "POST", body: JSON.stringify({ as: "jj@dev.test" }) })).status === 400);
check("minter lists the tenant token", ((await (await api(nate, "/tokens")).json()).tokens as any[]).some((t) => t.owner === "agents@dev.test"));
const tpub = tack(tenantTok.token, "publish", join(dir, "index.html"), "--title", "Tenant page");
check("tenant publishes as itself", tpub.code === 0 && tpub.json.owner === "agents@dev.test");
check("tenant can't open Nate's page", tack(tenantTok.token, "get", id).code === 5);
check("tenant's list holds only its own", tack(tenantTok.token, "list").json.every((a: any) => a.owner === "agents@dev.test"));
check("admin can share the tenant's page", (await api(nate, `/artifacts/${tpub.json.id}/sharing`, { method: "PUT", body: JSON.stringify({ mode: "users", users: "client@acme.example" }) })).status === 200);
tack(tok.token, "share", id, "--mode", "org");
check("an org page stays closed to the tenant", tack(tenantTok.token, "get", id).code === 5);
check("…and open to JJ", (await api(jj, `/artifacts/${id}`)).status === 200);

// A Whiteboard board: the snapshot, the page that reads it, and the viewer (from npm on first run)
const sample = join(import.meta.dir, "fixtures/sample.whiteboard");
const board = tack(tok.token, "board", sample);
check("tack board publishes a snapshot", board.code === 0 && board.json?.title === "Sample board", JSON.stringify(board.json));
if (board.code === 0) {
  const bf = await (await api(nate, `/artifacts/${board.json.id}/frame`)).json();
  check("board page maps the viewer to its own files", (await (await content(bf.src)).text()).includes('"@dev.fast/canvas": "./canvas/index.js"'));
  check("board snapshot is served as published", (await (await content(bf.src + "board.whiteboard")).text()) === readFileSync(sample, "utf8"));
  for (const f of ["main.js", "canvas/index.js", "canvas/assets/canvas.css", "vendor/react.js", "vendor/react-dom-client.js"])
    check(`board serves ${f}`, (await content(bf.src + f)).status === 200);
  check("board version is labelled with the board's version", tack(tok.token, "versions", board.json.id).json[0].label === "board v1");
  tack(tok.token, "delete", board.json.id, "--yes");
}
check("a file that is not a snapshot exits 2", tack(tok.token, "board", join(dir, "index.html")).code === 2);

// Whiteboard share hub: Tack answers the share-service protocol that `whiteboard login --origin`
// and `whiteboard share` speak. These are the requests that client sends, in its order.
const wb = (path: string, init: RequestInit = {}) => fetch(`${APP}${path}`, init);
const wbJson = (path: string, body: unknown, token?: string) =>
  wb(path, { method: "POST", headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) }, body: JSON.stringify(body) });
const errCode = async (r: Response) => ((await r.json()) as any)?.error?.code;
async function deviceLogin(cookie: string): Promise<string> {
  const d: any = await (await wbJson("/api/auth/device/code", { client_id: "review-cli", scope: "identity" })).json();
  const poll = () => wbJson("/api/auth/device/token", { grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: d.device_code, client_id: "review-cli" });
  const pending = await poll();
  check("device login waits for approval", pending.status === 400 && ((await pending.json()) as any).error === "authorization_pending");
  check("the approval page needs a sign-in", (await wb(`/device?user_code=${d.user_code}`, { redirect: "manual" })).status === 302);
  check("the approval page shows the code", (await (await wb(`/device?user_code=${d.user_code}`, { headers: { Cookie: cookie } })).text()).includes(d.user_code));
  const approve = (origin: string) =>
    wb("/device", { method: "POST", headers: { Cookie: cookie, Origin: origin }, body: new URLSearchParams({ user_code: d.user_code }) });
  check("another site can't approve", (await approve("http://evil.example")).status === 403);
  check("the signed-in person approves", (await (await approve(APP)).text()).includes("Whiteboard is signed in"));
  check("a code is approved once", (await (await approve(APP)).text()).includes("Code not accepted"));
  const got: any = await (await poll()).json();
  check("the next poll returns a token", typeof got.access_token === "string" && got.access_token.startsWith("tck_"));
  check("the device code is spent", ((await (await poll()).json()) as any).error === "expired_token");
  return got.access_token;
}
const wbTok = await deviceLogin(nate);
const session: any = await (await wb("/api/auth/get-session", { headers: { Authorization: `Bearer ${wbTok}` } })).json();
check("the token names its person", session.user?.name === "nate@dev.test" && session.user?.id === "nate@dev.test");
check("no JWT exchange: the client sends its token as it is", (await wb("/api/auth/token", { headers: { Authorization: `Bearer ${wbTok}` } })).status === 404);
// The token Whiteboard gets is for the hub only, and only a browser session can approve a code.
const hubOnly = { headers: { Authorization: `Bearer ${wbTok}` } };
check("a Whiteboard login token can't read or publish artifacts", (await wb("/api/artifacts", hubOnly)).status === 401 && ((await (await wb("/api/me", hubOnly)).json()) as any).email === null && tack(wbTok, "publish", join(dir, "index.html"), "--title", "Scoped").code === 4);
const scopedPage = await wb(`/a/${id}`, { ...hubOnly, redirect: "manual" });
check("…or open an artifact's page, which would hand it the files", scopedPage.status === 302 && !(await scopedPage.text()).includes("/t/") && (await wb(`/api/artifacts/${id}/frame`, hubOnly)).status === 401);
check("a full token still opens that page", (await (await wb(`/a/${id}`, { headers: { Authorization: `Bearer ${tok.token}` } })).text()).includes("/t/"));
check("…or name the board viewer", (await wb("/api/whiteboard/viewer", { method: "PUT", headers: { ...hubOnly.headers, "Content-Type": "application/json" }, body: JSON.stringify({ artifact: id }) })).status === 403);
const selfMint: any = await (await wbJson("/api/auth/device/code", { client_id: "review-cli" })).json();
const byToken = await wb("/device", { method: "POST", redirect: "manual", headers: { Authorization: `Bearer ${tok.token}`, Origin: APP }, body: new URLSearchParams({ user_code: selfMint.user_code }) });
const afterToken: any = await (await wbJson("/api/auth/device/token", { grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: selfMint.device_code })).json();
check("a token can't approve a device code for itself", byToken.status === 302 && afterToken.error === "authorization_pending", `${byToken.status} ${JSON.stringify(afterToken)}`);
const anonShares = await wb("/api/v2/shares");
check("the share API needs a login", anonShares.status === 401 && (await errCode(anonShares)) === "login_required");

const bundle = JSON.parse(readFileSync(sample, "utf8"));
const requestId = crypto.randomUUID();
const first: any = await (await wbJson("/api/v2/shares", { requestId, bundle }, wbTok)).json();
const cap: string = String(first.url ?? "").split("/s/")[1] ?? "";
check("sharing returns a share id and a capability link", /^[0-9a-f-]{36}$/.test(first.shareId) && /^[A-Za-z0-9_-]{43}$/.test(cap) && Object.keys(first).length === 2, JSON.stringify(first));
check("a retried upload answers the same", JSON.stringify(await (await wbJson("/api/v2/shares", { requestId, bundle }, wbTok)).json()) === JSON.stringify(first));
check("the same version again changes nothing", ((await (await wbJson("/api/v2/shares", { requestId: crypto.randomUUID(), bundle }, wbTok)).json()) as any).url === first.url);
const second: any = await (await wbJson("/api/v2/shares", { requestId: crypto.randomUUID(), bundle: { ...bundle, version: bundle.version + 1, title: "Sample board, edited" } }, wbTok)).json();
check("a newer version keeps the link", second.url === first.url && second.shareId === first.shareId);
const auth = { headers: { Authorization: `Bearer ${wbTok}` } };
const revs: any = await (await wb(`/api/v2/shares/${first.shareId}/revisions`, auth)).json();
check("…and adds a revision, newest first", revs.items?.length === 2 && revs.items[0].version === bundle.version + 1 && revs.latest === revs.items[0].id, JSON.stringify(revs));
check("the owner recovers the link", ((await (await wb(`/api/v2/shares/${first.shareId}/link`, auth)).json()) as any).url === first.url);
const listed: any = await (await wb("/api/v2/shares", auth)).json();
check("the owner lists their shares", listed.items?.some((i: any) => i.shareId === first.shareId && i.latestVersion === bundle.version + 1));

const meta = await wb(`/api/v2/shared/${cap}`);
const metaJson: any = await meta.json();
check("anyone with the link reads who shared it", meta.status === 200 && metaJson.sender?.login === "nate@dev.test" && Object.keys(metaJson.sender).length === 1 && metaJson.latest === revs.latest);
check("reads are uncached and unindexed", meta.headers.get("cache-control") === "private, no-store" && meta.headers.get("x-robots-tag") === "noindex");
const latestBundle: any = await (await wb(`/api/v2/shared/${cap}/bundle`)).json();
check("…and the newest snapshot", latestBundle.title === "Sample board, edited" && latestBundle.format === "review-share/2");
const oldBundle = await (await wb(`/api/v2/shared/${cap}/bundle?rev=${revs.items[1].id}`)).text();
check("an older revision is still readable by id", oldBundle === JSON.stringify(bundle));
const unknown = await wb(`/api/v2/shared/${"A".repeat(43)}`);
check("an unknown link is 404 not_found", unknown.status === 404 && (await errCode(unknown)) === "not_found");
check("an unknown revision is 404", (await wb(`/api/v2/shared/${cap}?rev=${crypto.randomUUID()}`)).status === 404);
check("something that is not a snapshot is refused", (await wbJson("/api/v2/shares", { requestId: crypto.randomUUID(), bundle: { ...bundle, format: "review-share/1" } }, wbTok)).status === 400);
const outsider = await deviceLogin(client);
check("anyone signed in can log Whiteboard in, but only publishers share", (await wbJson("/api/v2/shares", { requestId: crypto.randomUUID(), bundle }, outsider)).status === 403);
check("…and they can't touch someone else's share", (await wb(`/api/v2/shares/${first.shareId}`, { method: "DELETE", headers: { Authorization: `Bearer ${outsider}` } })).status === 404);

// The page a person opens: nothing to frame until an admin registers the viewer, then the board.
const sharePage = () => wb(`/s/${cap}`);
const bare = await sharePage();
const bareHtml = await bare.text();
check("the share page opens without a sign-in", bare.status === 200 && bareHtml.includes("Shared by nate@dev.test") && bare.headers.get("x-robots-tag") === "noindex");
check("…with a link that opens it in Whiteboard", bareHtml.includes(`dev-fast-review://share/${cap}?origin=${encodeURIComponent(APP)}&amp;rev=${revs.latest}`));
check("a non-admin can't register the viewer", tack(tenantTok.token, "board-viewer").code === 4);
const viewer = tack(tok.token, "board-viewer");
check("an admin registers the board viewer", viewer.code === 0 && viewer.json?.registered === true, JSON.stringify(viewer.json));
const frameSrc = (await (await sharePage()).text()).match(/<iframe src="([^"]+)"/)?.[1] ?? "";
check("the share page frames the board from its own origin", frameSrc.includes(`.localhost:${port}/t/`) && !frameSrc.includes(viewer.json?.id));
check("the frame serves the viewer", (await content(frameSrc + "main.js")).status === 200 && (await (await content(frameSrc)).text()).includes("@dev.fast/canvas"));
check("…and this share's snapshot", ((await (await content(frameSrc + "board.whiteboard")).json()) as any).title === "Sample board, edited");

// Generated by /ship coverage audit.
// Value: protects=a signed-in browser on another site can't share or revoke through the hub;
// fails_when=the Origin check on cookie-authenticated hub writes is dropped or skipped for /api/v2;
// why_new=the existing CSRF check covers /api/artifacts only, and every hub write above uses a bearer token;
// seam=none; no_claim=bearer requests (they carry no ambient credential and are not Origin-checked)
const evil = { Cookie: nate, Origin: "https://evil.example", "Content-Type": "application/json" };
check("a session reads the hub", (await wb("/api/v2/shares", { headers: { Cookie: nate } })).status === 200);
const csrfShare = await wb("/api/v2/shares", { method: "POST", headers: evil, body: JSON.stringify({ requestId: crypto.randomUUID(), bundle: { ...bundle, reviewId: "csrf-board" } }) });
check("another site can't share with the session", csrfShare.status === 403 && (await errCode(csrfShare)) === "forbidden");
check("another site can't revoke with the session", (await wb(`/api/v2/shares/${first.shareId}`, { method: "DELETE", headers: evil })).status === 403);
check("…and neither request changed anything",
  (await wb(`/api/v2/shared/${cap}`)).status === 200 && !((await (await wb("/api/v2/shares", auth)).json()) as any).items.some((i: any) => i.reviewId === "csrf-board"));

// Generated by /ship coverage audit.
// Value: protects=only an admin names the artifact whose files every share link serves, and it must exist;
// fails_when=the server-side isAdmin gate or the artifact look-up on PUT /api/whiteboard/viewer is removed;
// why_new=`tack board-viewer` refuses a non-admin from /api/me before it ever sends the PUT;
// seam=none; no_claim=who counts as an admin (test/access.test.ts and the dev config decide that)
const putViewer = (token: string | null, artifact: unknown) =>
  wb("/api/whiteboard/viewer", { method: "PUT", headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) }, body: JSON.stringify({ artifact }) });
check("the server refuses a non-admin's viewer", (await putViewer(tenantTok.token, tpub.json.id)).status === 403);
check("…and an anonymous one", (await putViewer(null, id)).status === 401);
check("…and an artifact that does not exist", (await putViewer(tok.token, "z".repeat(20))).status === 400);
check("…and an admin naming someone else's artifact", (await putViewer(tok.token, tpub.json.id)).status === 403);
check("the registered viewer is unchanged", ((await (await wb("/api/whiteboard/viewer", { headers: { Authorization: `Bearer ${tok.token}` } })).json()) as any).artifact === viewer.json?.id);

// Generated by /ship coverage audit.
// Value: protects=a board quoting uncommitted changes is view only (no Open in Whiteboard link), and ?app=preview targets the preview app;
// fails_when=the frozen flag is not stored or not read by /s, or the preview scheme is dropped;
// why_new=the sample board is not frozen, so only the link-present branch ran;
// seam=none; no_claim=that Whiteboard Desktop accepts the link (no desktop app in this run)
const frozen: any = await (await wbJson("/api/v2/shares", { requestId: crypto.randomUUID(), bundle: { ...bundle, reviewId: "frozen-board", title: "Frozen board", frozen: true } }, wbTok)).json();
const frozenHtml = await (await wb(String(frozen.url).replace(/^https?:\/\/[^/]+/, ""))).text();
check("a frozen board's page has no Open in Whiteboard link", frozenHtml.includes("Frozen board") && !frozenHtml.includes("dev-fast-review"), JSON.stringify(frozen));
check("?app=preview opens the preview app", (await (await wb(`/s/${cap}?app=preview`)).text()).includes(`dev-fast-review-preview://share/${cap}?`));
check("the frozen share is revoked", (await wb(`/api/v2/shares/${frozen.shareId}`, { method: "DELETE", ...auth })).status === 200);

// Generated by /ship coverage audit.
// Value: protects=the device endpoints refuse a malformed request, throttle a fast poller, and /device rejects a code nobody was shown;
// fails_when=a wrong grant type or missing client_id is accepted, slow_down is never sent, or an unknown code reaches the Approve form;
// why_new=deviceLogin above sends only well-formed requests, polls once before approval, and opens /device with a live code;
// seam=none; no_claim=the ten-minute expiry (no clock control against a running server)
check("an oversized device request is refused unread", ((await (await wbJson("/api/auth/device/code", { client_id: "x".repeat(64 * 1024) })).json()) as any).error === "invalid_request");
check("a device request without a client id is refused", ((await (await wbJson("/api/auth/device/code", { scope: "identity" })).json()) as any).error === "invalid_request");
const dc: any = await (await wbJson("/api/auth/device/code", { client_id: "review-cli" })).json();
check("a wrong grant type is refused", ((await (await wbJson("/api/auth/device/token", { grant_type: "password", device_code: dc.device_code })).json()) as any).error === "invalid_request");
// Three polls back to back: wherever a second boundary falls, two of them share a second.
const polls: string[] = [];
for (let i = 0; i < 3; i++) polls.push(((await (await wbJson("/api/auth/device/token", { grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: dc.device_code })).json()) as any).error);
check("polling faster than the interval is told to slow down", polls[0] === "authorization_pending" && polls.includes("slow_down"), polls.join(","));
const strangerCode = await (await wb("/device?user_code=ZZZZ-ZZZZ", { headers: { Cookie: nate } })).text();
check("a code nobody was shown gets no Approve form", strangerCode.includes("Code not accepted") && !strangerCode.includes('action="/device"'));
check("without a code the page asks for one", (await (await wb("/device", { headers: { Cookie: nate } })).text()).includes('name="user_code" type="text"'));

// Generated by /ship coverage audit.
// Value: protects=an upload is refused when it is not JSON, has no UUID request id or is over 16 MiB, and an older version never replaces a newer one;
// fails_when=the size limit, the request-id check or the version > latest comparison is removed or inverted;
// why_new=the only refusal checked above is a wrong format, and the only repeat upload is the same version;
// seam=none; no_claim=a bundle between 16 MiB and the envelope allowance (only the outer limit is sent)
const rawShare = (body: string) => wb("/api/v2/shares", { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${wbTok}` }, body });
const notJson = await rawShare("{not json");
check("an upload that is not JSON is refused", notJson.status === 400 && (await errCode(notJson)) === "invalid_request");
check("an upload without a UUID request id is refused", (await wbJson("/api/v2/shares", { requestId: "retry-1", bundle }, wbTok)).status === 400);
const huge = await rawShare("x".repeat(16 * 1024 * 1024 + 4097));
check("an upload over 16 MiB is refused as too_large", huge.status === 413 && (await errCode(huge)) === "too_large");
const older: any = await (await wbJson("/api/v2/shares", { requestId: crypto.randomUUID(), bundle: { ...bundle, version: 0, title: "Older" } }, wbTok)).json();
const revsAfter: any = await (await wb(`/api/v2/shares/${first.shareId}/revisions`, auth)).json();
check("an older version keeps the link and adds no revision", older.url === first.url && revsAfter.items?.length === 2 && revsAfter.latest === revs.latest, JSON.stringify(revsAfter));

// The viewer is pinned at the version registered: a later publish to that artifact changes no share page.
const fullAuth = { headers: { Authorization: `Bearer ${tok.token}` } };
const pinned: any = await (await wb("/api/whiteboard/viewer", fullAuth)).json();
check("the viewer is registered at one version", pinned.version === viewer.json?.live_version && pinned.owner === "nate@dev.test", JSON.stringify(pinned));
check("a new version of the viewer artifact publishes", tack(tok.token, "publish", join(dir, "index.html"), "--id", viewer.json?.id).code === 0);
const frameAfter = (await (await sharePage()).text()).match(/<iframe src="([^"]+)"/)?.[1] ?? "";
check("…and share pages still frame the registered version", (await (await content(frameAfter)).text()).includes("@dev.fast/canvas"));

// Admins can find and revoke anyone's share, since a link stays readable until someone does.
const theirs: any = await (await wbJson("/api/v2/shares", { requestId: crypto.randomUUID(), bundle: { ...bundle, reviewId: "tenant-board", title: "Tenant board" } }, tenantTok.token)).json();
const theirCap = String(theirs.url ?? "").split("/s/")[1] ?? "";
const everyone = await wb("/api/v2/shares?owner=*", fullAuth);
const everyoneItems: any[] = ((await everyone.json()) as any).items ?? [];
check("an admin lists everyone's shares, with owners", everyoneItems.some((i: any) => i.shareId === theirs.shareId && i.owner === "agents@dev.test"));
check("…but gets no link to read someone else's board", everyoneItems.find((i: any) => i.shareId === theirs.shareId)?.url === null && String(everyoneItems.find((i: any) => i.shareId === first.shareId)?.url).includes("/s/"));
check("a publisher can't list someone else's", (await wb("/api/v2/shares?owner=*", { headers: { Authorization: `Bearer ${tenantTok.token}` } })).status === 403 && (await wb("/api/v2/shares?owner=nate@dev.test", { headers: { Authorization: `Bearer ${tenantTok.token}` } })).status === 403);
check("an admin's Whiteboard login token is not an admin", (await wb("/api/v2/shares?owner=*", auth)).status === 403 && (await wb(`/api/v2/shares/${theirs.shareId}`, { method: "DELETE", ...auth })).status === 404 && (await wb(`/api/v2/shared/${theirCap}`)).status === 200);
check("an admin revokes someone else's share", (await wb(`/api/v2/shares/${theirs.shareId}`, { method: "DELETE", ...fullAuth })).status === 200 && (await wb(`/api/v2/shared/${theirCap}`)).status === 404);

const revoked: any = await (await wb(`/api/v2/shares/${first.shareId}`, { method: "DELETE", ...auth })).json();
check("the owner revokes", revoked.revoked === true && revoked.shareId === first.shareId);
check("a revoked link is 404 everywhere", (await wb(`/api/v2/shared/${cap}`)).status === 404 && (await wb(`/api/v2/shared/${cap}/bundle`)).status === 404 && (await sharePage()).status === 404);
check("…including a frame handed out before the revoke", (await content(frameSrc + "board.whiteboard")).status === 404);
if (viewer.code === 0) {
  tack(tok.token, "delete", viewer.json.id, "--yes");
  const gone: any = await (await wb("/api/whiteboard/viewer", fullAuth)).json();
  check("a deleted viewer reads back as none registered", gone.artifact === null && gone.version === null);
}

// Delete
check("delete needs --yes", tack(tok.token, "delete", id).code === 2);
check("owner deletes", tack(tok.token, "delete", id, "--yes").code === 0);
check("deleted artifact is gone", (await api(nate, `/artifacts/${id}`)).status === 404);

console.log(failed ? `\n${failed} failed` : "\nall checks passed");
process.exit(failed ? 1 : 0);
