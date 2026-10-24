// End-to-end against `bun run dev` (wrangler dev -c wrangler.dev.jsonc on :8787). Exercises what a person does:
// sign in, mint a CLI token, publish with lshare, view through the shell and the content origin,
// share each way, pin, comment, and check the refusals. Exit 1 on the first failed check.
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
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
const LSHARE_BIN = process.env.LSHARE_BIN ?? join(import.meta.dir, "../cli/lshare");
const lshare = (token: string, ...args: string[]) => {
  const r = spawnSync("bun", [LSHARE_BIN, ...args], {
    env: { ...process.env, LSHARE_URL: APP, LSHARE_TOKEN: token },
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
check("token minted", typeof tok.token === "string" && tok.token.startsWith("lsh_"));
check("non-publisher can't mint", (await api(client, "/tokens", { method: "POST", body: "{}" })).status === 403);

// Publish a two-file page with the CLI
const dir = mkdtempSync(join(tmpdir(), "lshare-"));
mkdirSync(join(dir, "assets"));
writeFileSync(join(dir, "index.html"), `<!doctype html><title>Smoke</title><link rel="stylesheet" href="assets/s.css"><h1>v1</h1>`);
writeFileSync(join(dir, "assets/s.css"), "h1{color:teal}");
const pub = lshare(tok.token, "publish", dir, "--title", "Smoke test", "--label", "first");
check("lshare publish exits 0", pub.code === 0, JSON.stringify(pub.json));
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
let s = lshare(tok.token, "share", id, "--mode", "people", "--users", "client@acme.example");
check("share with people", s.code === 0 && s.json.sharing.mode === "users");
check("named person can view", (await fetch(`${APP}/a/${id}`, { headers: { Cookie: client } })).status === 200);
check("viewer gets no sharing details", (await (await api(client, `/artifacts/${id}`)).json()).sharing === undefined);
check("viewer can't publish", (await api(client, `/artifacts/${id}/versions`, { method: "POST", body: new FormData() })).status === 403);
check("viewer can't change sharing", (await api(client, `/artifacts/${id}/sharing`, { method: "PUT", body: JSON.stringify({ mode: "public" }) })).status === 403);
check("JJ (org, not named) refused", (await api(jj, `/artifacts/${id}`)).status === 404);

// Org
lshare(tok.token, "share", id, "--mode", "org");
check("org mode admits JJ", (await api(jj, `/artifacts/${id}`)).status === 200);
check("org mode drops the client", (await api(client, `/artifacts/${id}`)).status === 404);

// Public + pin
s = lshare(tok.token, "share", id, "--mode", "public", "--pin", "current");
check("public, pinned to v1", s.json.sharing.mode === "public" && s.json.sharing.pinned_version === 1);
writeFileSync(join(dir, "index.html"), `<!doctype html><title>Smoke</title><link rel="stylesheet" href="assets/s.css"><h1>v2</h1>`);
const v2 = lshare(tok.token, "publish", join(dir, "index.html"), "--id", id, "--label", "second");
check("publish v2 keeps files left out", v2.code === 0 && v2.json.live_version === 2);
const anonFrame = await (await fetch(`${APP}/api/artifacts/${id}/frame?v=2`)).json();
check("anonymous sees pinned v1 even when asking for v2", anonFrame.version === 1);
check("anonymous v1 content", (await (await content(anonFrame.src)).text()).includes("<h1>v1</h1>"));
const ownerFrame = await (await api(nate, `/artifacts/${id}/frame`)).json();
check("owner sees live v2", ownerFrame.version === 2 && (await (await content(ownerFrame.src)).text()).includes("<h1>v2</h1>"));
check("v2 still has the css (copied forward)", (await content(ownerFrame.src + "assets/s.css")).status === 200);
lshare(tok.token, "share", id, "--pin", "live");
check("unpinned: anonymous follows live", (await (await fetch(`${APP}/api/artifacts/${id}/head`)).json()).version === 2);

// Concurrency guard
const stale = lshare(tok.token, "publish", join(dir, "index.html"), "--id", id, "--base", "1");
check("publish built on a stale version is refused", stale.code === 5 && /newer/.test(stale.json?.error ?? ""));

// Comments
check("anonymous can't comment", (await fetch(`${APP}/api/artifacts/${id}/comments`, { method: "POST", body: "{}" })).status === 401);
check("JJ comments", (await api(jj, `/artifacts/${id}/comments`, { method: "POST", body: JSON.stringify({ body: "Looks right" }) })).status === 201);
const cl = lshare(tok.token, "comments", id);
check("lshare reads comments", cl.json.length === 1 && cl.json[0].author === "jj@dev.test");

// Editors
lshare(tok.token, "share", id, "--mode", "private", "--editors", "jj@dev.test");
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
check("unknown CLI flag exits 2", lshare(tok.token, "list", "--bogus").code === 2);
check("bad token exits 4", lshare("lsh_nope", "list").code === 4);

// A tenant's agents: an admin mints their token; they see only what they publish
const tenantTok = await (await api(nate, "/tokens", { method: "POST", body: JSON.stringify({ label: "tenant", as: "agents@dev.test" }) })).json();
check("admin mints a token for another publisher", tenantTok.owner === "agents@dev.test" && tenantTok.token?.startsWith("lsh_"));
check("non-admin can't mint for someone else", (await api(jj, "/tokens", { method: "POST", body: JSON.stringify({ as: "agents@dev.test" }) })).status === 403);
check("admin can't mint for a non-publisher", (await api(nate, "/tokens", { method: "POST", body: JSON.stringify({ as: "jj@dev.test" }) })).status === 400);
check("minter lists the tenant token", ((await (await api(nate, "/tokens")).json()).tokens as any[]).some((t) => t.owner === "agents@dev.test"));
const tpub = lshare(tenantTok.token, "publish", join(dir, "index.html"), "--title", "Tenant page");
check("tenant publishes as itself", tpub.code === 0 && tpub.json.owner === "agents@dev.test");
check("tenant can't open Nate's page", lshare(tenantTok.token, "get", id).code === 5);
check("tenant's list holds only its own", lshare(tenantTok.token, "list").json.every((a: any) => a.owner === "agents@dev.test"));
check("admin can share the tenant's page", (await api(nate, `/artifacts/${tpub.json.id}/sharing`, { method: "PUT", body: JSON.stringify({ mode: "users", users: "client@acme.example" }) })).status === 200);
lshare(tok.token, "share", id, "--mode", "org");
check("an org page stays closed to the tenant", lshare(tenantTok.token, "get", id).code === 5);
check("…and open to JJ", (await api(jj, `/artifacts/${id}`)).status === 200);

// Delete
check("delete needs --yes", lshare(tok.token, "delete", id).code === 2);
check("owner deletes", lshare(tok.token, "delete", id, "--yes").code === 0);
check("deleted artifact is gone", (await api(nate, `/artifacts/${id}`)).status === 404);

console.log(failed ? `\n${failed} failed` : "\nall checks passed");
process.exit(failed ? 1 : 0);
