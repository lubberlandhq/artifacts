// What the app-side pages show to whom, and the status of the page for an unknown address.
import { describe, expect, test } from "bun:test";
import type { Env } from "../src/env";
import { onContentDomain } from "../src/content";
import worker from "../src/index";
import { galleryPage, messagePage } from "../src/pages";

const env = {
  APP_ORIGIN: "https://share.example.com",
  LOGIN_ORIGIN: "https://share-login.example.com",
  CONTENT_DOMAIN: "content.example.net",
  CONTENT_SCHEME: "https",
  ORG_NAME: "Example Co",
  ORG_EMAILS: "nate@example.com",
  ORG_DOMAINS: "",
  PUBLISHERS: "nate@example.com",
  ADMINS: "nate@example.com",
} as Env;

describe("gallery", () => {
  test("a publisher gets the publish zone and the token form", async () => {
    const html = await galleryPage(env, "nate@example.com").text();
    expect(html).toContain('id="drop"');
    expect(html).toContain('id="tnew"');
    expect(html).toContain("const PUB=true;");
  });

  test("someone who can't publish gets neither, and the token section starts hidden", async () => {
    const html = await galleryPage(env, "client@acme.example").text();
    expect(html).not.toContain('id="drop"');
    expect(html).not.toContain('id="tnew"');
    expect(html).toContain('<section id="tsec" hidden>');
    expect(html).toContain("const PUB=false;");
  });

  test("only an admin gets everyone else's pages", async () => {
    const admin = await galleryPage(env, "nate@example.com").text();
    expect(admin).toContain("<h2 class=\"sec\">Everyone else's pages</h2>");
    expect(admin).toContain("api('/artifacts?all=1')");
    // If the first list fails, the second says so instead of loading forever.
    expect(admin).toMatch(/load\(\)\.catch\(x=>\{[^}]*\$\('#all'\)/);
    const other = await galleryPage(env, "client@acme.example").text();
    expect(other).not.toContain('id="all"');
    expect(other).not.toContain("?all=1");
  });

  test("the email is escaped in the page and in the script", async () => {
    const html = await galleryPage(env, 'a"<script>@x.test').text();
    expect(html).not.toContain('a"<script>@x.test');
  });
});

describe("standalone pages", () => {
  test("a message page carries the brand bar, which links home", async () => {
    const html = await messagePage(env, "Not found", "Nothing lives at this address.").text();
    expect(html).toContain('<a class="brand" href="/">');
  });

  test("an unknown address on the app host answers 404", async () => {
    const r = await worker.fetch(new Request("https://share.example.com/nope"), env);
    expect(r.status).toBe(404);
    expect(await r.text()).toContain("Not found");
  });
});

describe("the content domain", () => {
  const hosts = ["x.content.example.net", "content.example.net", "a.b.content.example.net", "SHORT.Content.Example.Net", "x.content.example.net.", "x.content.example.net:8443", `${"a".repeat(20)}.content.example.net:8443`];
  for (const host of hosts) {
    for (const [method, path] of [["GET", "/"], ["POST", "/api/auth/device/token"], ["GET", "/login"], ["DELETE", "/api/artifacts/x"]]) {
      test(`${method} ${host}${path} answers 404 with the content headers`, async () => {
        const r = await worker.fetch(new Request(`https://${host}${path}`, { method }), env);
        expect(r.status).toBe(404);
        expect(r.headers.get("x-content-type-options")).toBe("nosniff");
        expect(r.headers.get("referrer-policy")).toBe("no-referrer");
        expect(await r.text()).toBe("Not found");
      });
    }
  }

  test("a content id with no grant still goes to the content handler", async () => {
    const r = await worker.fetch(new Request(`https://${"a".repeat(20)}.content.example.net/`), env);
    expect(r.status).toBe(404);
    const p = await worker.fetch(new Request(`https://${"a".repeat(20)}.content.example.net/`, { method: "POST" }), env);
    expect(p.status).toBe(405);
  });

  test("a lookalike name is not on the content domain", () => {
    expect(onContentDomain(env, "evilcontent.example.net")).toBe(false);
    expect(onContentDomain(env, "content.example.net.evil.test")).toBe(false);
    expect(onContentDomain({ ...env, CONTENT_DOMAIN: "Content.Example.Net." } as Env, "x.content.example.net")).toBe(true);
  });

  test("a login host on the content domain (dev) still reaches the login handler", async () => {
    const dev = { ...env, APP_ORIGIN: "http://localhost:8787", LOGIN_ORIGIN: "http://login.localhost:8787", CONTENT_DOMAIN: "localhost:8787" } as Env;
    const r = await worker.fetch(new Request("http://login.localhost:8787/nope"), dev);
    expect(await r.text()).not.toBe("Not found");
  });

  test("an app host that is the content domain (dev) still serves the app", async () => {
    const dev = { ...env, APP_ORIGIN: "http://localhost:8787", LOGIN_ORIGIN: "", CONTENT_DOMAIN: "localhost:8787" } as Env;
    const r = await worker.fetch(new Request("http://localhost:8787/nope"), dev);
    expect(r.status).toBe(404);
    expect(await r.text()).toContain("Back to Tack");
    const c = await worker.fetch(new Request("http://x.localhost:8787/"), dev);
    expect(await c.text()).toBe("Not found");
  });
});
