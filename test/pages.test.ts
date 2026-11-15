// What the app-side pages show to whom, and the status of the page for an unknown address.
import { describe, expect, test } from "bun:test";
import type { Env } from "../src/env";
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
