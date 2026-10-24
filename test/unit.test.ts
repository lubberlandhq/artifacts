import { describe, expect, test } from "bun:test";
import { canAdmin, canPublish, canRead, canWrite, isAdmin, orgPolicy, parseEmails, visibleVersion } from "../src/authz";
import { randomId, seal, unseal } from "../src/crypto";
import { contentCsp } from "../src/csp";
import type { Artifact } from "../src/env";
import { validPath } from "../src/store";

const policy = orgPolicy({ ORG_EMAILS: "jj@x.com", ORG_DOMAINS: "example.com", PUBLISHERS: "" });
const art = (over: Partial<Artifact> = {}): Artifact => ({
  id: "a".repeat(20), owner: "nate@example.com", title: "t", description: "", live_version: 3,
  read_mode: "owner", read_users: [], write_users: [], pinned_version: null, created_at: "", updated_at: "", ...over,
});

describe("authz", () => {
  test("private: owner and editors only", () => {
    const a = art({ write_users: ["ed@out.com"] });
    expect(canRead(policy, a, "nate@example.com")).toBe(true);
    expect(canRead(policy, a, "ed@out.com")).toBe(true);
    expect(canRead(policy, a, "bob@example.com")).toBe(false);
    expect(canRead(policy, a, null)).toBe(false);
  });
  test("users mode admits named emails case-insensitively, nobody else", () => {
    const a = art({ read_mode: "users", read_users: ["client@acme.com"] });
    expect(canRead(policy, a, "Client@Acme.com")).toBe(true);
    expect(canRead(policy, a, "other@acme.com")).toBe(false);
    expect(canWrite(policy, a, "client@acme.com")).toBe(false);
  });
  test("org mode: listed emails and domains", () => {
    const a = art({ read_mode: "org" });
    expect(canRead(policy, a, "jj@x.com")).toBe(true);
    expect(canRead(policy, a, "anyone@example.com")).toBe(true);
    expect(canRead(policy, a, "anyone@example.com.evil.com")).toBe(false);
    expect(canRead(policy, a, null)).toBe(false);
  });
  test("public mode: anonymous allowed", () => {
    expect(canRead(policy, art({ read_mode: "public" }), null)).toBe(true);
  });
  test("only the owner administers", () => {
    const a = art({ write_users: ["ed@out.com"] });
    expect(canAdmin(policy, a, "ed@out.com")).toBe(false);
    expect(canAdmin(policy, a, "NATE@example.com")).toBe(true);
  });
  test("viewers see the pin; editors pick", () => {
    const a = art({ read_mode: "public", pinned_version: 2 });
    expect(visibleVersion(policy, a, null, 3)).toBe(2);
    expect(visibleVersion(policy, art({ read_mode: "public" }), null, 1)).toBe(3);
    expect(visibleVersion(policy, a, "nate@example.com", 1)).toBe(1);
    expect(visibleVersion(policy, a, "nate@example.com", 99)).toBe(3);
  });
  test("admins administer and edit any artifact; a tenant identity only its own", () => {
    const p = orgPolicy({ ORG_EMAILS: "", ORG_DOMAINS: "", PUBLISHERS: "", ADMINS: "boss@x.com" });
    const tenantPage = art({ owner: "agents@x.com" });
    expect(canAdmin(p, tenantPage, "boss@x.com")).toBe(true);
    expect(canWrite(p, tenantPage, "boss@x.com")).toBe(true);
    expect(canRead(p, tenantPage, "boss@x.com")).toBe(true);
    expect(canAdmin(p, art(), "agents@x.com")).toBe(false);
    expect(canRead(p, art(), "agents@x.com")).toBe(false);
    expect(isAdmin(p, "BOSS@x.com")).toBe(true);
  });
  test("publishers default to org members", () => {
    expect(canPublish(policy, "x@example.com")).toBe(true);
    expect(canPublish(policy, "x@gmail.com")).toBe(false);
    expect(canPublish(orgPolicy({ ORG_EMAILS: "", ORG_DOMAINS: "example.com", PUBLISHERS: "n@a.com" }), "x@example.com")).toBe(false);
  });
  test("emails parse and validate", () => {
    expect(parseEmails("A@b.co, c@d.io;a@b.co")).toEqual(["a@b.co", "c@d.io"]);
    expect(parseEmails("not-an-email")).toBeNull();
    expect(parseEmails("")).toEqual([]);
  });
});

describe("crypto", () => {
  test("ids are 20 lowercase base36 chars", () => {
    for (let i = 0; i < 50; i++) expect(randomId()).toMatch(/^[a-z0-9]{20}$/);
  });
  test("sealed tokens are purpose-bound, tamper-evident and expire", async () => {
    const t = await seal("s", "content", { a: "x" }, 60);
    expect((await unseal<{ a: string }>("s", "content", t))?.a).toBe("x");
    expect(await unseal("s", "session", t)).toBeNull();
    expect(await unseal("other", "content", t)).toBeNull();
    expect(await unseal("s", "content", t.slice(0, -2) + "AA")).toBeNull();
    expect(await unseal("s", "content", await seal("s", "content", {}, -1))).toBeNull();
  });
});

describe("paths and policy", () => {
  test("published paths stay inside the artifact", () => {
    for (const ok of ["index.html", "assets/app.js", "data/2026 q3.csv"]) expect(validPath(ok)).toBe(true);
    for (const bad of ["/abs.html", "../x", "a/../b", "a/./b", "dir/", "", "a\\b"]) expect(validPath(bad)).toBe(false);
  });
  test("content CSP: framable only by the app, no outside fetches", () => {
    const c = contentCsp("https://share.example.com");
    expect(c).toContain("frame-ancestors https://share.example.com");
    expect(c).toContain("connect-src 'self'");
    expect(c).toContain("https://cdnjs.cloudflare.com");
  });
});
