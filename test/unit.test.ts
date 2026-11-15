import { describe, expect, test } from "bun:test";
import { tokenLimits } from "../src/auth";
import { canAdmin, canPublish, canRead, canWrite, isAdmin, orgPolicy, parseEmails, visibleVersion } from "../src/authz";
import { decryptText, encryptText, randomId, seal, timeOrderedUuid, unseal } from "../src/crypto";
import { contentCsp } from "../src/csp";
import type { Artifact } from "../src/env";
import { validPath } from "../src/store";
import { bundleProblem, callerBucket, loginTtlSeconds, normalizeUserCode } from "../src/whiteboard";

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

describe("whiteboard hub", () => {
  // protects: a share link stays recoverable only with the server secret. fails_when: the sealed
  // capability opens under another purpose or secret, or is stored readable. no_claim: key rotation.
  test("a sealed capability opens only with its secret and purpose", async () => {
    const cap = "x9wBwK7gRrER63g3fEi181kMS4YH5CbOsP0HuqASvZ8";
    const sealed = await encryptText("s", "wb-capability", cap);
    expect(sealed).not.toContain(cap);
    expect(await decryptText("s", "wb-capability", sealed)).toBe(cap);
    expect(await decryptText("other", "wb-capability", sealed)).toBeNull();
    expect(await decryptText("s", "session", sealed)).toBeNull();
    expect(await decryptText("s", "wb-capability", "not-a-sealed-value")).toBeNull();
    expect(await encryptText("s", "wb-capability", cap)).not.toBe(sealed);
  });
  // protects: a person can type the code as Whiteboard prints it or loosely. fails_when: a
  // mistyped length is accepted. no_claim: whether the code exists.
  test("user codes are read however they are typed", () => {
    expect(normalizeUserCode("4hq4-g5u6")).toBe("4HQ4-G5U6");
    expect(normalizeUserCode(" 4HQ4 G5U6 ")).toBe("4HQ4-G5U6");
    expect(normalizeUserCode("4HQ4G5U")).toBeNull();
    expect(normalizeUserCode(null)).toBeNull();
  });
  // protects: a Whiteboard login lasts the configured number of days, 90 by default. fails_when:
  // a bad setting gives a token that expires at once or never. no_claim: that an expired token is
  // refused (checked by hand against the dev server; the smoke lane has no clock).
  test("the login lifetime is WHITEBOARD_LOGIN_DAYS, else 90 days", () => {
    const day = 24 * 3600;
    expect(loginTtlSeconds({})).toBe(90 * day);
    expect(loginTtlSeconds({ WHITEBOARD_LOGIN_DAYS: "30" })).toBe(30 * day);
    expect(loginTtlSeconds({ WHITEBOARD_LOGIN_DAYS: " 0.5 " })).toBe(day / 2);
    expect(loginTtlSeconds({ WHITEBOARD_LOGIN_DAYS: "3650" })).toBe(3650 * day);
    // Too small to be a second, too large for a date, or not a number: the default, never 0 or forever.
    for (const bad of ["", "0", "-7", "soon", "Infinity", "0.000001", "3651", "9999999", "1e300"]) expect(loginTtlSeconds({ WHITEBOARD_LOGIN_DAYS: bad })).toBe(90 * day);
  });
  // protects: only review-share/2 snapshots are stored. fails_when: another format, a missing
  // required part or a bad version passes. no_claim: the document inside `snapshot` is valid;
  // the reader checks that.
  test("only a review-share/2 snapshot is accepted", () => {
    const ok = { format: "review-share/2", reviewId: "r", version: 0, title: "", snapshot: {}, images: {}, traces: {}, maps: {}, commits: [], selections: {}, sources: [] };
    expect(bundleProblem(ok)).toBeNull();
    expect(bundleProblem({ ...ok, extra: 1, frozen: true })).toBeNull();
    expect(bundleProblem({ ...ok, format: "review-share/1" })).not.toBeNull();
    expect(bundleProblem({ ...ok, reviewId: "" })).not.toBeNull();
    expect(bundleProblem({ ...ok, version: -1 })).not.toBeNull();
    expect(bundleProblem({ ...ok, version: 1.5 })).not.toBeNull();
    expect(bundleProblem({ ...ok, version: 1e300 })).not.toBeNull();
    expect(bundleProblem({ ...ok, snapshot: [] })).not.toBeNull();
    expect(bundleProblem({ ...ok, sources: {} })).not.toBeNull();
    expect(bundleProblem(null)).not.toBeNull();
  });
});

// Value: protects=share ids are UUIDs Whiteboard's client accepts (version 7, RFC variant) and sort by creation time;
// fails_when=the version or variant bits are wrong (the client refuses the id), or a later id sorts before an earlier one;
// seam=none; no_claim=order within one millisecond (random)
describe("time-ordered share ids", () => {
  test("version 7, and later sorts after earlier", () => {
    const ids = [1, 2, 1_700_000_000_000, 1_800_000_000_000].map((t) => timeOrderedUuid(t));
    for (const id of ids) expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect([...ids].sort()).toEqual(ids);
    expect(timeOrderedUuid(0x0123456789ab).startsWith("01234567-89ab-7")).toBe(true);
  });
});

// Value: protects=a token limit that is given always binds: a zero, negative or non-numeric lifetime and an empty scope are refused, never read as "no limit";
// fails_when=a falsy lifetime mints a token that never expires, or an empty scope a token for the whole API;
// seam=none; no_claim=the database row (createApiToken writes what this returns)
describe("token limits", () => {
  test("a given limit binds or is refused", () => {
    expect(tokenLimits({})).toEqual({ scope: null, ttlSeconds: null });
    expect(tokenLimits({ scope: "whiteboard", ttlSeconds: 60 })).toEqual({ scope: "whiteboard", ttlSeconds: 60 });
    for (const bad of [0, -1, 0.5, NaN, Infinity]) expect(() => tokenLimits({ ttlSeconds: bad })).toThrow();
    for (const bad of ["", "  "]) expect(() => tokenLimits({ scope: bad })).toThrow();
  });
});

// Value: protects=device-code requests count against the caller's IPv4 address or IPv6 /64, however the address is written;
// fails_when=an IPv6 address is counted whole, or two spellings of one network land in different buckets;
// seam=none; no_claim=what Cloudflare puts in CF-Connecting-IP
describe("who a device-code request counts against", () => {
  test("IPv4 by address, IPv6 by /64", () => {
    expect(callerBucket("203.0.113.9")).toBe("203.0.113.9");
    expect(callerBucket(null)).toBe("");
    expect(callerBucket("2001:db8:1:2::1")).toBe("2001:db8:1:2::/64");
    expect(callerBucket("2001:0DB8:0001:0002:aaaa:bbbb:cccc:dddd")).toBe("2001:db8:1:2::/64");
    expect(callerBucket("2001:db8:1:3::1")).not.toBe(callerBucket("2001:db8:1:2::1"));
    expect(callerBucket("2001:db8::1")).toBe("2001:db8:0:0::/64");
    expect(callerBucket("::1")).toBe("0:0:0:0::/64");
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
