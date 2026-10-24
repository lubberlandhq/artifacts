// The Access JWT check on the login host, against a locally generated key (fetch is stubbed).
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { verifyAccessJwt } from "../src/auth";
import { b64url } from "../src/crypto";
import type { Env } from "../src/env";

const env = { ACCESS_TEAM_DOMAIN: "team.cloudflareaccess.com", ACCESS_AUD: "aud-1" } as Env;
let priv: CryptoKey;
const realFetch = globalThis.fetch;

beforeAll(async () => {
  const kp = (await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  priv = kp.privateKey;
  const jwk = { ...(await crypto.subtle.exportKey("jwk", kp.publicKey)), kid: "k1" };
  globalThis.fetch = (async (u: string) => {
    expect(String(u)).toBe("https://team.cloudflareaccess.com/cdn-cgi/access/certs");
    return new Response(JSON.stringify({ keys: [jwk] }));
  }) as typeof fetch;
});
afterAll(() => {
  globalThis.fetch = realFetch;
});

async function jwt(claims: Record<string, unknown>, header: Record<string, unknown> = { alg: "RS256", kid: "k1" }, key = priv) {
  const e = new TextEncoder();
  const h = b64url(e.encode(JSON.stringify(header)));
  const p = b64url(e.encode(JSON.stringify(claims)));
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, e.encode(`${h}.${p}`));
  return `${h}.${p}.${b64url(sig)}`;
}
const good = () => ({ aud: ["aud-1"], iss: "https://team.cloudflareaccess.com", exp: Math.floor(Date.now() / 1000) + 300, email: "Client@Acme.com" });

describe("verifyAccessJwt", () => {
  test("valid token yields the lowercased email", async () => {
    expect(await verifyAccessJwt(env, await jwt(good()))).toBe("client@acme.com");
  });
  test("wrong audience", async () => {
    expect(await verifyAccessJwt(env, await jwt({ ...good(), aud: ["other-app"] }))).toBeNull();
  });
  test("wrong issuer", async () => {
    expect(await verifyAccessJwt(env, await jwt({ ...good(), iss: "https://evil.cloudflareaccess.com" }))).toBeNull();
  });
  test("expired", async () => {
    expect(await verifyAccessJwt(env, await jwt({ ...good(), exp: 1 }))).toBeNull();
  });
  test("alg none / unknown kid / tampered payload", async () => {
    expect(await verifyAccessJwt(env, await jwt(good(), { alg: "none", kid: "k1" }))).toBeNull();
    expect(await verifyAccessJwt(env, await jwt(good(), { alg: "RS256", kid: "nope" }))).toBeNull();
    const t = (await jwt(good())).split(".");
    t[1] = b64url(new TextEncoder().encode(JSON.stringify({ ...good(), email: "nate@example.com" })));
    expect(await verifyAccessJwt(env, t.join("."))).toBeNull();
  });
  test("service token (no email) gets no identity", async () => {
    const { email, ...rest } = good();
    expect(await verifyAccessJwt(env, await jwt({ ...rest, common_name: "svc" }))).toBeNull();
  });
});
