// Whiteboard share hub. Whiteboard (dev.fast's review app) uploads a board snapshot to a share
// service and hands out a link; its client lets the service origin be changed
// (`whiteboard login --origin`). These routes answer that client's protocol, read from the
// installed @dev.fast/whiteboard 0.5.2, so a board's link is a Tack link:
//
//   /api/auth/device/code, /device/token, /get-session   device login (approved on /device)
//   /api/v2/shares[...]        bearer: upload a snapshot, list, recover the link, revisions, revoke
//   /api/v2/shared/<cap>[...]  anonymous: who shared it, and the snapshot
//   /s/<cap>                   the page a person opens (src/index.ts, src/pages.ts)
//
// Reads are anonymous because the client sends them with no credentials and refuses redirects:
// the 43-character capability in the link is the only read control. Shares are immutable
// snapshots; nothing here is live.
import { createApiToken, currentUser } from "./auth";
import { canPublish, isAdmin, orgPolicy } from "./authz";
import { type BoardSource, contentUrl } from "./content";
import { SECURITY_HEADERS } from "./csp";
import { decryptText, encryptText, randomId, randomToken, sha256Hex } from "./crypto";
import type { Env } from "./env";
import { getArtifact } from "./store";

export const SHARE_FORMAT = "review-share/2";
export const MAX_SHARE_BYTES = 16 * 1024 * 1024;
const DEVICE_TTL = 600; // seconds a device code stays approvable
const POLL_INTERVAL = 2; // seconds the client waits between polls
const POLL_TOO_FAST_MS = 1000; // polls closer together than this are told to slow down
export const TOKEN_SCOPE = "whiteboard"; // what a device login's token is limited to
const REQUEST_TTL_MS = 7 * 24 * 3600 * 1000;
const VIEWER_SETTING = "whiteboard_viewer";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const CAPABILITY = /^[A-Za-z0-9_-]{43}$/;

const HEADERS = {
  ...SECURITY_HEADERS,
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "private, no-store",
  "X-Robots-Tag": "noindex",
};
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: HEADERS });
// The share client reads {"error":{"code"}}; these are the codes it knows.
const fail = (status: number, code: string) => json({ error: { code } }, status);
// The device endpoints answer in OAuth's shape instead.
const oauthFail = (error: string) => json({ error }, 400);

const nowSeconds = () => Math.floor(Date.now() / 1000);

// A request body of at most `limit` bytes, read as it arrives so an oversized or undeclared
// body is dropped at the limit instead of buffered whole. Null when it is larger.
async function readBounded(req: Request, limit: number): Promise<Uint8Array | null> {
  if (Number(req.headers.get("Content-Length") ?? 0) > limit) return null;
  if (!req.body) return new Uint8Array();
  const reader = req.body.getReader();
  const parts: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > limit) {
      await reader.cancel().catch(() => {});
      return null;
    }
    parts.push(value);
  }
  const out = new Uint8Array(size);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.byteLength;
  }
  return out;
}

const SMALL_BODY = 8 * 1024; // the device endpoints take a few short strings

async function smallJson<T>(req: Request): Promise<T | null> {
  const raw = await readBounded(req, SMALL_BODY);
  if (!raw) return null;
  try {
    return JSON.parse(new TextDecoder().decode(raw)) as T;
  } catch {
    return null;
  }
}

// ---- Device login ----------------------------------------------------------------------------

// No 0/O or 1/I, and 32 symbols so a byte maps evenly.
const USER_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

function newUserCode(): string {
  const c = [...crypto.getRandomValues(new Uint8Array(8))].map((b) => USER_CODE_ALPHABET[b & 31]).join("");
  return `${c.slice(0, 4)}-${c.slice(4)}`;
}

// What a person typed or followed a link with, in the stored form; null when it can't be a code.
export function normalizeUserCode(input: string | null): string | null {
  const c = (input ?? "").toUpperCase().replace(/[^A-Z0-9]/g, "");
  return c.length === 8 ? `${c.slice(0, 4)}-${c.slice(4)}` : null;
}

async function deviceCode(req: Request, env: Env): Promise<Response> {
  const body = await smallJson<{ client_id?: unknown }>(req);
  if (!body || typeof body.client_id !== "string") return oauthFail("invalid_request");
  const now = nowSeconds();
  await env.DB.prepare("DELETE FROM wb_device_codes WHERE expires < ?").bind(now).run();
  const device = randomToken(32);
  const user = newUserCode();
  await env.DB.prepare("INSERT INTO wb_device_codes (device_hash, user_code, expires) VALUES (?, ?, ?)")
    .bind(await sha256Hex(device), user, now + DEVICE_TTL)
    .run();
  return json({
    device_code: device,
    user_code: user,
    verification_uri: `${env.APP_ORIGIN}/device`,
    verification_uri_complete: `${env.APP_ORIGIN}/device?user_code=${user}`,
    expires_in: DEVICE_TTL,
    interval: POLL_INTERVAL,
  });
}

async function deviceToken(req: Request, env: Env): Promise<Response> {
  const body = await smallJson<{ grant_type?: unknown; device_code?: unknown }>(req);
  if (!body || body.grant_type !== "urn:ietf:params:oauth:grant-type:device_code" || typeof body.device_code !== "string") {
    return oauthFail("invalid_request");
  }
  const hash = await sha256Hex(body.device_code);
  const now = nowSeconds();
  const row = await env.DB.prepare("SELECT email, expires, last_poll FROM wb_device_codes WHERE device_hash = ?")
    .bind(hash)
    .first<{ email: string | null; expires: number; last_poll: number | null }>();
  if (!row || row.expires < now) return oauthFail("expired_token");
  if (!row.email) {
    const nowMs = Date.now();
    await env.DB.prepare("UPDATE wb_device_codes SET last_poll = ? WHERE device_hash = ?").bind(nowMs, hash).run();
    return oauthFail(row.last_poll !== null && nowMs - row.last_poll < POLL_TOO_FAST_MS ? "slow_down" : "authorization_pending");
  }
  // Deleting the row is the claim: of two polls racing, one gets the token.
  const claimed = await env.DB.prepare("DELETE FROM wb_device_codes WHERE device_hash = ? AND email IS NOT NULL RETURNING email")
    .bind(hash)
    .first<{ email: string }>();
  if (!claimed) return oauthFail("expired_token");
  // Listed and revoked with the person's other tokens, but good for the share hub only.
  const token = await createApiToken(env, claimed.email, "Whiteboard login", claimed.email, TOKEN_SCOPE);
  return json({ access_token: token, token_type: "Bearer" });
}

export async function devicePending(env: Env, userCode: string): Promise<boolean> {
  const row = await env.DB.prepare("SELECT 1 AS ok FROM wb_device_codes WHERE user_code = ? AND email IS NULL AND expires >= ?")
    .bind(userCode, nowSeconds())
    .first();
  return !!row;
}

// A signed-in person vouches for the computer showing this code. False when the code is unknown,
// expired or already approved.
export async function approveDevice(env: Env, userCode: string, email: string): Promise<boolean> {
  const r = await env.DB.prepare("UPDATE wb_device_codes SET email = ? WHERE user_code = ? AND email IS NULL AND expires >= ?")
    .bind(email.toLowerCase(), userCode, nowSeconds())
    .run();
  return r.meta.changes === 1;
}

// ---- Shares ----------------------------------------------------------------------------------

interface ShareRow {
  id: string;
  owner: string;
  review_id: string;
  title: string;
  cap_hash: string;
  cap_sealed: string;
  content_id: string;
  created_at: number;
}

interface RevisionRow {
  id: string;
  share_id: string;
  version: number;
  size: number;
  sender: string;
  frozen: number;
  created_at: number;
}

const blobKey = (shareId: string, revisionId: string) => `wb/${shareId}/${revisionId}.json`;

// Whether a snapshot's revision still exists. The content origin asks before serving a board, so
// a frame handed out before a revoke stops at the revoke, not when its grant expires.
export async function boardStillShared(env: Env, key: string): Promise<boolean> {
  const m = key.match(/^wb\/[0-9a-f-]{36}\/([0-9a-f-]{36})\.json$/);
  return !!m && !!(await env.DB.prepare("SELECT 1 AS ok FROM wb_revisions WHERE id = ?").bind(m[1]).first());
}

const linkUrl = (env: Env, capability: string, revision?: string) =>
  `${env.APP_ORIGIN}/s/${capability}${revision ? `?rev=${revision}` : ""}`;

// Null when the sealed copy no longer opens: SESSION_SECRET changed since the share was made.
// The link still works for whoever holds it; only the server can't spell it out any more.
const capabilityOf = (env: Env, share: ShareRow): Promise<string | null> => decryptText(env.SESSION_SECRET, "wb-capability", share.cap_sealed);

const sealCapability = async (env: Env, capability: string) => ({
  hash: await sha256Hex(capability),
  sealed: await encryptText(env.SESSION_SECRET, "wb-capability", capability),
});

// The link for an upload's answer. A share whose link can't be recovered gets a new one: the
// old link stops working, which beats an owner who can never share that board again.
async function linkForUpload(env: Env, share: ShareRow): Promise<string> {
  const known = await capabilityOf(env, share);
  if (known) return linkUrl(env, known);
  const capability = randomToken(32);
  const c = await sealCapability(env, capability);
  // Only if nobody replaced it meanwhile: of two uploads racing here, both answer the winner's link.
  const r = await env.DB.prepare("UPDATE wb_shares SET cap_hash = ?, cap_sealed = ? WHERE id = ? AND cap_hash = ?")
    .bind(c.hash, c.sealed, share.id, share.cap_hash)
    .run();
  if (r.meta.changes === 1) return linkUrl(env, capability);
  const now = await env.DB.prepare("SELECT * FROM wb_shares WHERE id = ?").bind(share.id).first<ShareRow>();
  const winner = now ? await capabilityOf(env, now) : null;
  if (!winner) throw new Error(`share ${share.id}: no recoverable link after a concurrent change`);
  return linkUrl(env, winner);
}

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

// The fields this service reads or that every reader requires. The reader validates the rest
// against its own schema, so a field a newer Whiteboard adds passes through untouched.
export function bundleProblem(b: unknown): string | null {
  if (!isRecord(b)) return "bundle is not an object";
  if (b.format !== SHARE_FORMAT) return `format is not ${SHARE_FORMAT}`;
  if (typeof b.reviewId !== "string" || b.reviewId.length < 1 || b.reviewId.length > 256) return "reviewId";
  if (typeof b.version !== "number" || !Number.isSafeInteger(b.version) || b.version < 0) return "version";
  if (typeof b.title !== "string" || b.title.length > 4096) return "title";
  for (const k of ["snapshot", "images", "traces", "maps", "selections"]) if (!isRecord(b[k])) return k;
  for (const k of ["commits", "sources"]) if (!Array.isArray(b[k])) return k;
  return null;
}

async function publish(req: Request, env: Env, email: string): Promise<Response> {
  // A little room for the envelope around the 16 MiB bundle.
  const limit = MAX_SHARE_BYTES + 4096;
  const raw = await readBounded(req, limit);
  if (!raw) return fail(413, "too_large");
  let body: { requestId?: unknown; bundle?: unknown };
  try {
    body = JSON.parse(new TextDecoder().decode(raw));
  } catch {
    return fail(400, "invalid_request");
  }
  if (!isRecord(body) || typeof body.requestId !== "string" || !UUID.test(body.requestId) || bundleProblem(body.bundle)) {
    return fail(400, "invalid_request");
  }
  const bundle = body.bundle as { reviewId: string; version: number; title: string; frozen?: unknown };
  const bytes = new TextEncoder().encode(JSON.stringify(bundle));
  if (bytes.byteLength > MAX_SHARE_BYTES) return fail(413, "too_large");
  const requestId = body.requestId.toLowerCase();
  const now = Date.now();

  // A retry of an upload that already landed answers as the first one did.
  const prior = await env.DB.prepare("SELECT s.* FROM wb_requests r JOIN wb_shares s ON s.id = r.share_id WHERE r.owner = ? AND r.request_id = ?")
    .bind(email, requestId)
    .first<ShareRow>();
  if (prior) return json({ shareId: prior.id, url: await linkForUpload(env, prior) });

  const find = () =>
    env.DB.prepare("SELECT * FROM wb_shares WHERE owner = ? AND review_id = ?").bind(email, bundle.reviewId).first<ShareRow>();
  let share = await find();
  if (!share) {
    const c = await sealCapability(env, randomToken(32));
    // OR IGNORE: two first uploads of one board race to the same row, and both then read it.
    await env.DB.prepare(
      "INSERT OR IGNORE INTO wb_shares (id, owner, review_id, title, cap_hash, cap_sealed, content_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
      .bind(
        crypto.randomUUID(),
        email,
        bundle.reviewId,
        bundle.title,
        c.hash,
        c.sealed,
        randomId(),
        now,
      )
      .run();
    share = await find();
    if (!share) throw new Error("share row missing after insert");
  }

  // One link per board; a higher saved version adds a revision, anything else changes nothing.
  const latest = await env.DB.prepare("SELECT MAX(version) AS v FROM wb_revisions WHERE share_id = ?").bind(share.id).first<{ v: number | null }>();
  if (latest?.v == null || bundle.version > latest.v) {
    const revisionId = crypto.randomUUID();
    try {
      await env.BLOBS.put(blobKey(share.id, revisionId), bytes, { httpMetadata: { contentType: "application/json" } });
    } catch (e) {
      // A first upload that stored nothing leaves no share behind to list with a dead link.
      await env.DB.prepare("DELETE FROM wb_shares WHERE id = ?1 AND NOT EXISTS (SELECT 1 FROM wb_revisions WHERE share_id = ?1)").bind(share.id).run();
      throw e;
    }
    try {
      await env.DB.batch([
        env.DB.prepare("INSERT INTO wb_revisions (id, share_id, version, size, sender, frozen, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)").bind(
          revisionId,
          share.id,
          bundle.version,
          bytes.byteLength,
          email,
          bundle.frozen === true ? 1 : 0,
          now,
        ),
        // The newest version names the share, whatever order uploads land in.
        env.DB.prepare("UPDATE wb_shares SET title = ?1 WHERE id = ?2 AND NOT EXISTS (SELECT 1 FROM wb_revisions WHERE share_id = ?2 AND version > ?3)").bind(
          bundle.title,
          share.id,
          bundle.version,
        ),
      ]);
    } catch (e) {
      // The same version landed from a concurrent upload: that one stands.
      await env.BLOBS.delete(blobKey(share.id, revisionId));
      if (!String(e).includes("UNIQUE")) throw e;
    }
  }

  await env.DB.batch([
    env.DB.prepare("INSERT OR IGNORE INTO wb_requests (owner, request_id, share_id, created_at) VALUES (?, ?, ?, ?)").bind(email, requestId, share.id, now),
    env.DB.prepare("DELETE FROM wb_requests WHERE created_at < ?").bind(now - REQUEST_TTL_MS),
  ]);
  return json({ shareId: share.id, url: await linkForUpload(env, share) });
}

// `owner` is whose shares to list; null is everyone's (admins, with ?owner=*).
async function listShares(env: Env, owner: string | null, cursor: string | null, showOwner: boolean, caller: string): Promise<Response> {
  const PAGE = 100;
  const email = owner ?? "";
  const everyone = owner === null ? 1 : 0;
  let after: ShareRow | null = null;
  if (cursor) {
    if (!UUID.test(cursor)) return fail(400, "invalid_request");
    after = await env.DB.prepare("SELECT * FROM wb_shares WHERE id = ?1 AND (owner = ?2 OR ?3 = 1)").bind(cursor, email, everyone).first<ShareRow>();
    if (!after) return fail(400, "invalid_request");
  }
  const { results } = await (after
    ? env.DB.prepare(
        `SELECT s.*, (SELECT MAX(version) FROM wb_revisions WHERE share_id = s.id) AS latest_version FROM wb_shares s
          WHERE (s.owner = ?1 OR ?5 = 1) AND (s.created_at < ?2 OR (s.created_at = ?2 AND s.id > ?3))
          ORDER BY s.created_at DESC, s.id LIMIT ?4`,
      ).bind(email, after.created_at, after.id, PAGE + 1, everyone)
    : env.DB.prepare(
        `SELECT s.*, (SELECT MAX(version) FROM wb_revisions WHERE share_id = s.id) AS latest_version FROM wb_shares s
          WHERE (s.owner = ?1 OR ?3 = 1) ORDER BY s.created_at DESC, s.id LIMIT ?2`,
      ).bind(email, PAGE + 1, everyone)
  ).all<ShareRow & { latest_version: number | null }>();
  const page = results.slice(0, PAGE);
  const items = await Promise.all(
    page.map(async (s) => {
      // The link is the read capability: an admin listing other people's shares gets ids to
      // revoke by, not links to read with.
      const capability = s.owner === caller ? await capabilityOf(env, s) : null;
      return {
        shareId: s.id,
        reviewId: s.review_id,
        title: s.title,
        latestVersion: s.latest_version,
        createdAt: s.created_at,
        // Null for someone else's share, or when the link can't be recovered; revoke works by id.
        url: capability ? linkUrl(env, capability) : null,
        ...(showOwner ? { owner: s.owner } : {}),
      };
    }),
  );
  return json({ items, ...(results.length > PAGE ? { next: page[page.length - 1].id } : {}) });
}

async function revisionsOf(env: Env, shareId: string): Promise<RevisionRow[]> {
  const { results } = await env.DB.prepare("SELECT * FROM wb_revisions WHERE share_id = ? ORDER BY version DESC").bind(shareId).all<RevisionRow>();
  return results;
}

async function revoke(env: Env, share: ShareRow): Promise<Response> {
  // Snapshots first: if this fails part-way the share row is still there, so the owner can
  // revoke again. Then the rows, which is what stops every read (boardStillShared below), and
  // one more sweep for a snapshot an upload stored while this ran.
  const sweep = async () => {
    for (;;) {
      const listed = await env.BLOBS.list({ prefix: `wb/${share.id}/` });
      if (listed.objects.length) await env.BLOBS.delete(listed.objects.map((o) => o.key));
      if (!listed.truncated) break;
    }
  };
  await sweep();
  await env.DB.batch([
    env.DB.prepare("DELETE FROM wb_revisions WHERE share_id = ?").bind(share.id),
    env.DB.prepare("DELETE FROM wb_requests WHERE share_id = ?").bind(share.id),
    env.DB.prepare("DELETE FROM wb_shares WHERE id = ?").bind(share.id),
  ]);
  await sweep();
  return json({ shareId: share.id, revoked: true });
}

// ---- Anonymous reads -------------------------------------------------------------------------

export interface SharedBoard {
  share: ShareRow;
  revision: RevisionRow;
  latest: string; // id of the newest revision
}

// The revision a link names: `rev` when given, else the newest. Null for an unknown capability,
// an unknown revision and a revoked share alike.
export async function resolveShared(env: Env, capability: string, rev: string | null): Promise<SharedBoard | null> {
  if (!CAPABILITY.test(capability) || (rev !== null && !UUID.test(rev))) return null;
  const share = await env.DB.prepare("SELECT * FROM wb_shares WHERE cap_hash = ?").bind(await sha256Hex(capability)).first<ShareRow>();
  if (!share) return null;
  const revisions = await revisionsOf(env, share.id);
  const revision = rev === null ? revisions[0] : revisions.find((r) => r.id === rev.toLowerCase());
  return revision ? { share, revision, latest: revisions[0].id } : null;
}

// Where a share's page frames its board from, or null when no viewer is registered.
export async function sharedFrame(env: Env, s: SharedBoard): Promise<string | null> {
  const viewer = await registeredViewer(env);
  if (!viewer) return null;
  const from: BoardSource = { manifest: viewer.artifact, board: blobKey(s.share.id, s.revision.id) };
  return contentUrl(env, s.share.content_id, viewer.version, from);
}

// The registered board viewer: one artifact at one version, "<id>:<version>". Pinned, so a later
// publish to that artifact changes no share page until an admin registers it again. Null when
// nothing is registered or the artifact is gone.
async function registeredViewer(env: Env): Promise<{ artifact: string; version: number; owner: string } | null> {
  const [id, ver] = ((await getSetting(env, VIEWER_SETTING)) ?? "").split(":");
  const a = id ? await getArtifact(env, id) : null;
  const version = Number(ver);
  return a && Number.isInteger(version) && version >= 1 && version <= a.live_version ? { artifact: a.id, version, owner: a.owner } : null;
}

// ---- Settings --------------------------------------------------------------------------------

async function getSetting(env: Env, key: string): Promise<string | null> {
  const r = await env.DB.prepare("SELECT value FROM settings WHERE key = ?").bind(key).first<{ value: string }>();
  return r?.value ?? null;
}

async function setSetting(env: Env, key: string, value: string) {
  await env.DB.prepare("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").bind(key, value).run();
}

// ---- Routing ---------------------------------------------------------------------------------

export const isWhiteboardApi = (path: string) =>
  path.startsWith("/api/auth/") || path === "/api/v2" || path.startsWith("/api/v2/") || path === "/api/whiteboard/viewer";

export async function handleWhiteboardApi(req: Request, env: Env, url: URL): Promise<Response> {
  const method = req.method;
  const path = url.pathname;

  if (path === "/api/auth/device/code" && method === "POST") return deviceCode(req, env);
  if (path === "/api/auth/device/token" && method === "POST") return deviceToken(req, env);

  // Anonymous reads never look at credentials.
  const shared = path.match(/^\/api\/v2\/shared\/([^/]+)(\/bundle)?$/);
  if (shared) {
    if (method !== "GET" && method !== "HEAD") return fail(405, "method_not_allowed");
    const s = await resolveShared(env, shared[1], url.searchParams.get("rev"));
    if (!s) return fail(404, "not_found");
    if (!shared[2]) {
      return json({
        sender: { login: s.revision.sender },
        sharedAt: s.revision.created_at,
        size: s.revision.size,
        revision: { id: s.revision.id, version: s.revision.version, createdAt: s.revision.created_at },
        latest: s.latest,
      });
    }
    const obj = await env.BLOBS.get(blobKey(s.share.id, s.revision.id));
    if (!obj) return fail(404, "not_found");
    return new Response(method === "HEAD" ? null : obj.body, { headers: { ...HEADERS, "Content-Length": String(obj.size) } });
  }

  const user = await currentUser(req, env, TOKEN_SCOPE);
  const email = user?.email ?? null;
  const policy = orgPolicy(env);
  if (method !== "GET" && user?.via === "session" && req.headers.get("Origin") !== env.APP_ORIGIN) return fail(403, "forbidden");

  if (path === "/api/auth/get-session" && method === "GET") {
    if (!email) return fail(401, "login_required");
    // Whiteboard saves `name` as the login it shows; here a person is their email.
    return json({ user: { id: email, name: email, email } });
  }

  // Which artifact holds the board viewer. Its files are served to anyone holding a share link,
  // so only an admin names it, only one of their own, and never with a hub-only token.
  if (path === "/api/whiteboard/viewer") {
    if (user?.scope) return fail(403, "forbidden");
    if (method === "GET") {
      if (!email) return fail(401, "login_required");
      // Nulls too when the registered artifact was deleted, so `tack board-viewer` starts a new one.
      const v = await registeredViewer(env);
      return json({ artifact: v?.artifact ?? null, version: v?.version ?? null, owner: v?.owner ?? null });
    }
    if (method === "PUT") {
      if (!email) return fail(401, "login_required");
      if (!isAdmin(policy, email)) return fail(403, "forbidden");
      const b = (await req.json().catch(() => null)) as { artifact?: unknown } | null;
      const a = typeof b?.artifact === "string" ? await getArtifact(env, b.artifact) : null;
      if (!a) return fail(400, "invalid_request");
      if (a.owner !== email) return fail(403, "forbidden");
      await setSetting(env, VIEWER_SETTING, `${a.id}:${a.live_version}`);
      return json({ artifact: a.id, version: a.live_version, owner: a.owner });
    }
  }

  const parts = path.replace(/^\/api\/v2\/?/, "").split("/").filter(Boolean);
  if (path.startsWith("/api/v2") && parts[0] === "shares") {
    if (!email) return fail(401, "login_required");
    // An admin acts on anyone's shares, but not with a hub-only token: that one is a person's
    // Whiteboard, not their admin hat.
    const admin = isAdmin(policy, email) && !user?.scope;
    if (parts.length === 1 && method === "GET") {
      // ?owner=<email> or ?owner=* (everyone) is for admins; without it, the caller's own.
      const owner = url.searchParams.get("owner")?.trim().toLowerCase() || null;
      if (owner && owner !== email && !admin) return fail(403, "forbidden");
      return listShares(env, owner === "*" ? null : (owner ?? email), url.searchParams.get("cursor"), owner !== null, email);
    }
    if (parts.length === 1 && method === "POST") {
      if (!canPublish(policy, email)) return fail(403, "forbidden");
      return publish(req, env, email);
    }
    if (parts.length >= 2 && UUID.test(parts[1])) {
      // Someone else's share and no share look the same, except to an admin, who may revoke it.
      const found = await env.DB.prepare("SELECT * FROM wb_shares WHERE id = ?").bind(parts[1].toLowerCase()).first<ShareRow>();
      if (found && parts.length === 2 && method === "DELETE" && (found.owner === email || admin)) return revoke(env, found);
      const share = found?.owner === email ? found : null;
      if (!share) return fail(404, "not_found");
      if (parts.length === 3 && (parts[2] === "link" || parts[2] === "revisions") && method === "GET") {
        const capability = await capabilityOf(env, share);
        // Sharing the board again mints a new link (linkForUpload); the old one can't be shown.
        if (!capability) return fail(409, "link_unrecoverable");
        if (parts[2] === "link") return json({ shareId: share.id, url: linkUrl(env, capability) });
        const revisions = await revisionsOf(env, share.id);
        return json({
          latest: revisions[0]?.id,
          items: revisions.map((r) => ({ id: r.id, version: r.version, createdAt: r.created_at, size: r.size, url: linkUrl(env, capability, r.id) })),
        });
      }
    }
  }

  // Includes /api/auth/token: a 404 there tells the client to send its token as it is.
  return fail(404, "not_found");
}
