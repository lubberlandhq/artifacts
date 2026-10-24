import { randomId, sha256Hex } from "./crypto";
import type { Artifact, ArtifactRow, Env, Manifest, Mode } from "./env";

export const MAX_FILE_BYTES = 25 * 1024 * 1024;
export const MAX_VERSION_BYTES = 100 * 1024 * 1024;
export const MAX_FILES = 500;

const now = () => new Date().toISOString();

function hydrate(r: ArtifactRow): Artifact {
  return { ...r, read_users: JSON.parse(r.read_users), write_users: JSON.parse(r.write_users) };
}

export async function getArtifact(env: Env, id: string): Promise<Artifact | null> {
  if (!/^[a-z0-9]{20}$/.test(id)) return null;
  const r = await env.DB.prepare("SELECT * FROM artifacts WHERE id = ?").bind(id).first<ArtifactRow>();
  return r ? hydrate(r) : null;
}

export async function getManifest(env: Env, id: string, ver: number): Promise<Manifest | null> {
  const r = await env.DB.prepare("SELECT manifest FROM versions WHERE artifact_id = ? AND ver = ?")
    .bind(id, ver)
    .first<{ manifest: string }>();
  return r ? JSON.parse(r.manifest) : null;
}

export async function listVersions(env: Env, id: string) {
  const { results } = await env.DB.prepare(
    "SELECT ver, author, label, created_at, manifest FROM versions WHERE artifact_id = ? ORDER BY ver DESC",
  )
    .bind(id)
    .all<{ ver: number; author: string; label: string; created_at: string; manifest: string }>();
  return results.map(({ manifest, ...v }) => ({ ...v, files: Object.keys(JSON.parse(manifest)).length }));
}

// Mine first, then everything shared with me by name or as an editor. Org- and public-mode
// artifacts of other people are reachable by link but not listed, as on claude.ai.
export async function listFor(env: Env, email: string) {
  const { results } = await env.DB.prepare(
    `SELECT a.* FROM artifacts a
      WHERE a.owner = ?1
         OR EXISTS (SELECT 1 FROM json_each(a.write_users) WHERE value = ?1)
         OR (a.read_mode = 'users' AND EXISTS (SELECT 1 FROM json_each(a.read_users) WHERE value = ?1))
      ORDER BY a.updated_at DESC LIMIT 200`,
  )
    .bind(email)
    .all<ArtifactRow>();
  return results.map(hydrate);
}

export interface IncomingFile {
  path: string;
  data: ArrayBuffer;
  type: string;
}

const PATH_OK = /^(?!\/)(?!.*(?:^|\/)\.\.?(?:\/|$))[A-Za-z0-9._\-\/ @+()]{1,512}$/;
export function validPath(p: string): boolean {
  return PATH_OK.test(p) && !p.endsWith("/");
}

export function guessType(path: string, given?: string): string {
  const ext = path.toLowerCase().split(".").pop() ?? "";
  const known: Record<string, string> = {
    html: "text/html; charset=utf-8",
    htm: "text/html; charset=utf-8",
    css: "text/css; charset=utf-8",
    js: "text/javascript; charset=utf-8",
    mjs: "text/javascript; charset=utf-8",
    json: "application/json; charset=utf-8",
    md: "text/markdown; charset=utf-8",
    txt: "text/plain; charset=utf-8",
    csv: "text/csv; charset=utf-8",
    svg: "image/svg+xml",
    png: "image/png",
    jpg: "image/jpeg",
    jpeg: "image/jpeg",
    gif: "image/gif",
    webp: "image/webp",
    avif: "image/avif",
    ico: "image/x-icon",
    pdf: "application/pdf",
    mp4: "video/mp4",
    webm: "video/webm",
    mp3: "audio/mpeg",
    wav: "audio/wav",
    woff: "font/woff",
    woff2: "font/woff2",
    ttf: "font/ttf",
    otf: "font/otf",
    wasm: "application/wasm",
  };
  return known[ext] ?? (given && given !== "application/octet-stream" ? given : "application/octet-stream");
}

export class PublishError extends Error {
  constructor(
    message: string,
    public status = 400,
  ) {
    super(message);
  }
}

// Writes blobs (content-addressed, so identical bytes are stored once) and returns the new
// manifest: the previous version's files, plus `files` added or replaced, minus `remove`.
// Same semantics as Claude's publish: files left out are kept, removal is explicit.
async function buildManifest(env: Env, base: Manifest, files: IncomingFile[], remove: string[]): Promise<Manifest> {
  const m: Manifest = { ...base };
  for (const p of remove) delete m[p];
  for (const f of files) {
    if (!validPath(f.path)) throw new PublishError(`bad path: ${JSON.stringify(f.path)}`);
    if (f.data.byteLength > MAX_FILE_BYTES) throw new PublishError(`${f.path} is over ${MAX_FILE_BYTES} bytes`, 413);
    const sha256 = await sha256Hex(f.data);
    const type = guessType(f.path, f.type);
    if (!(await env.BLOBS.head(`blob/${sha256}`))) {
      await env.BLOBS.put(`blob/${sha256}`, f.data, { httpMetadata: { contentType: type } });
    }
    m[f.path] = { sha256, size: f.data.byteLength, type };
  }
  if (!m["index.html"]) throw new PublishError("an artifact needs an index.html at its root");
  if (Object.keys(m).length > MAX_FILES) throw new PublishError(`more than ${MAX_FILES} files`, 413);
  const total = Object.values(m).reduce((n, e) => n + e.size, 0);
  if (total > MAX_VERSION_BYTES) throw new PublishError(`version is over ${MAX_VERSION_BYTES} bytes`, 413);
  return m;
}

export async function createArtifact(
  env: Env,
  owner: string,
  meta: { title: string; description: string; label: string },
  files: IncomingFile[],
): Promise<Artifact> {
  const manifest = await buildManifest(env, {}, files, []);
  const id = randomId();
  const t = now();
  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO artifacts (id, owner, title, description, live_version, created_at, updated_at)
       VALUES (?, ?, ?, ?, 1, ?, ?)`,
    ).bind(id, owner, meta.title, meta.description, t, t),
    env.DB.prepare(
      "INSERT INTO versions (artifact_id, ver, author, label, manifest, created_at) VALUES (?, 1, ?, ?, ?, ?)",
    ).bind(id, owner, meta.label, JSON.stringify(manifest), t),
  ]);
  return (await getArtifact(env, id))!;
}

export async function addVersion(
  env: Env,
  a: Artifact,
  author: string,
  meta: { title?: string; description?: string; label: string; baseVersion?: number },
  files: IncomingFile[],
  remove: string[],
): Promise<number> {
  // Optimistic concurrency: a publish built on an older version is refused rather than silently
  // dropping someone else's newer changes (Claude refuses the same way and hands back the live copy).
  if (meta.baseVersion !== undefined && meta.baseVersion !== a.live_version) {
    throw new PublishError(`version ${a.live_version} is newer than the ${meta.baseVersion} this publish was built on`, 409);
  }
  const base = (await getManifest(env, a.id, a.live_version)) ?? {};
  const manifest = await buildManifest(env, base, files, remove);
  const ver = a.live_version + 1;
  const t = now();
  // The batch is one transaction: a concurrent publish of the same version number fails the
  // INSERT on the primary key and rolls the UPDATE back with it.
  try {
    await env.DB.batch([
      env.DB.prepare(
        "INSERT INTO versions (artifact_id, ver, author, label, manifest, created_at) VALUES (?, ?, ?, ?, ?, ?)",
      ).bind(a.id, ver, author, meta.label, JSON.stringify(manifest), t),
      env.DB.prepare(
        "UPDATE artifacts SET live_version = ?, title = ?, description = ?, updated_at = ? WHERE id = ?",
      ).bind(ver, meta.title ?? a.title, meta.description ?? a.description, t, a.id),
    ]);
  } catch (e) {
    if (String(e).includes("UNIQUE") || String(e).includes("PRIMARY")) {
      throw new PublishError("someone published at the same moment; retry", 409);
    }
    throw e;
  }
  return ver;
}

export async function setSharing(
  env: Env,
  id: string,
  s: { mode: Mode; readUsers: string[]; writeUsers: string[]; pinnedVersion: number | null },
) {
  await env.DB.prepare(
    `UPDATE artifacts SET read_mode = ?, read_users = ?, write_users = ?, pinned_version = ?, updated_at = ? WHERE id = ?`,
  )
    .bind(s.mode, JSON.stringify(s.readUsers), JSON.stringify(s.writeUsers), s.pinnedVersion, now(), id)
    .run();
}

export async function renameArtifact(env: Env, id: string, title: string, description: string) {
  await env.DB.prepare("UPDATE artifacts SET title = ?, description = ?, updated_at = ? WHERE id = ?")
    .bind(title, description, now(), id)
    .run();
}

// Deletes the rows. Blobs may be shared with other artifacts (content addressing), so they are
// left for a sweep rather than removed here.
export async function deleteArtifact(env: Env, id: string) {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM comments WHERE artifact_id = ?").bind(id),
    env.DB.prepare("DELETE FROM versions WHERE artifact_id = ?").bind(id),
    env.DB.prepare("DELETE FROM artifacts WHERE id = ?").bind(id),
  ]);
}

export async function listComments(env: Env, id: string) {
  const { results } = await env.DB.prepare(
    "SELECT id, ver, author, body, resolved, created_at FROM comments WHERE artifact_id = ? ORDER BY created_at",
  )
    .bind(id)
    .all();
  return results;
}

export async function addComment(env: Env, id: string, ver: number, author: string, body: string) {
  const cid = randomId(12);
  await env.DB.prepare("INSERT INTO comments (id, artifact_id, ver, author, body, created_at) VALUES (?, ?, ?, ?, ?, ?)")
    .bind(cid, id, ver, author, body, now())
    .run();
  return cid;
}

export async function resolveComment(env: Env, id: string, cid: string, resolved: boolean) {
  await env.DB.prepare("UPDATE comments SET resolved = ? WHERE id = ? AND artifact_id = ?")
    .bind(resolved ? 1 : 0, cid, id)
    .run();
}
