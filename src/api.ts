// JSON API on the app host. Session-cookie callers must send a same-origin Origin header on
// writes (CSRF); bearer-token callers (CLI, agents) are exempt because browsers never attach them.
import { canAdmin, canPublish, canRead, canWrite, isAdmin, orgPolicy, parseEmails, visibleVersion } from "./authz";
import { createApiToken, currentUser } from "./auth";
import { contentUrl } from "./content";
import type { Artifact, Env, Mode } from "./env";
import {
  addComment,
  addVersion,
  createArtifact,
  deleteArtifact,
  getArtifact,
  getManifest,
  type IncomingFile,
  listComments,
  listFor,
  listVersions,
  PublishError,
  renameArtifact,
  resolveComment,
  setSharing,
} from "./store";

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
  });
const err = (status: number, error: string) => json({ error }, status);

export function publicView(env: Env, a: Artifact, email: string | null) {
  const policy = orgPolicy(env);
  return {
    id: a.id,
    url: `${env.APP_ORIGIN}/a/${a.id}`,
    title: a.title,
    description: a.description,
    owner: a.owner,
    live_version: a.live_version,
    updated_at: a.updated_at,
    created_at: a.created_at,
    role: canAdmin(policy, a, email) ? "owner" : canWrite(policy, a, email) ? "editor" : "viewer",
    // Sharing details go to editors only; a viewer learns nothing about who else can see it.
    ...(canWrite(policy, a, email)
      ? {
          sharing: {
            mode: a.read_mode,
            users: a.read_users,
            editors: a.write_users,
            pinned_version: a.pinned_version,
            viewers_see: a.pinned_version === null ? "live" : a.pinned_version === a.live_version ? "pinned-current" : "pinned-earlier",
          },
        }
      : {}),
  };
}

async function readPublish(req: Request) {
  const form = await req.formData();
  const files: IncomingFile[] = [];
  for (const [key, value] of form.entries()) {
    // Each file part is named "file"; its filename is the published path (folders included).
    const v = value as unknown as File | string;
    if (key === "file" && typeof v !== "string") {
      files.push({ path: v.name, data: await v.arrayBuffer(), type: v.type });
    }
  }
  const str = (k: string) => {
    const v = form.get(k);
    return typeof v === "string" ? v.trim() : undefined;
  };
  const remove = form.getAll("remove").filter((v): v is string => typeof v === "string");
  const base = str("base_version");
  return {
    files,
    remove,
    title: str("title")?.slice(0, 200),
    description: str("description")?.slice(0, 1000),
    label: (str("label") ?? "").slice(0, 60),
    baseVersion: base ? Number(base) : undefined,
  };
}

export async function handleApi(req: Request, env: Env, url: URL): Promise<Response> {
  const user = await currentUser(req, env);
  const email = user?.email ?? null;
  const policy = orgPolicy(env);
  const method = req.method;
  const parts = url.pathname.replace(/^\/api\/?/, "").split("/").filter(Boolean);

  if (method !== "GET" && user?.via === "session" && req.headers.get("Origin") !== env.APP_ORIGIN) {
    return err(403, "cross-origin write refused");
  }

  try {
    // GET /api/me
    if (parts[0] === "me" && parts.length === 1) {
      return json({ email, can_publish: canPublish(policy, email), admin: isAdmin(policy, email) });
    }

    // /api/tokens — mint, list, revoke CLI/agent tokens (session only: a token can't mint tokens)
    // /api/tokens — mint, list, revoke CLI/agent tokens (session only: a token can't mint tokens).
    // An admin may mint for another publisher ({"as": "tenant-agents@example.com"}); the minter
    // lists and revokes it alongside their own.
    if (parts[0] === "tokens") {
      if (!user || user.via !== "session") return err(401, "sign in on the web to manage tokens");
      if (method === "GET" && parts.length === 1) {
        const { results } = await env.DB.prepare(
          `SELECT substr(hash, 1, 12) AS id, owner, label, created_at, last_used FROM tokens
            WHERE owner = ?1 OR created_by = ?1 ORDER BY created_at DESC`,
        )
          .bind(user.email)
          .all();
        return json({ tokens: results });
      }
      if (method === "POST" && parts.length === 1) {
        const body = (await req.json().catch(() => ({}))) as { label?: string; as?: string };
        const label = (body.label ?? "").trim().slice(0, 60) || "token";
        const as = (body.as ?? "").trim().toLowerCase() || user.email;
        if (as !== user.email) {
          if (!isAdmin(policy, user.email)) return err(403, "only an admin can mint a token for someone else");
          if (!canPublish(policy, as)) return err(400, `${as} is not in PUBLISHERS`);
        } else if (!canPublish(policy, email)) return err(403, "not a publisher");
        return json({ token: await createApiToken(env, as, label, user.email), label, owner: as }, 201);
      }
      if (method === "DELETE" && parts.length === 2 && /^[0-9a-f]{12}$/.test(parts[1])) {
        await env.DB.prepare("DELETE FROM tokens WHERE (owner = ?1 OR created_by = ?1) AND substr(hash, 1, 12) = ?2")
          .bind(user.email, parts[1])
          .run();
        return json({ ok: true });
      }
    }

    if (parts[0] !== "artifacts") return err(404, "no such endpoint");

    // GET /api/artifacts — mine and shared with me
    if (parts.length === 1 && method === "GET") {
      if (!email) return err(401, "sign in");
      const rows = await listFor(env, email);
      return json({ artifacts: rows.map((a) => publicView(env, a, email)) });
    }

    // POST /api/artifacts — publish a new artifact (multipart: file parts, title, description, label)
    if (parts.length === 1 && method === "POST") {
      if (!canPublish(policy, email)) return err(email ? 403 : 401, email ? "not a publisher" : "sign in");
      const p = await readPublish(req);
      if (!p.title) return err(400, "title is required");
      const a = await createArtifact(env, email!, { title: p.title, description: p.description ?? "", label: p.label }, p.files);
      return json(publicView(env, a, email), 201);
    }

    const a = await getArtifact(env, parts[1]);
    // Not found and not allowed look the same, so a link's existence isn't confirmed to strangers.
    if (!a || !canRead(policy, a, email)) return err(email ? 404 : 401, email ? "no artifact at that id you can open" : "sign in");
    const sub = parts[2];

    if (!sub) {
      if (method === "GET") return json(publicView(env, a, email));
      if (method === "PATCH") {
        if (!canAdmin(policy, a, email)) return err(403, "only the owner can rename");
        const b = (await req.json()) as { title?: string; description?: string };
        await renameArtifact(env, a.id, (b.title ?? a.title).trim().slice(0, 200) || a.title, (b.description ?? a.description).slice(0, 1000));
        return json(publicView(env, (await getArtifact(env, a.id))!, email));
      }
      if (method === "DELETE") {
        if (!canAdmin(policy, a, email)) return err(403, "only the owner can delete");
        await deleteArtifact(env, a.id);
        return json({ deleted: a.id });
      }
    }

    // GET /api/artifacts/:id/head — what the viewer should be showing now (the shell polls this)
    if (sub === "head" && method === "GET") {
      return json({ version: visibleVersion(policy, a, email), live_version: a.live_version, updated_at: a.updated_at });
    }

    // GET /api/artifacts/:id/frame?v= — a fresh content-origin URL for this viewer
    if (sub === "frame" && method === "GET") {
      const v = visibleVersion(policy, a, email, Number(url.searchParams.get("v")) || undefined);
      return json({ version: v, src: await contentUrl(env, a.id, v) });
    }

    // /api/artifacts/:id/versions
    if (sub === "versions") {
      if (method === "GET") {
        if (!canWrite(policy, a, email)) return err(403, "version history is for editors");
        return json({ versions: await listVersions(env, a.id) });
      }
      if (method === "POST") {
        if (!canWrite(policy, a, email)) return err(403, "you can view this artifact but not publish to it");
        const p = await readPublish(req);
        const ver = await addVersion(env, a, email!, p, p.files, p.remove);
        return json({ ...publicView(env, (await getArtifact(env, a.id))!, email), published_version: ver }, 201);
      }
    }

    // GET /api/artifacts/:id/files?v= — the manifest (editors)
    if (sub === "files" && method === "GET") {
      if (!canWrite(policy, a, email)) return err(403, "file listing is for editors");
      const v = visibleVersion(policy, a, email, Number(url.searchParams.get("v")) || undefined);
      return json({ version: v, files: await getManifest(env, a.id, v) });
    }

    // PUT /api/artifacts/:id/sharing  {mode, users, editors, pin: "live" | "current" | <ver>}
    if (sub === "sharing" && method === "PUT") {
      if (!canAdmin(policy, a, email)) return err(403, "only the owner can change sharing");
      const b = (await req.json()) as { mode?: Mode; users?: unknown; editors?: unknown; pin?: unknown };
      const mode = b.mode ?? a.read_mode;
      if (!["owner", "users", "org", "public"].includes(mode)) return err(400, "mode is owner, users, org or public");
      const users = b.users === undefined ? a.read_users : parseEmails(b.users);
      const editors = b.editors === undefined ? a.write_users : parseEmails(b.editors);
      if (!users || !editors) return err(400, "users and editors are email addresses");
      let pinned = a.pinned_version;
      if (b.pin === "live") pinned = null;
      else if (b.pin === "current") pinned = a.live_version;
      else if (typeof b.pin === "number" && b.pin >= 1 && b.pin <= a.live_version) pinned = b.pin;
      else if (b.pin !== undefined) return err(400, 'pin is "live", "current" or a version number');
      await setSharing(env, a.id, { mode, readUsers: users, writeUsers: editors.filter((e) => e !== a.owner), pinnedVersion: pinned });
      return json(publicView(env, (await getArtifact(env, a.id))!, email));
    }

    // /api/artifacts/:id/comments
    if (sub === "comments") {
      if (method === "GET") return json({ comments: await listComments(env, a.id) });
      if (!email) return err(401, "sign in to comment");
      if (method === "POST" && parts.length === 3) {
        const b = (await req.json()) as { body?: string; version?: number };
        const body = (b.body ?? "").trim().slice(0, 5000);
        if (!body) return err(400, "empty comment");
        const id = await addComment(env, a.id, visibleVersion(policy, a, email, b.version), email, body);
        return json({ id }, 201);
      }
      if (method === "PATCH" && parts.length === 4) {
        if (!canWrite(policy, a, email)) return err(403, "editors resolve comments");
        const b = (await req.json()) as { resolved?: boolean };
        await resolveComment(env, a.id, parts[3], b.resolved !== false);
        return json({ ok: true });
      }
    }

    return err(404, "no such endpoint");
  } catch (e) {
    if (e instanceof PublishError) return err(e.status, e.message);
    throw e;
  }
}

